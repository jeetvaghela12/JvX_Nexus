"""
API: invoice_routes.py
The Pre-Invoice Compliance Engine's upload endpoint: PDF invoice intake,
mock AI/OCR extraction, and dual-layer double-invoicing fraud detection
(raw file hash + normalized content fingerprint).
"""
import hashlib
import logging
from decimal import Decimal, InvalidOperation

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from core.database import get_db
from core.dependencies import get_current_user
from models.compliance_model import CommercialInvoice
from models.user_model import User
from schemas.invoice_schemas import InvoiceUploadResponse
from services.compliance_engine import compute_content_fingerprint, extract_invoice_metadata
from services.file_storage_client import save_invoice_pdf

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/invoices", tags=["Pre-Invoice Compliance"])

_PDF_MAGIC_BYTES = b"%PDF-"
_MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB -- a sensible ceiling for an invoice document, not a value given explicitly


@router.post("/upload", response_model=InvoiceUploadResponse, status_code=201)
async def upload_invoice(
    file: UploadFile = File(...),
    invoice_number: str = Form(...),
    amount: str = Form(...),
    currency: str = Form(...),
    buyer_name: str = Form(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> InvoiceUploadResponse:
    """
    multipart/form-data, not JSON -- the first upload endpoint in this
    codebase, so this is a genuinely different request shape from
    everything else built so far. amount arrives as a Form string, not a
    JSON number, and is parsed to Decimal explicitly below -- form fields
    have no native numeric type the way JSON does, so there was never a
    float to avoid here in the first place.

    ORDER OF CHECKS, deliberate: (1) file validity, (2) exact-file
    duplicate (file_hash) -- cheapest, most obvious rejection first, (3)
    mock extraction + cross-check against claimed values, (4) content-
    level duplicate (content_fingerprint) -- catches a re-saved/
    re-exported copy of an already-submitted invoice that (2) would miss
    entirely, (5) store + persist.
    """
    pdf_bytes = await file.read()

    if len(pdf_bytes) > _MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"File exceeds the {_MAX_UPLOAD_BYTES // (1024 * 1024)}MB upload limit.")
    if not pdf_bytes.startswith(_PDF_MAGIC_BYTES):
        # Checked against the actual bytes, not file.content_type or the
        # filename extension -- both are caller-supplied and trivially
        # spoofable; the magic-byte signature isn't.
        raise HTTPException(status_code=400, detail="Uploaded file is not a valid PDF.")

    try:
        claimed_amount = Decimal(amount)
    except InvalidOperation:
        raise HTTPException(status_code=400, detail=f"amount is not a valid decimal number: {amount!r}.")
    if claimed_amount <= 0:
        raise HTTPException(status_code=400, detail="amount must be positive.")

    normalized_currency = currency.strip().upper()
    if len(normalized_currency) != 3:
        raise HTTPException(status_code=400, detail="currency must be a 3-letter ISO 4217 code.")

    # --- 1. Raw file hash -- exact-duplicate check ---
    file_hash = hashlib.sha256(pdf_bytes).hexdigest()

    existing_by_file_hash = db.execute(
        select(CommercialInvoice).where(CommercialInvoice.file_hash == file_hash)
    ).scalar_one_or_none()
    if existing_by_file_hash is not None:
        raise HTTPException(status_code=409, detail="This exact file has already been submitted (duplicate file hash).")

    # --- 2. Mock AI/OCR extraction ---
    # pdf_bytes now passed explicitly -- extract_invoice_metadata's
    # signature changed when it moved from mock to real AWS Textract
    # scaffolding (services/compliance_engine.py), since real OCR
    # obviously needs the actual file bytes, unlike the mock. Without
    # this argument, every upload would fail with a TypeError.
    extraction = extract_invoice_metadata(
        pdf_bytes, invoice_number.strip(), claimed_amount, normalized_currency, buyer_name.strip()
    )

    # --- 3. Cross-check extracted vs claimed ---
    # Currently UNREACHABLE given the mock's default behavior (it always
    # confirms whatever was claimed, since there's no real OCR here to
    # disagree) -- kept anyway because this is exactly where the check
    # needs to live once real extraction replaces the mock, and it
    # documents the intended real-world behavior rather than silently
    # trusting claimed values forever.
    if extraction.amount != claimed_amount or extraction.currency != normalized_currency or extraction.buyer_name != buyer_name.strip():
        raise HTTPException(
            status_code=400,
            detail="Extracted invoice data does not match the submitted values.",
        )

    # --- 4. Content fingerprint -- catches a re-saved/re-exported duplicate ---
    content_fingerprint = compute_content_fingerprint(
        extraction.invoice_number, extraction.amount, extraction.currency, extraction.buyer_name
    )

    existing_by_fingerprint = db.execute(
        select(CommercialInvoice).where(CommercialInvoice.content_fingerprint == content_fingerprint)
    ).scalar_one_or_none()
    if existing_by_fingerprint is not None:
        raise HTTPException(
            status_code=409,
            detail="An invoice with this exact content has already been submitted under a different file.",
        )

    # --- 5. Store the file, persist the record ---
    storage_key = save_invoice_pdf(file_hash, pdf_bytes)

    invoice = CommercialInvoice(
        user_id=current_user.id,
        invoice_number=extraction.invoice_number,
        amount=extraction.amount,
        currency=extraction.currency,
        buyer_name=extraction.buyer_name,
        file_hash=file_hash,
        content_fingerprint=content_fingerprint,
        storage_key=storage_key,
        status="pending_bank_approval",
    )

    try:
        db.add(invoice)
        db.commit()
    except IntegrityError:
        # Race: two concurrent uploads of the same file/content, or a
        # (user_id, invoice_number) collision -- same class of race
        # guarded elsewhere in this codebase by unique constraint +
        # IntegrityError catch. The database's own constraints are the
        # actual guarantee; the checks above are the fast, friendly path,
        # not the only enforcement.
        db.rollback()
        raise HTTPException(status_code=409, detail="A conflicting invoice record already exists.")
    except Exception:
        db.rollback()
        logger.exception("Unexpected failure saving invoice (user_id=%s)", current_user.id)
        raise

    db.refresh(invoice)
    return InvoiceUploadResponse(
        id=invoice.id,
        invoice_number=invoice.invoice_number,
        amount=invoice.amount,
        currency=invoice.currency,
        buyer_name=invoice.buyer_name,
        status=invoice.status,
        message="Invoice uploaded, verified, and cleared for bank review.",
    )