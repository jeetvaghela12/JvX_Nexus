"""
API: consolidator_routes.py
Pillar 2's route surface -- logging income, uploading real proof,
generating a self-declared receipt for genuinely undocumented income,
the gap-detection dashboard, and the export.

RECONSTRUCTED, NOT RE-VERIFIED -- same caveat as income_model.py and
consolidator_engine.py. In particular, this assumes core.dependencies.
get_current_user and core.database.get_db exist with the same signatures
used throughout the rest of this codebase -- confirm against your real
files before treating this as final.
"""
import hashlib
import logging

from fastapi import APIRouter, Depends, Form, HTTPException, UploadFile
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from core.database import get_db
from core.dependencies import get_current_user
from models.income_model import ConnectedIncomeSource, ExportProofDocument, ForeignIncomeRecord
from models.user_model import User
from services.adsense_client import (
    AdSenseAuthenticationError,
    AdSenseServiceError,
    AdSenseUnavailableError,
    build_authorization_url,
    exchange_code_for_tokens,
    fetch_and_store_earnings,
)
from services.consolidator_engine import (
    AlreadyDocumentedError,
    compute_ca_export,
    compute_documentation_gaps,
    create_self_declared_receipt,
)
from services.file_storage_client import save_document
from services.oauth_state import InvalidOAuthStateError, verify_oauth_state

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/consolidator", tags=["Consolidator"])


class IncomeRecordRequest(BaseModel):
    source: str
    amount: float
    currency: str
    received_date: str
    client_name: str | None = None
    notes: str | None = None


class GenerateReceiptRequest(BaseModel):
    recipient_full_name: str


@router.post("/income", status_code=201)
async def log_income(
    payload: IncomeRecordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    record = ForeignIncomeRecord(
        user_id=current_user.id,
        source=payload.source,
        amount=payload.amount,
        currency=payload.currency,
        received_date=payload.received_date,
        client_name=payload.client_name,
        notes=payload.notes,
    )
    try:
        db.add(record)
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Unexpected failure logging income record (user_id=%s)", current_user.id)
        raise
    db.refresh(record)
    return {"id": record.id, "source": record.source, "amount": str(record.amount)}


@router.get("/income")
async def list_income(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict]:
    records = db.execute(
        select(ForeignIncomeRecord).where(ForeignIncomeRecord.user_id == current_user.id)
    ).scalars().all()
    return [
        {"id": r.id, "source": r.source, "amount": str(r.amount), "currency": r.currency, "received_date": str(r.received_date)}
        for r in records
    ]


@router.post("/income/{income_id}/generate-receipt", status_code=201)
async def generate_receipt(
    income_id: int,
    payload: GenerateReceiptRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """
    Generates a self-declared receipt for genuinely undocumented income
    -- refuses outright if the record already has real proof attached
    (see AlreadyDocumentedError), and refuses if the record doesn't
    belong to the caller, using the same uniform-404 ownership-check
    pattern as every other user-owned resource in this codebase.
    """
    record = db.execute(
        select(ForeignIncomeRecord).where(
            ForeignIncomeRecord.id == income_id,
            ForeignIncomeRecord.user_id == current_user.id,
        )
    ).scalar_one_or_none()
    if record is None:
        raise HTTPException(status_code=404, detail="Income record not found.")

    try:
        document = create_self_declared_receipt(db, record, payload.recipient_full_name)
    except AlreadyDocumentedError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    return {
        "id": document.id,
        "document_type": document.document_type,
        "storage_key": document.storage_key,
        "message": "Self-declared receipt generated -- this is a self-attestation, not bank or platform issued.",
    }


@router.get("/gaps")
async def get_gaps(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    report = compute_documentation_gaps(db, current_user.id)
    return {
        "total_income_records": report.total_income_records,
        "records_with_proof": report.records_with_proof,
        "records_missing_proof": [
            {"income_record_id": g.income_record_id, "source": g.source, "amount": str(g.amount), "currency": g.currency}
            for g in report.records_missing_proof
        ],
    }


@router.get("/export")
async def export_for_ca(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """
    The '1-click audit-ready export' -- every income record and every
    document attached to it, in one response. Structured JSON, not a
    rendered PDF -- see compute_ca_export's own docstring for why that's
    the honest scope today, not a gap being hidden.
    """
    report = compute_ca_export(db, current_user.id)
    return {
        "generated_at": report.generated_at.isoformat(),
        "total_income_records": report.total_income_records,
        "total_documented": report.total_documented,
        "total_missing_documentation": report.total_missing_documentation,
        "records": [
            {
                "income_record_id": r.income_record_id,
                "source": r.source,
                "amount": str(r.amount),
                "currency": r.currency,
                "received_date": str(r.received_date),
                "documents": [
                    {"document_type": d.document_type, "storage_key": d.storage_key}
                    for d in r.documents
                ],
            }
            for r in report.records
        ],
    }


# ----------------------------------------------------------------------
# AdSense OAuth -- the one genuinely self-serve, automated income source
# (see the dedicated feasibility research: Upwork/PayPal/Wise/Fiverr are
# all partner-gated or offer no API path). Two routes handle the flow;
# a third lets a connected user re-sync without redoing consent.
# ----------------------------------------------------------------------

@router.get("/adsense/connect")
async def adsense_connect(
    current_user: User = Depends(get_current_user),
) -> dict:
    """
    Returns the URL to send the user's browser to -- deliberately JSON
    with a URL field, not a server-side redirect, so the frontend
    controls the navigation (e.g. a popup, or its own "connecting..."
    state) rather than the API silently redirecting out from under it.
    """
    return {"authorization_url": build_authorization_url(current_user.id)}


@router.get("/adsense/callback")
async def adsense_callback(
    code: str,
    state: str,
    db: Session = Depends(get_db),
) -> dict:
    """
    Google redirects the user's browser HERE directly after consent --
    there is no Authorization header on this request, so
    Depends(get_current_user) cannot be used here, unlike every other
    route in this file. The state token (verified below) is what tells
    us which user this is, and is the CSRF protection for the entire
    flow -- see services/oauth_state.py's own module docstring for why
    this mechanism exists at all.
    """
    try:
        user_id = verify_oauth_state(state)
    except InvalidOAuthStateError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid or expired connection attempt: {exc}")

    try:
        token_response = exchange_code_for_tokens(code)
    except AdSenseAuthenticationError as exc:
        raise HTTPException(status_code=401, detail=str(exc))
    except AdSenseUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    refresh_token = token_response.get("refresh_token")
    if not refresh_token:
        # build_authorization_url sends prompt=consent specifically to
        # avoid this, but a caller retrying an already-completed flow
        # could still land here without a fresh refresh_token.
        raise HTTPException(
            status_code=400,
            detail="Google did not return a refresh token -- disconnect and reconnect AdSense to try again.",
        )

    existing_connection = db.execute(
        select(ConnectedIncomeSource).where(
            ConnectedIncomeSource.user_id == user_id,
            ConnectedIncomeSource.source == "ADSENSE",
        )
    ).scalar_one_or_none()

    if existing_connection is not None:
        existing_connection.encrypted_refresh_token = refresh_token
        connection = existing_connection
    else:
        connection = ConnectedIncomeSource(user_id=user_id, source="ADSENSE", encrypted_refresh_token=refresh_token)
        db.add(connection)

    try:
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Unexpected failure saving AdSense connection (user_id=%s)", user_id)
        raise
    db.refresh(connection)

    try:
        new_records = fetch_and_store_earnings(db, user_id, connection)
    except AdSenseServiceError:
        # The connection itself is saved and real -- a transient failure
        # on the immediate post-connect sync shouldn't force the user
        # back through the entire consent flow. They can retry via
        # POST /consolidator/adsense/sync below.
        logger.exception(
            "AdSense connected successfully but the immediate post-connect sync failed (user_id=%s) -- "
            "connection is saved; sync can be retried.", user_id,
        )
        return {"connected": True, "new_income_records_imported": None, "sync_note": "Connected; initial sync failed and can be retried via /consolidator/adsense/sync."}

    return {"connected": True, "new_income_records_imported": new_records}


@router.post("/adsense/sync")
async def adsense_sync(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Re-syncs an already-connected AdSense account -- safe to call
    repeatedly, since fetch_and_store_earnings deduplicates against
    external_reference_id and only imports genuinely new payments."""
    connection = db.execute(
        select(ConnectedIncomeSource).where(
            ConnectedIncomeSource.user_id == current_user.id,
            ConnectedIncomeSource.source == "ADSENSE",
        )
    ).scalar_one_or_none()
    if connection is None:
        raise HTTPException(status_code=404, detail="AdSense is not connected for this account.")

    try:
        new_records = fetch_and_store_earnings(db, current_user.id, connection)
    except AdSenseAuthenticationError as exc:
        raise HTTPException(status_code=401, detail=f"{exc} Reconnect AdSense to continue syncing.")
    except AdSenseUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    return {"new_income_records_imported": new_records}


# ----------------------------------------------------------------------
# Secure document upload -- for every income source that isn't AdSense,
# where the honest, feasible path today is manual upload, not automated
# fetching (see the Pillar 2 feasibility research on why).
# ----------------------------------------------------------------------

_PDF_MAGIC = b"%PDF"
_JPG_MAGIC = b"\xff\xd8\xff"
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10MB

_ALLOWED_UPLOAD_DOCUMENT_TYPES = {"FIRC", "FIRA", "PLATFORM_RECEIPT", "FORM_1042S", "OTHER"}
# Deliberately excludes SELF_DECLARED_RECEIPT: that type is only ever
# produced by consolidator_engine.py's own generate_self_declared_receipt_content,
# a system-generated document with its own honesty banner baked into the
# text. Allowing a user to upload an arbitrary file and label it
# SELF_DECLARED_RECEIPT here would let them bypass that entirely --
# uploading a real-looking document under a label that's supposed to
# mean "the system generated this, and said so, inside the file itself."


def _detect_file_type(file_bytes: bytes) -> str | None:
    """
    Returns 'pdf' / 'jpg' / 'png' based on the file's actual leading
    bytes -- never the client-supplied filename or Content-Type header,
    both of which are trivially spoofable and neither of which this
    function trusts. Same principle as invoice_routes.py's own PDF
    magic-byte check in Pillar 1, applied here to three formats instead
    of one.
    """
    if file_bytes.startswith(_PDF_MAGIC):
        return "pdf"
    if file_bytes.startswith(_JPG_MAGIC):
        return "jpg"
    if file_bytes.startswith(_PNG_MAGIC):
        return "png"
    return None


@router.post("/income/{income_id}/proof", status_code=201)
async def upload_proof_document(
    income_id: int,
    file: UploadFile,
    document_type: str = Form(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """
    Uploads external proof (a FIRC, e-FIRA, platform receipt, or 1042-S)
    for an existing income record. Ownership-checked with the same
    uniform-404 pattern as generate_receipt above; file-type-checked by
    actual content, not filename; storage is mocked gracefully via
    file_storage_client's existing local-disk implementation, with the
    same interface a real object-storage backend would need to satisfy.
    """
    if document_type not in _ALLOWED_UPLOAD_DOCUMENT_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"document_type must be one of {sorted(_ALLOWED_UPLOAD_DOCUMENT_TYPES)}.",
        )

    record = db.execute(
        select(ForeignIncomeRecord).where(
            ForeignIncomeRecord.id == income_id,
            ForeignIncomeRecord.user_id == current_user.id,
        )
    ).scalar_one_or_none()
    if record is None:
        raise HTTPException(status_code=404, detail="Income record not found.")

    file_bytes = await file.read()

    if len(file_bytes) > _MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds the {_MAX_UPLOAD_BYTES // (1024 * 1024)}MB limit.",
        )

    detected_type = _detect_file_type(file_bytes)
    if detected_type is None:
        raise HTTPException(
            status_code=422,
            detail="File is not a recognized PDF, JPG, or PNG -- checked by content, not filename or declared type.",
        )

    file_hash = hashlib.sha256(file_bytes).hexdigest()

    try:
        storage_key = save_document(
            document_type=document_type.lower(),
            file_hash=file_hash,
            file_bytes=file_bytes,
            extension=detected_type,
        )
    except Exception:
        logger.exception("Unexpected failure storing uploaded proof document (income_record_id=%s)", income_id)
        raise HTTPException(status_code=503, detail="Could not store the uploaded file -- try again shortly.")

    document = ExportProofDocument(
        income_record_id=record.id,
        document_type=document_type,
        storage_key=storage_key,
    )

    try:
        db.add(document)
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Unexpected failure saving proof document row (income_record_id=%s)", income_id)
        raise
    db.refresh(document)

    return {
        "id": document.id,
        "document_type": document.document_type,
        "storage_key": document.storage_key,
        "detected_file_type": detected_type,
    }