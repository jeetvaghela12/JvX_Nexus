"""
API: compliance_routes.py
e-FIRA compliance bundle generation and retrieval -- packaging, for the
AD-1 bank's own compliance interface, not issuance. See models/
compliance_model.py's EFiraLog docstring for why that distinction is
stated explicitly here too, not left implicit.
"""
import logging
from dataclasses import asdict

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from core.database import get_db
from core.dependencies import get_current_user
from models.compliance_model import CommercialInvoice, EFiraLog
from models.ledger_model import TransactionLedger
from models.user_model import User
from schemas.compliance_schemas import EFiraBundleResponse, EFiraGenerateRequest
from services.compliance_engine import generate_efira_bundle

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/compliance", tags=["Compliance / e-FIRA"])


@router.post("/efira/generate", response_model=EFiraBundleResponse, status_code=201)
async def generate_efira_log(
    payload: EFiraGenerateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> EFiraBundleResponse:
    """
    Generates and persists an e-FIRA compliance bundle for one of the
    caller's own COMPLETED transactions, optionally linking specific
    invoices the caller also owns.
    """
    transaction = db.execute(
        select(TransactionLedger).where(
            TransactionLedger.id == payload.transaction_id,
            TransactionLedger.user_id == current_user.id,
        )
    ).scalar_one_or_none()
    if transaction is None:
        # Uniform 404 for "doesn't exist" and "isn't yours" -- same
        # ticket-enumeration-prevention reasoning as api/support_routes.py.
        raise HTTPException(status_code=404, detail="Transaction not found.")

    if transaction.status != "COMPLETED":
        raise HTTPException(
            status_code=400,
            detail=f"Cannot generate an e-FIRA bundle for a transaction with status {transaction.status!r} -- only COMPLETED transactions qualify.",
        )

    invoices: list[CommercialInvoice] = []
    if payload.invoice_ids:
        invoices = list(
            db.execute(
                select(CommercialInvoice).where(
                    CommercialInvoice.id.in_(payload.invoice_ids),
                    CommercialInvoice.user_id == current_user.id,
                )
            )
            .scalars()
            .all()
        )
        if len(invoices) != len(set(payload.invoice_ids)):
            raise HTTPException(
                status_code=400,
                detail="One or more invoice_ids were not found or do not belong to this user.",
            )

    bundle_data = generate_efira_bundle(
        transaction_reference=transaction.transaction_reference,
        gross_amount=transaction.gross_amount,
        source_currency=transaction.source_currency,
        compliance_purpose_code=transaction.compliance_purpose_code,
        completed_at=transaction.completed_at,
        user_full_name=current_user.full_name,
        user_entity_type=current_user.entity_type,
        linked_invoice_storage_keys=[inv.storage_key for inv in invoices],
        linked_invoice_file_hashes=[inv.file_hash for inv in invoices],
    )

    log_entry = EFiraLog(
        transaction_id=transaction.id,
        bundle_payload=asdict(bundle_data),
        bundle_hash=bundle_data.bundle_hash,
        status="GENERATED",
    )

    try:
        db.add(log_entry)
        db.commit()
    except IntegrityError:
        # bundle_hash's unique=True firing: byte-for-byte identical
        # content already generated as an earlier bundle. Same class of
        # race/duplicate handling used throughout this codebase --
        # database constraint as the actual guarantee, this as the clean
        # error translation.
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="A bundle with this exact content has already been generated.",
        )
    except Exception:
        db.rollback()
        logger.exception(
            "Unexpected failure saving e-FIRA bundle (user_id=%s, transaction_id=%s)",
            current_user.id,
            payload.transaction_id,
        )
        raise

    db.refresh(log_entry)
    return EFiraBundleResponse(id=log_entry.id, bundle_hash=log_entry.bundle_hash, bundle=log_entry.bundle_payload)


@router.get("/efira/{bundle_id}", response_model=EFiraBundleResponse)
async def get_efira_log(
    bundle_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> EFiraBundleResponse:
    """
    Retrieve a previously-generated bundle. Ownership is checked via the
    bundle's linked transaction (EFiraLog has no user_id column of its
    own -- see the model), not a direct column comparison, but the
    uniform-404 result for "doesn't exist" vs. "isn't yours" is identical
    either way.
    """
    log_entry = db.execute(select(EFiraLog).where(EFiraLog.id == bundle_id)).scalar_one_or_none()
    if log_entry is None:
        raise HTTPException(status_code=404, detail="Bundle not found.")

    transaction = db.execute(
        select(TransactionLedger).where(TransactionLedger.id == log_entry.transaction_id)
    ).scalar_one_or_none()
    if transaction is None or transaction.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Bundle not found.")

    return EFiraBundleResponse(id=log_entry.id, bundle_hash=log_entry.bundle_hash, bundle=log_entry.bundle_payload)