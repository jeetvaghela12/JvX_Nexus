"""
API: compliance_routes.py

e-FIRA compliance bundle generation and retrieval.

PACKAGING, NOT ISSUANCE. The bank issues the FIRA. What this builds is a
tamper-evident bundle — the payment details, the linked invoices, and a
hash over all of it — that the bank's compliance interface can read when
it issues the real thing. If this ever starts producing something
presented to a customer as a FIRA, the product has stepped outside what
it is allowed to do.

Rewritten to read from InboundPayment. The previous version read from
TransactionLedger, which belonged to the earlier design where this
platform moved money and took a cut. That model is gone.
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
from models.payment_model import InboundPayment
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
    Build a compliance bundle for one of the caller's own credited
    payments, optionally linking invoices the caller also owns.

    payload.transaction_id now carries the bank_reference rather than an
    internal row id. The bank's reference is what appears on the bank's
    own systems, so it is the identifier a compliance officer can actually
    look up when they receive this bundle.
    """
    payment = db.execute(
        select(InboundPayment).where(
            InboundPayment.bank_reference == payload.transaction_id,
            InboundPayment.user_id == current_user.id,
        )
    ).scalar_one_or_none()
    if payment is None:
        # Uniform 404 whether it does not exist or belongs to someone
        # else. Distinguishing the two confirms to a caller that a
        # reference they guessed is real.
        raise HTTPException(status_code=404, detail="Payment not found.")

    if payment.status != "CREDITED":
        raise HTTPException(
            status_code=400,
            detail=(
                f"Cannot build a compliance bundle for a payment with status "
                f"{payment.status!r}. Only CREDITED payments qualify — the bank has "
                "not yet settled this one."
            ),
        )

    if payment.purpose_code is None:
        # The purpose code is what makes the bundle meaningful to a
        # compliance officer. Building one without it produces a document
        # that looks complete and answers nothing.
        raise HTTPException(
            status_code=400,
            detail="This payment has no purpose code assigned yet. The bank confirms the purpose code on settlement.",
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
        transaction_reference=payment.bank_reference,
        gross_amount=payment.amount,
        source_currency=payment.currency,
        compliance_purpose_code=payment.purpose_code,
        completed_at=payment.updated_at,
        user_full_name=current_user.full_name,
        user_entity_type=current_user.entity_type,
        linked_invoice_storage_keys=[inv.storage_key for inv in invoices],
        linked_invoice_file_hashes=[inv.file_hash for inv in invoices],
    )

    log_entry = EFiraLog(
        transaction_id=payment.id,
        bundle_payload=asdict(bundle_data),
        bundle_hash=bundle_data.bundle_hash,
        status="GENERATED",
    )

    try:
        db.add(log_entry)
        db.commit()
    except IntegrityError:
        # bundle_hash is unique: byte-for-byte identical content was
        # already generated. Database constraint as the guarantee, this
        # as the readable translation of it.
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="A bundle with this exact content has already been generated.",
        )
    except Exception:
        db.rollback()
        logger.exception(
            "Unexpected failure saving e-FIRA bundle (user_id=%s, bank_reference=%s)",
            current_user.id,
            payload.transaction_id,
        )
        raise

    db.refresh(log_entry)
    return EFiraBundleResponse(
        id=log_entry.id,
        bundle_hash=log_entry.bundle_hash,
        bundle=log_entry.bundle_payload,
    )


@router.get("/efira/{bundle_id}", response_model=EFiraBundleResponse)
async def get_efira_log(
    bundle_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> EFiraBundleResponse:
    """
    Retrieve a previously generated bundle.

    Ownership is checked through the linked payment, because EFiraLog has
    no user_id column of its own. The uniform 404 covers both "does not
    exist" and "is not yours".
    """
    log_entry = db.execute(select(EFiraLog).where(EFiraLog.id == bundle_id)).scalar_one_or_none()
    if log_entry is None:
        raise HTTPException(status_code=404, detail="Bundle not found.")

    payment = db.execute(
        select(InboundPayment).where(InboundPayment.id == log_entry.transaction_id)
    ).scalar_one_or_none()
    if payment is None or payment.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Bundle not found.")

    return EFiraBundleResponse(
        id=log_entry.id,
        bundle_hash=log_entry.bundle_hash,
        bundle=log_entry.bundle_payload,
    )