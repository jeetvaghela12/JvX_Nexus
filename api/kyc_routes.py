"""
API: kyc_routes.py
KYC submission and (mock) bank verification -- decoupled from Virtual
Account issuance, which now lives in api/van_routes.py entirely. Submit
here only ever saves data and screens compliance; it never talks to a
VAN provider.
"""
import hmac
import logging

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from core.config import settings
from core.database import get_db
from core.dependencies import get_current_user
from models.user_model import User
from schemas.kyc_schemas import KycSubmissionRequest, KycVerificationRequest
from services.compliance_engine import (
    CorporateOwnershipData,
    OwnerRecord,
    screen_aml_watchlists,
    verify_pan_linkage,
    verify_ubo,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/kyc", tags=["KYC"])


class KycSubmissionResponse(BaseModel):
    kyc_status: str
    message: str = "KYC documents submitted and cleared initial compliance screening. Pending bank review."


@router.post("/submit", response_model=KycSubmissionResponse)
async def submit_kyc(
    payload: KycSubmissionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> KycSubmissionResponse:
    """
    Runs the submitted PAN, entity name, and ownership data through
    services/compliance_engine.py; on a clear result, encrypts and stores
    PAN/GST/IEC on the caller's own User row and moves kyc_status to
    PENDING_BANK_REVIEW.

    DECOUPLED FROM VAN ISSUANCE, on purpose: this route used to also
    request a Virtual Account Number immediately after a clear result.
    That's gone -- VAN issuance is now a completely separate action
    (api/van_routes.py), gated on kyc_status == VERIFIED, which only
    /kyc/verify below can set. This mirrors real-world sequencing: a bank
    reviews submitted compliance data before anyone gets an account
    number, not the moment the data merely arrives.

    REJECTION SCOPE, UNCHANGED FROM BEFORE: only two conditions reject
    the submission -- invalid PAN format, and an AML watchlist hit (on
    the entity name or on any beneficial owner past the UBO threshold).
    pan_result.is_linked_to_aadhaar being False is still NOT a rejection
    reason, only recorded.
    """
    # --- 1. PAN: format check via the compliance engine ---
    pan_result = verify_pan_linkage(payload.pan_number)
    if not pan_result.is_valid_format:
        raise HTTPException(status_code=400, detail="Invalid PAN format.")

    # --- 2. AML: screen the entity name ---
    entity_screening = screen_aml_watchlists(payload.entity_name)
    if not entity_screening.is_clear:
        raise HTTPException(status_code=403, detail="Compliance screening failed for the submitted entity.")

    # --- 3. UBO: identify beneficial owners at/above the 10% threshold ---
    ownership_data = CorporateOwnershipData(
        entity_name=payload.entity_name,
        owners=[
            OwnerRecord(full_name=owner.full_name, ownership_percentage=owner.ownership_percentage)
            for owner in payload.owners
        ],
    )
    ubo_result = verify_ubo(ownership_data)

    for ubo_owner in ubo_result.ubo_owners:
        owner_screening = screen_aml_watchlists(ubo_owner.full_name)
        if not owner_screening.is_clear:
            raise HTTPException(
                status_code=403,
                detail=f"Compliance screening failed for beneficial owner {ubo_owner.full_name!r}.",
            )

    # --- 4. Clear: encrypt + store, advance kyc_status. That's it. ---
    # pan_result.pan_number (not payload.pan_number) -- the compliance
    # engine's normalized (stripped/uppercased) form, so what's stored is
    # consistent regardless of how the caller cased their input.
    current_user.tax_id_number = pan_result.pan_number
    current_user.gst_number = payload.gst_number
    current_user.iec_code = payload.iec_code
    current_user.kyc_status = "PENDING_BANK_REVIEW"
    # No more VAN issuance step here -- see this route's docstring.

    try:
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Unexpected failure saving KYC submission (user_id=%s)", current_user.id)
        raise

    db.refresh(current_user)
    return KycSubmissionResponse(kyc_status=current_user.kyc_status)


@router.post("/verify", response_model=KycSubmissionResponse)
async def verify_kyc(
    payload: KycVerificationRequest,
    x_verification_secret: str = Header(...),
    db: Session = Depends(get_db),
) -> KycSubmissionResponse:
    """
    MOCK admin/bank-webhook endpoint standing in for the real "Main Bank"
    compliance verification callback -- transitions a user from
    PENDING_BANK_REVIEW to VERIFIED (or REJECTED). No real bank contacts
    this; something (an internal admin tool, eventually a real bank
    webhook) would call it in production.

    NOT LEFT UNAUTHENTICATED, even as a mock: this endpoint can approve
    ANY user's KYC by user_id -- leaving it open, even for testing
    purposes, would mean any caller could self-approve or approve anyone
    else. Protected the same conceptual way bank-to-platform calls
    already are elsewhere in this codebase (a shared secret header,
    mirroring the Decentro callback's own model rather than inventing a
    new pattern) -- a real implementation would replace this with proper
    admin authentication or the actual bank's own callback auth scheme,
    but "mock" doesn't mean "open."
    """
    expected_secret = settings.KYC_VERIFICATION_WEBHOOK_SECRET.get_secret_value().strip()
    if not hmac.compare_digest(x_verification_secret.strip(), expected_secret):
        raise HTTPException(status_code=401, detail="Invalid verification secret.")

    user = db.execute(select(User).where(User.id == payload.user_id)).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found.")

    if user.kyc_status != "PENDING_BANK_REVIEW":
        raise HTTPException(
            status_code=400,
            detail=f"User is not awaiting bank review (current kyc_status: {user.kyc_status!r}).",
        )

    user.kyc_status = "VERIFIED" if payload.approved else "REJECTED"

    try:
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Unexpected failure updating kyc_status during verification (user_id=%s)", payload.user_id)
        raise

    db.refresh(user)
    return KycSubmissionResponse(
        kyc_status=user.kyc_status,
        message=f"KYC status set to {user.kyc_status}."
        + (" User may now request a Virtual Account via /van/request." if user.kyc_status == "VERIFIED" else ""),
    )