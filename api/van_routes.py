"""
API: van_routes.py
Country-specific Virtual Account Number (VAN) requests -- decoupled from
KYC submission. A user may only request a VAN once their kyc_status is
VERIFIED (set via api/kyc_routes.py's mock /kyc/verify endpoint, standing
in for the real bank compliance callback).
"""
import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from core.database import get_db
from core.dependencies import get_current_user
from models.user_model import User
from models.virtual_account_model import VirtualAccount
from schemas.van_schemas import VanRequest, VanResponse
from services.bank_onboarding_client import get_virtual_account_provider

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/van", tags=["Virtual Accounts"])


def _to_response(virtual_account: VirtualAccount) -> VanResponse:
    return VanResponse(
        country_code=virtual_account.country_code,
        masked_account_number=f"••••{virtual_account.account_number[-4:]}",
        status=virtual_account.status,
        provider_name=virtual_account.provider_name,
    )


@router.post("/request", response_model=VanResponse, status_code=201)
async def request_van(
    payload: VanRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> VanResponse:
    """
    Request a VAN for a specific country. Requires kyc_status == VERIFIED
    -- KYC submission alone (PENDING_BANK_REVIEW) is not sufficient, and
    neither is a rejected review. One VAN per (user, country_code), same
    as the database's own uq_virtual_accounts_user_country constraint --
    checked here first for a clean 409 rather than relying solely on the
    constraint to reject a duplicate request.
    """
    if current_user.kyc_status != "VERIFIED":
        raise HTTPException(
            status_code=403,
            detail=f"KYC must be VERIFIED before requesting a Virtual Account (current status: {current_user.kyc_status!r}).",
        )

    existing = db.execute(
        select(VirtualAccount).where(
            VirtualAccount.user_id == current_user.id,
            VirtualAccount.country_code == payload.country_code,
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(status_code=409, detail=f"A Virtual Account for {payload.country_code} already exists.")

    provider = get_virtual_account_provider()
    van_result = provider.issue_virtual_account(current_user, country_code=payload.country_code)

    if not van_result.success:
        # 502, not 400/500: the REQUEST itself was well-formed and
        # legitimate (KYC verified, no duplicate) -- the failure is the
        # upstream provider's, which is exactly what 502 Bad Gateway
        # means. Distinct from kyc_routes.py's earlier compliance-
        # rejection cases, which are 400/403 because those really are
        # about the request itself being invalid or unauthorized.
        raise HTTPException(status_code=502, detail=f"Virtual Account issuance failed: {van_result.error_message}")

    virtual_account = VirtualAccount(
        user_id=current_user.id,
        country_code=payload.country_code,
        account_number=van_result.virtual_account_number,
        routing_details=van_result.routing_details or {},
        status="ACTIVE",
        provider_name="decentro" if van_result.raw_provider_response is not None else "mock",
        # provider_name inferred from whether a real provider response
        # came back, rather than reading settings.VAM_PROVIDER directly
        # here -- keeps this route from needing to know provider names
        # itself, matching the rest of this codebase's pattern of routes
        # talking to the provider only through the VirtualAccountProvider
        # interface.
    )

    try:
        db.add(virtual_account)
        db.commit()
    except IntegrityError:
        db.rollback()
        # Race: two concurrent requests for the same (user, country)
        # pair -- same class of race guarded elsewhere in this codebase
        # by unique constraint + IntegrityError catch (bank_webhook.py's
        # idempotency, auth_routes.py's signup). The database's own
        # uq_virtual_accounts_user_country constraint is the actual
        # guarantee; this just turns it into a clean 409.
        raise HTTPException(status_code=409, detail=f"A Virtual Account for {payload.country_code} already exists.")
    except Exception:
        db.rollback()
        logger.exception("Unexpected failure saving VirtualAccount (user_id=%s, country_code=%s)", current_user.id, payload.country_code)
        raise

    db.refresh(virtual_account)
    return _to_response(virtual_account)


@router.get("", response_model=list[VanResponse])
async def list_vans(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[VanResponse]:
    """
    List every VAN the caller has been issued, across all countries.
    Not explicitly requested, but added anyway: once a user can hold
    more than one VAN, there needs to be some way to see them all --
    without this, a dashboard would have no route to build on at all.
    """
    virtual_accounts = db.execute(
        select(VirtualAccount).where(VirtualAccount.user_id == current_user.id).order_by(VirtualAccount.country_code)
    ).scalars().all()
    return [_to_response(va) for va in virtual_accounts]