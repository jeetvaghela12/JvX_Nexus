"""
API: payout_routes.py
Manage a user's outbound payout methods (Indian bank account, digital/
e-Rupee wallet) and their preferred_payout_route selection between them.
"""
import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from core.database import get_db
from core.dependencies import get_current_user
from models.user_model import User
from schemas.payout_schemas import (
    BankAccountRequest,
    PayoutMethodResponse,
    PreferredRouteRequest,
    WalletRequest,
)
from services.compliance_engine import verify_bank_account_penny_drop

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/payout", tags=["Payout Routing"])


def _build_response(user: User, message: str) -> PayoutMethodResponse:
    masked = f"••••{user.local_bank_account_number[-4:]}" if user.local_bank_account_number else None
    return PayoutMethodResponse(
        has_bank_account=user.local_bank_account_number is not None,
        masked_account_number=masked,
        has_digital_wallet=user.digital_wallet_address is not None,
        preferred_payout_route=user.preferred_payout_route,
        message=message,
    )


@router.post("/bank-account", response_model=PayoutMethodResponse)
async def add_bank_account(
    payload: BankAccountRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PayoutMethodResponse:
    """
    Add or update the caller's Indian bank account, gated on a Penny Drop
    verification first -- this works identically whether it's the first
    time (add) or replacing an existing account (update); the route
    doesn't need to distinguish those cases, since the logic is the same
    either way.
    """
    penny_drop = verify_bank_account_penny_drop(
        account_number=payload.account_number,
        ifsc=payload.ifsc,
        expected_name=current_user.full_name,
    )

    if not penny_drop.is_valid:
        raise HTTPException(status_code=400, detail="Bank account verification failed -- the account could not be confirmed as active.")
    if penny_drop.name_matches_expected is False:
        raise HTTPException(
            status_code=400,
            detail=f"Bank account holder name ({penny_drop.account_holder_name!r}) does not match your registered name.",
        )

    # SELECTION LOGIC: auto-set preferred_payout_route only when this is
    # the FIRST payout method the user has ever configured -- going from
    # zero methods to one removes all ambiguity, so there's nothing to
    # ask. If a wallet was already on file, adding a bank account doesn't
    # silently override whatever route they'd already chosen; explicit
    # selection (via /payout/preferred-route below) is required for that.
    # This same check works correctly whether this call is adding a bank
    # account for the first time or updating an existing one -- an update
    # always has had_bank_already=True, so the auto-set branch never
    # fires for it, which is exactly the desired behavior.
    had_bank_already = current_user.local_bank_account_number is not None
    had_wallet_already = current_user.digital_wallet_address is not None

    current_user.local_bank_account_number = payload.account_number
    current_user.local_bank_ifsc = payload.ifsc

    if not had_bank_already and not had_wallet_already:
        current_user.preferred_payout_route = "FIAT"

    try:
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Unexpected failure saving bank account (user_id=%s)", current_user.id)
        raise

    db.refresh(current_user)
    return _build_response(current_user, "Bank account verified and saved.")


@router.post("/wallet", response_model=PayoutMethodResponse)
async def add_wallet(
    payload: WalletRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PayoutMethodResponse:
    """
    Add or update the caller's digital/e-Rupee wallet address. No
    verification step here, unlike the bank account route -- not
    something asked for this step, and there's no penny-drop equivalent
    for a CBDC wallet in this codebase yet. Worth deciding later whether
    this needs its own check (e.g. a small test-transfer confirmation)
    before this route is treated as production-ready the same way the
    bank account one now is.
    """
    had_bank_already = current_user.local_bank_account_number is not None
    had_wallet_already = current_user.digital_wallet_address is not None

    current_user.digital_wallet_address = payload.wallet_address

    # Same selection logic as add_bank_account above, mirrored.
    if not had_wallet_already and not had_bank_already:
        current_user.preferred_payout_route = "CBDC"

    try:
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Unexpected failure saving wallet address (user_id=%s)", current_user.id)
        raise

    db.refresh(current_user)
    return _build_response(current_user, "Digital wallet address saved.")


@router.post("/preferred-route", response_model=PayoutMethodResponse)
async def set_preferred_route(
    payload: PreferredRouteRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PayoutMethodResponse:
    """
    Explicit selection between FIAT and CBDC -- this is the endpoint the
    "if they add both, they must be able to select which one is
    currently active" requirement actually maps to. Rejects selecting a
    route the user hasn't actually configured a method for yet, rather
    than silently accepting a preference that points at nothing.
    """
    if payload.preferred_payout_route == "FIAT" and current_user.local_bank_account_number is None:
        raise HTTPException(status_code=400, detail="Cannot select FIAT as the preferred payout route without a bank account on file.")
    if payload.preferred_payout_route == "CBDC" and current_user.digital_wallet_address is None:
        raise HTTPException(status_code=400, detail="Cannot select CBDC as the preferred payout route without a digital wallet address on file.")

    current_user.preferred_payout_route = payload.preferred_payout_route

    try:
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Unexpected failure updating preferred payout route (user_id=%s)", current_user.id)
        raise

    db.refresh(current_user)
    return _build_response(current_user, f"Preferred payout route set to {current_user.preferred_payout_route}.")