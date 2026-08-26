"""
Services: settlement_engine.py
The orchestrator: given a PENDING TransactionLedger row, looks up its
recipient, reads their preferred_payout_route, and dispatches to the
correct settlement rail -- services/e_rupee_mint.py for CBDC,
services/fiat_settlement.py for FIAT. This is the piece that was missing:
both settlement functions were built and tested, but nothing connected a
freshly-created ledger row to either one.

WHAT THIS FILE DELIBERATELY DOES NOT DO: retry a dispatch that couldn't
happen (no bank account/wallet configured yet) or that failed
unexpectedly. A row left PENDING by either case stays PENDING -- correctly
reflecting "funds received, not yet settled" -- until something re-
attempts dispatch for it. No sweep/retry job exists anywhere in this
codebase to do that automatically yet; this file only handles the
synchronous, immediate-dispatch path triggered right after a webhook
creates a row. Flagging the gap rather than silently building a
background-job system that wasn't asked for.
"""
import logging
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from models.ledger_model import TransactionLedger
from models.user_model import User
from services.e_rupee_mint import InvalidLedgerStateError as CbdcInvalidLedgerStateError
from services.e_rupee_mint import mint_digital_currency
from services.fiat_settlement import InvalidLedgerStateError as FiatInvalidLedgerStateError
from services.fiat_settlement import MissingBankAccountError, execute_fiat_settlement

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class SettlementDispatchResult:
    dispatched: bool
    # False whenever settlement was never attempted at all -- no payout
    # method configured, or the recipient/route couldn't be resolved.
    # True whenever mint_digital_currency/execute_fiat_settlement was
    # actually called, REGARDLESS of whether that call itself succeeded --
    # "dispatched" means "we tried," not "it worked."
    rail: str | None
    # "CBDC" / "FIAT" / None (None only when dispatched is False and the
    # route itself couldn't even be determined).
    success: bool | None
    # None when dispatched is False (nothing ran, so there's no outcome
    # to report). Otherwise mirrors the underlying MintResult/
    # FiatSettlementResult.success.
    reason: str | None
    # Human-readable explanation either way -- why nothing was dispatched,
    # or the error_reason from a dispatched-but-failed attempt.


def dispatch_settlement(db: Session, ledger_entry: TransactionLedger) -> SettlementDispatchResult:
    """
    The core routing decision. Looks up ledger_entry.user_id, reads their
    preferred_payout_route, and calls the matching settlement function --
    but only after confirming the corresponding payout method is actually
    configured. If it isn't, this returns dispatched=False rather than
    letting mint_digital_currency/execute_fiat_settlement fail on a
    precondition they'd have rejected anyway -- the distinction matters
    for what a caller should log: "not configured yet" is an expected,
    recoverable state; a genuine dispatch failure is not.
    """
    recipient = db.execute(select(User).where(User.id == ledger_entry.user_id)).scalar_one_or_none()
    if recipient is None:
        # Should be unreachable given TransactionLedger.user_id's FK
        # RESTRICT to users.id -- a ledger row can't outlive the user it
        # points to. Handled anyway rather than trusted silently: "should
        # be unreachable" and "is unreachable" aren't the same claim.
        logger.error("Settlement dispatch: no User found for ledger_entry.user_id=%s -- data integrity problem.", ledger_entry.user_id)
        return SettlementDispatchResult(dispatched=False, rail=None, success=None, reason="Recipient user not found.")

    if recipient.preferred_payout_route == "CBDC":
        if recipient.digital_wallet_address is None:
            logger.warning(
                "Settlement dispatch: user_id=%s prefers CBDC but has no digital_wallet_address configured -- ledger_entry_id=%s left PENDING.",
                recipient.id,
                ledger_entry.id,
            )
            return SettlementDispatchResult(dispatched=False, rail="CBDC", success=None, reason="CBDC preferred but no wallet configured.")

        try:
            mint_result = mint_digital_currency(db, ledger_entry)
        except CbdcInvalidLedgerStateError as exc:
            logger.warning("Settlement dispatch: CBDC mint refused for ledger_entry_id=%s: %s", ledger_entry.id, exc)
            return SettlementDispatchResult(dispatched=False, rail="CBDC", success=None, reason=str(exc))

        return SettlementDispatchResult(
            dispatched=True, rail="CBDC", success=mint_result.success, reason=mint_result.error_reason
        )

    elif recipient.preferred_payout_route == "FIAT":
        if recipient.local_bank_account_number is None:
            logger.warning(
                "Settlement dispatch: user_id=%s prefers FIAT but has no bank account configured -- ledger_entry_id=%s left PENDING.",
                recipient.id,
                ledger_entry.id,
            )
            return SettlementDispatchResult(dispatched=False, rail="FIAT", success=None, reason="FIAT preferred but no bank account configured.")

        try:
            fiat_result = execute_fiat_settlement(db, ledger_entry, recipient)
        except (FiatInvalidLedgerStateError, MissingBankAccountError) as exc:
            logger.warning("Settlement dispatch: FIAT settlement refused for ledger_entry_id=%s: %s", ledger_entry.id, exc)
            return SettlementDispatchResult(dispatched=False, rail="FIAT", success=None, reason=str(exc))

        return SettlementDispatchResult(
            dispatched=True, rail="FIAT", success=fiat_result.success, reason=fiat_result.error_reason
        )

    else:
        # Defensive, not paranoid: preferred_payout_route has NO
        # CheckConstraint (confirmed directly against models/user_model.py)
        # -- nothing in this codebase currently sets it to anything but
        # "FIAT"/"CBDC", but the column itself doesn't enforce that, so
        # this branch is genuinely reachable, not just theoretically so.
        logger.error(
            "Settlement dispatch: user_id=%s has unrecognized preferred_payout_route=%r -- ledger_entry_id=%s left PENDING.",
            recipient.id,
            recipient.preferred_payout_route,
            ledger_entry.id,
        )
        return SettlementDispatchResult(
            dispatched=False,
            rail=None,
            success=None,
            reason=f"Unrecognized preferred_payout_route: {recipient.preferred_payout_route!r}.",
        )