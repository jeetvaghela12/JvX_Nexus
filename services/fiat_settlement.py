"""
Services: fiat_settlement.py
Handles the simulated interaction with the partner bank to execute an
IMPS/NEFT transfer to a user's local bank account -- the FIAT-rail
counterpart to services/e_rupee_mint.py's CBDC mint, built by mirroring
that file's structure line for line (including its concurrency-safety
discipline) rather than inventing a new pattern for the same class of
problem.

MOCK BOUNDARY: _call_bank_transfer_mock is the entire simulated part of
this file, exactly matching e_rupee_mint.py's own boundary. Everything
around it -- the locking, the status transitions, the commit/rollback
handling -- is real and doesn't change when a genuine bank transfer API
replaces the mock. When that happens, the new implementation should be
routed through config.py (e.g. settings.PARTNER_BANK_TRANSFER_URL) with a
comment marking the test/live URL swap, matching every other external
endpoint in this codebase -- not built here since there's no real
endpoint yet to route to.
"""
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from models.ledger_model import TransactionLedger
from models.user_model import User


class InvalidLedgerStateError(Exception):
    """Raised when execute_fiat_settlement is asked to process a ledger entry that isn't (or is no longer) PENDING."""


class MissingBankAccountError(Exception):
    """Raised when the recipient has no local_bank_account_number/local_bank_ifsc on file -- a caller-side precondition failure, not a bank transfer failure."""


@dataclass(frozen=True, slots=True)
class _BankTransferOutcome:
    success: bool
    utr: str | None
    error_reason: str | None


def _call_bank_transfer_mock(
    ledger_entry: TransactionLedger, recipient: User, *, simulate_failure: bool = False
) -> _BankTransferOutcome:
    """
    MOCK -- stands in for a real HTTP call to the partner bank's IMPS/NEFT
    transfer API. There's no real endpoint yet; see the module docstring
    for where the real integration goes when it exists.

    Deterministic, not random, matching e_rupee_mint.py's own mock exactly:
    defaults to always succeeding, since there's no real API to observe an
    actual failure mode from yet. simulate_failure is the same honest
    escape hatch for exercising the FAILED branch in execute_fiat_settlement.
    """
    time.sleep(0.05)  # stand-in for real network latency, not a meaningful duration itself

    if simulate_failure:
        return _BankTransferOutcome(
            success=False,
            utr=None,
            error_reason="Simulated bank transfer failure (mock, simulate_failure=True).",
        )

    return _BankTransferOutcome(success=True, utr=f"UTR{uuid.uuid4().hex[:16].upper()}", error_reason=None)


@dataclass(frozen=True, slots=True)
class FiatSettlementResult:
    success: bool
    utr: str | None
    error_reason: str | None
    ledger_entry: TransactionLedger


def execute_fiat_settlement(db: Session, ledger_entry: TransactionLedger, recipient: User) -> FiatSettlementResult:
    """
    Simulates calling the partner bank's transfer API, and transitions
    ledger_entry from PENDING to COMPLETED or FAILED -- same concurrency-
    safety discipline as mint_digital_currency (see that function's own
    docstring for the full reasoning): SELECT ... FOR UPDATE acquires an
    exclusive row lock BEFORE the (mock) external call, not just around
    the final status write, so a real transfer API would only ever be
    invoked once per ledger entry even under concurrent callers.

    recipient must already have local_bank_account_number and
    local_bank_ifsc set -- raises MissingBankAccountError before
    attempting anything if not. This is deliberately a caller-side
    precondition check, not a "bank transfer failed" outcome: a missing
    bank account means the recipient hasn't finished payout setup, which
    is a different, earlier problem than a transfer that was attempted
    and failed.
    """
    if recipient.local_bank_account_number is None or recipient.local_bank_ifsc is None:
        raise MissingBankAccountError(
            f"User {recipient.id} has no bank account on file -- cannot execute FIAT settlement "
            "until they add one via POST /payout/bank-account."
        )

    locked_entry = db.execute(
        select(TransactionLedger).where(TransactionLedger.id == ledger_entry.id).with_for_update()
    ).scalar_one_or_none()

    if locked_entry is None:
        raise ValueError(f"No TransactionLedger row exists with id={ledger_entry.id}.")

    if locked_entry.status != "PENDING":
        raise InvalidLedgerStateError(
            f"Refusing to settle ledger entry {locked_entry.id}: status is "
            f"{locked_entry.status!r}, not 'PENDING'. Calling this twice for the "
            "same entry is exactly the double-settlement scenario this check exists "
            "to prevent -- if this fires, look at the caller, not this function."
        )

    outcome = _call_bank_transfer_mock(locked_entry, recipient)

    if outcome.success:
        locked_entry.status = "COMPLETED"
        locked_entry.completed_at = datetime.now(timezone.utc)
        locked_entry.fiat_settlement_utr = outcome.utr
    else:
        locked_entry.status = "FAILED"
        locked_entry.error_reason = outcome.error_reason
        # completed_at intentionally left unset for FAILED, matching
        # mint_digital_currency's exact same open question and same
        # conservative choice -- see that file's comment on this.

    try:
        db.commit()
    except Exception:
        db.rollback()
        raise

    return FiatSettlementResult(
        success=outcome.success,
        utr=outcome.utr,
        error_reason=outcome.error_reason,
        ledger_entry=locked_entry,
    )