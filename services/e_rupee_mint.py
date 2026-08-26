"""
Services: e_rupee_mint.py
Handles the simulated interaction with the central bank/CBDC node to mint e-Rupees to the user's wallet.

SCHEMA GAP: CLOSED. This docstring used to flag that TransactionLedger
had nowhere to persist cbdc_reference_number or error_reason -- both
columns exist now (models/ledger_model.py). What it didn't originally
flag, and what stayed broken until this pass: mint_digital_currency
computed both values and returned them in MintResult, but never actually
assigned them to the locked ledger row -- every successful mint was
silently losing its reference number. Fixed now (see the assignments
below), caught while building services/fiat_settlement.py's counterpart
and comparing the two implementations directly against each other.

MOCK BOUNDARY: _call_cbdc_network_mock is the entire simulated part of
this file. Everything around it -- the locking, the status transitions,
the commit/rollback handling -- is the real logic and doesn't change when
a genuine CBDC network integration replaces the mock. When that happens,
the new implementation should be routed through config.py (e.g.
settings.CBDC_NETWORK_URL) with a comment marking the test/live URL swap,
matching every other external endpoint in this codebase -- not built here
since there's no real endpoint yet to route to.
"""
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from models.ledger_model import TransactionLedger


class InvalidLedgerStateError(Exception):
    """Raised when mint_digital_currency is asked to process a ledger entry that isn't (or is no longer) PENDING."""


@dataclass(frozen=True, slots=True)
class _CbdcCallOutcome:
    success: bool
    cbdc_reference_number: str | None
    error_reason: str | None


def _call_cbdc_network_mock(ledger_entry: TransactionLedger, *, simulate_failure: bool = False) -> _CbdcCallOutcome:
    """
    MOCK -- stands in for a real HTTP call to the CBDC/e-Rupee minting
    network. There's no real endpoint yet; see the module docstring for
    where the real integration goes when it exists.

    Deterministic, not random: defaults to always succeeding, since there's
    no real API to observe an actual failure mode from yet -- inventing a
    fake failure rule (e.g. "fails for amounts over X") would risk being
    mistaken for a real business rule later. simulate_failure is an
    explicit, honest escape hatch for exercising the FAILED branch in
    mint_digital_currency (tests, manual verification) instead.
    """
    time.sleep(0.05)  # stand-in for real network latency, not a meaningful duration itself

    if simulate_failure:
        return _CbdcCallOutcome(
            success=False,
            cbdc_reference_number=None,
            error_reason="Simulated CBDC network failure (mock, simulate_failure=True).",
        )

    return _CbdcCallOutcome(
        success=True,
        cbdc_reference_number=f"CBDC-{uuid.uuid4()}",
        error_reason=None,
    )


@dataclass(frozen=True, slots=True)
class MintResult:
    """
    success: whether the (simulated) CBDC mint succeeded.
    cbdc_reference_number: the network's reference for this mint, when
        success is True -- now genuinely persisted on ledger_entry.
        cbdc_reference_number too (see the fix in mint_digital_currency
        below), not just returned here.
    error_reason: what went wrong, when success is False. Same -- now
        persisted on ledger_entry.error_reason, not just returned.
    ledger_entry: the same row that was passed in, mutated in place
        (status, completed_at, and cbdc_reference_number/error_reason)
        and already committed. Returned again purely for convenient
        chaining.
    """
    success: bool
    cbdc_reference_number: str | None
    error_reason: str | None
    ledger_entry: TransactionLedger


def mint_digital_currency(db: Session, ledger_entry: TransactionLedger) -> MintResult:
    """
    Simulates calling the external CBDC/Bank API to mint e-Rupees, and
    transitions ledger_entry from PENDING to COMPLETED or FAILED.

    PREVENTING DOUBLE-MINTING UNDER CONCURRENCY
    ---------------------------------------------
    A plain `if ledger_entry.status != "PENDING": raise` on the object
    that was passed in is NOT sufficient by itself: it only checks whatever
    status that Python object happened to hold in memory, not what's true
    in the database right now, and it does nothing to stop two concurrent
    calls for the same ledger entry from both passing the check before
    either has written anything back -- exactly the double-mint scenario
    this function is required to prevent.

    Instead, this function re-fetches the row with SELECT ... FOR UPDATE,
    which acquires an exclusive row lock before checking status. A second
    concurrent call for the same entry doesn't get to run this same check
    concurrently -- it blocks until the first call's transaction commits or
    rolls back, and only then evaluates the status, by which point it will
    correctly see COMPLETED or FAILED rather than PENDING. This is also why
    the lock is acquired BEFORE the (mock) external call rather than only
    around the final status write: for a real minting API, the goal isn't
    just "only one DB write wins" -- it's "the mint operation itself is
    only ever invoked once" for a given ledger entry. Locking only around
    the final UPDATE would still let two concurrent callers both invoke a
    real external mint call before either checked in.

    ledger_entry itself is intentionally not trusted for the status check
    for the same reason -- only the freshly-locked row is.
    """
    locked_entry = db.execute(
        select(TransactionLedger).where(TransactionLedger.id == ledger_entry.id).with_for_update()
    ).scalar_one_or_none()

    if locked_entry is None:
        raise ValueError(f"No TransactionLedger row exists with id={ledger_entry.id}.")

    if locked_entry.status != "PENDING":
        raise InvalidLedgerStateError(
            f"Refusing to mint for ledger entry {locked_entry.id}: status is "
            f"{locked_entry.status!r}, not 'PENDING'. Calling this twice for the "
            "same entry is exactly the double-minting scenario this check exists "
            "to prevent -- if this fires, look at the caller, not this function."
        )

    outcome = _call_cbdc_network_mock(locked_entry)

    if outcome.success:
        locked_entry.status = "COMPLETED"
        locked_entry.completed_at = datetime.now(timezone.utc)
        locked_entry.cbdc_reference_number = outcome.cbdc_reference_number
        # FIXED: this assignment was missing even after ledger_model.py
        # gained the column to receive it -- outcome.cbdc_reference_number
        # was being computed and returned in MintResult below, but never
        # actually written to the row. Every successful mint was silently
        # losing its reference number the moment this function returned.
        # Caught while building the FIAT settlement counterpart and
        # comparing the two implementations line for line.
    else:
        locked_entry.status = "FAILED"
        locked_entry.error_reason = outcome.error_reason
        # Same fix as cbdc_reference_number above -- this was also being
        # computed and returned without ever being persisted.
        # completed_at intentionally left unset for FAILED. ledger_model.py
        # already flags this exact question as open -- whether completed_at
        # means "succeeded" specifically or "reached any terminal state" --
        # leaving it null here is the more conservative reading of the two
        # until that's explicitly settled.

    try:
        db.commit()
    except Exception:
        db.rollback()
        raise

    return MintResult(
        success=outcome.success,
        cbdc_reference_number=outcome.cbdc_reference_number,
        error_reason=outcome.error_reason,
        ledger_entry=locked_entry,
    )