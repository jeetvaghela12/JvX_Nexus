"""
Services: sweep_engine.py
Batch retry for stuck PENDING TransactionLedger rows -- closes the gap
services/settlement_engine.py's own docstring flagged: dispatch_settlement
handles the immediate, webhook-triggered attempt, but nothing previously
retried a row left PENDING because a payout method wasn't configured yet,
or because dispatch hit an unexpected error. This file is that retry.

WHY A ROW ENDS UP HERE, AND WHY REPEATED SWEEPS ARE SAFE: a row stays
PENDING either because dispatch_settlement returned dispatched=False (no
bank account/wallet configured, or an unrecognized preferred_payout_route)
or because something raised unexpectedly. Re-running dispatch_settlement
on a row that's still genuinely PENDING is always safe to retry -- the
underlying mint_digital_currency/execute_fiat_settlement functions refuse
(via InvalidLedgerStateError) to touch a row that isn't PENDING, which is
exactly the same guarantee that makes trigger_settlement_dispatch safe to
call from two different webhook routes. A sweep finding nothing to do for
a given row costs one fast, cheap check, not a real problem -- so running
this every few minutes indefinitely, for rows that may take hours to
resolve (a user finishing payout setup), is the intended, correct
behavior, not something needing special-cased backoff.
"""
import logging
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from models.ledger_model import TransactionLedger
from services.settlement_engine import dispatch_settlement

logger = logging.getLogger(__name__)

DEFAULT_SWEEP_BATCH_LIMIT = 500
# A bound, not a guess at "the right number" -- without one, a systemic
# problem (many rows failing dispatch for the same underlying reason)
# could turn one sweep run into an unbounded-duration request. 500 rows
# at roughly 50-100ms each (the mock settlement calls' simulated latency
# plus DB round-trips) is realistically tens of seconds, not minutes --
# worth revisiting downward if real volume or a real (non-mock, higher-
# latency) settlement API changes that math.


@dataclass(frozen=True, slots=True)
class SweepSummary:
    total_found: int
    dispatched_and_succeeded: int
    dispatched_and_failed: int
    skipped_not_dispatched: int
    unexpected_errors: int
    problem_ledger_entry_ids: list[int] = field(default_factory=list)
    # Only rows that need actual human attention: dispatched-but-failed,
    # or an unexpected error. Deliberately does NOT include "skipped, no
    # payout method configured yet" rows -- that's an expected, self-
    # resolving state (the user finishes payout setup, the next sweep
    # picks it up), not something worth surfacing as a problem to
    # whoever's watching sweep output.


def sweep_pending_settlements(db: Session, *, batch_limit: int = DEFAULT_SWEEP_BATCH_LIMIT) -> SweepSummary:
    """
    Finds up to batch_limit PENDING rows, oldest first, and re-attempts
    dispatch_settlement for each -- one row's failure (expected or
    unexpected) never stops the batch; every row gets its own try/except,
    and the loop always continues.

    No SELECT ... FOR UPDATE at this query level, deliberately: it isn't
    needed for correctness, since dispatch_settlement's own underlying
    calls already acquire a row-level lock before touching anything --
    two overlapping sweep runs (or a sweep overlapping a webhook-triggered
    dispatch for the same row) would have the second attempt correctly
    block, then see the row is no longer PENDING, and cleanly report
    dispatched=False rather than double-settle. Locking at this level too
    would only be a minor efficiency gain (avoiding a short wait rather
    than preventing a real bug), not a correctness requirement -- skipped
    to keep this function simpler.
    """
    pending_rows = (
        db.execute(
            select(TransactionLedger)
            .where(TransactionLedger.status == "PENDING")
            .order_by(TransactionLedger.created_at.asc())
            .limit(batch_limit)
        )
        .scalars()
        .all()
    )

    dispatched_and_succeeded = 0
    dispatched_and_failed = 0
    skipped_not_dispatched = 0
    unexpected_errors = 0
    problem_ids: list[int] = []

    for row in pending_rows:
        try:
            outcome = dispatch_settlement(db, row)
        except Exception:
            logger.exception("Sweep: unexpected error dispatching settlement for ledger_entry_id=%s", row.id)
            db.rollback()
            # Defensive, not redundant: mint_digital_currency/
            # execute_fiat_settlement already roll back on a failed
            # commit internally, but an exception raised BEFORE reaching
            # that commit (a genuine bug, not a DB failure) could leave
            # this session holding uncommitted changes. Rolling back here
            # unconditionally guarantees a clean session for the NEXT row
            # in this loop, regardless of exactly where the failure
            # actually occurred.
            unexpected_errors += 1
            problem_ids.append(row.id)
            continue

        if not outcome.dispatched:
            skipped_not_dispatched += 1
        elif outcome.success:
            dispatched_and_succeeded += 1
        else:
            dispatched_and_failed += 1
            problem_ids.append(row.id)

    summary = SweepSummary(
        total_found=len(pending_rows),
        dispatched_and_succeeded=dispatched_and_succeeded,
        dispatched_and_failed=dispatched_and_failed,
        skipped_not_dispatched=skipped_not_dispatched,
        unexpected_errors=unexpected_errors,
        problem_ledger_entry_ids=problem_ids,
    )
    logger.info(
        "Sweep complete: found=%d succeeded=%d failed=%d skipped=%d errors=%d",
        summary.total_found,
        summary.dispatched_and_succeeded,
        summary.dispatched_and_failed,
        summary.skipped_not_dispatched,
        summary.unexpected_errors,
    )
    return summary