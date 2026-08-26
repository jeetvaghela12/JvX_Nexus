"""
API: admin_routes.py
Internal/admin-only endpoints -- not part of the user-facing API surface.
Currently just the sweep trigger, meant to be called by an external
scheduler (cron, AWS EventBridge) on a timer, not by any user-facing
client.
"""
import hmac
import logging

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from core.config import settings
from core.database import get_db
from services.sweep_engine import DEFAULT_SWEEP_BATCH_LIMIT, sweep_pending_settlements

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin", tags=["Admin"])


class SweepResponse(BaseModel):
    total_found: int
    dispatched_and_succeeded: int
    dispatched_and_failed: int
    skipped_not_dispatched: int
    unexpected_errors: int
    problem_ledger_entry_ids: list[int]


@router.post("/sweep-pending", response_model=SweepResponse)
async def trigger_sweep(
    x_admin_api_key: str = Header(...),
    db: Session = Depends(get_db),
) -> SweepResponse:
    """
    Re-attempts settlement dispatch for every PENDING TransactionLedger
    row, oldest first, up to services/sweep_engine.py's batch limit.
    Meant to be called on a schedule (every few minutes) by something
    outside this application entirely -- a cron job, AWS EventBridge, or
    equivalent -- not triggered by anything inside this codebase itself.

    AUTH: a shared secret via X-Admin-Api-Key, compared with
    hmac.compare_digest -- same constant-time-comparison discipline as
    every other shared-secret check in this codebase (POST /kyc/verify,
    Decentro's webhook header), for the same reason: a naive `==`
    comparison leaks timing information about how many leading characters
    matched, which is a real (if slow) way to brute-force a secret over
    enough attempts.

    This is meaningfully higher-stakes than /kyc/verify's shared secret:
    a successful call here can dispatch real settlement (mint or bank
    transfer, mocked today, real money once those are) for potentially
    hundreds of transactions in one request. Treat ADMIN_API_KEY with
    that in mind -- store it wherever the calling scheduler keeps its own
    secrets (e.g. AWS Secrets Manager, referenced from EventBridge/
    Lambda), not embedded in a cron script's own source.

    SYNCHRONOUS, NOT FIRE-AND-FORGET, ON PURPOSE: this blocks until the
    whole batch finishes and returns a full summary in the response body,
    rather than kicking off a background task and returning immediately.
    Deliberately simple -- avoids introducing a task queue (Celery/Redis
    or similar) for what a bounded, periodically-scheduled batch job
    doesn't yet need. Worth revisiting if DEFAULT_SWEEP_BATCH_LIMIT ever
    needs to grow enough that a single sweep risks exceeding the calling
    scheduler's own HTTP timeout -- an internal/cron-triggered timeout is
    typically far more generous than a user-facing one, but it isn't
    infinite.
    """
    expected = settings.ADMIN_API_KEY.get_secret_value().strip()
    if not hmac.compare_digest(x_admin_api_key.strip(), expected):
        raise HTTPException(status_code=401, detail="Invalid admin API key.")

    summary = sweep_pending_settlements(db, batch_limit=DEFAULT_SWEEP_BATCH_LIMIT)

    return SweepResponse(
        total_found=summary.total_found,
        dispatched_and_succeeded=summary.dispatched_and_succeeded,
        dispatched_and_failed=summary.dispatched_and_failed,
        skipped_not_dispatched=summary.skipped_not_dispatched,
        unexpected_errors=summary.unexpected_errors,
        problem_ledger_entry_ids=summary.problem_ledger_entry_ids,
    )