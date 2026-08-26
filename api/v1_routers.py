"""
API: v1_routers.py
Exposes standard client-facing endpoints (e.g., fetching transaction history).
"""
import logging
from datetime import datetime
from decimal import Decimal

from fastapi import APIRouter, Depends, Header, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from core.database import get_db
from models.ledger_model import TransactionLedger

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["Client API"])


class TransactionHistoryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)  # lets .model_validate() read straight off the ORM row below

    transaction_reference: str
    status: str
    gross_amount: Decimal
    source_currency: str
    created_at: datetime


@router.get("/transactions", response_model=list[TransactionHistoryResponse])
async def get_transaction_history(
    x_user_id: int = Header(...),  # Mock auth for now -- JWT replacement planned for the final integration pass
    limit: int = Query(default=50, ge=1, le=100),
    db: Session = Depends(get_db),
) -> list[TransactionHistoryResponse]:
    """
    Fetches the transaction history for the authenticated user: newest
    first, capped at `limit` (default 50, hard ceiling 100) so a user
    with a very long history can't trigger an unbounded payload fetch.
    No ownership check needed here the way support_routes.py needed one
    for ticket_id -- the query is scoped to x_user_id itself, so there's
    no other user's data this could ever return in the first place.

    INDEX USAGE: this is exactly the query shape
    ix_ledger_user_id_created_at (a composite index on (user_id,
    created_at)) was built for. Postgres can satisfy WHERE user_id = X by
    jumping straight into that user's slice of the index, and satisfy
    ORDER BY created_at DESC over that same slice with a backward index
    scan -- B-tree indexes support reverse traversal natively, so this
    doesn't need a separate DESC-ordered index or an explicit sort step.
    Combined with LIMIT, Postgres can stop as soon as it's collected
    `limit` rows without touching the rest of that user's history at all
    -- the index and the limit reinforce each other here, they're not
    just two independent optimizations.
    """
    try:
        statement = (
            select(TransactionLedger)
            .where(TransactionLedger.user_id == x_user_id)
            .order_by(TransactionLedger.created_at.desc())
            .limit(limit)
        )
        rows = db.execute(statement).scalars().all()
    except Exception:
        logger.exception("Unexpected failure fetching transaction history (user_id=%s)", x_user_id)
        raise

    # Explicit conversion, not just `return rows` and trusting
    # response_model to coerce it: this keeps the function's own return
    # type hint (list[TransactionHistoryResponse]) literally true, rather
    # than relying on FastAPI's automatic response_model validation to
    # paper over a return type that doesn't actually match what's
    # returned at the Python level.
    return [TransactionHistoryResponse.model_validate(row) for row in rows]