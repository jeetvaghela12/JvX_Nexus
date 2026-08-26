"""
API: support_routes.py
Exposes endpoints for the user-facing AI support system.

MOCK AUTH FLAG: x_user_id is a raw header with no cryptographic proof
behind it -- as written (matching the provided base code, "Mock auth for
now"), any caller can set X-User-Id to any value and act as that user.
The real replacement is core/security.py's decode_access_token(),
extracting identity from a verified JWT's "sub" claim instead of trusting
a bare header. Not swapped in here since the brief calls for the mock
explicitly, but this route should not go live authenticating this way.
"""
import logging

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from core.database import get_db
from models.ticket_model import SupportTicket
from services.ai_support import TicketNotFoundError, generate_ai_response

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/support", tags=["AI Support"])


class AskAIRequest(BaseModel):
    user_query: str


class AskAIResponse(BaseModel):
    ticket_id: int
    ai_response: str


@router.post("/tickets/{ticket_id}/ask-ai", response_model=AskAIResponse)
async def ask_ai_support(
    ticket_id: int,
    payload: AskAIRequest,
    x_user_id: int = Header(...),  # Mock auth for now
    db: Session = Depends(get_db),
) -> AskAIResponse:
    """
    Receives a user query for a specific ticket and generates an AI
    response grounded strictly in the ticket's safe context.

    OWNERSHIP CHECK: a ticket that exists but belongs to a different user
    returns the same 404 as a ticket that doesn't exist at all, rather
    than a differentiated 403. A 403 would confirm to an unauthorized
    caller that a ticket with that ID exists -- information they aren't
    entitled to -- which turns ticket_id into an enumeration vector (probe
    sequential IDs, watch for 403 vs 404, map out real ticket volume). A
    uniform 404 gives no signal either way. This is a judgment call, not
    the only valid one -- swap to a differentiated 403/404 if clearer
    error semantics for legitimate API consumers matters more here than
    closing that particular information leak.
    """
    ticket = db.execute(select(SupportTicket).where(SupportTicket.id == ticket_id)).scalar_one_or_none()

    if ticket is None or ticket.user_id != x_user_id:
        raise HTTPException(status_code=404, detail="Ticket not found.")

    # generate_ai_response (services/ai_support.py) does its own internal
    # lookup of the same ticket via build_safe_context -- so this request
    # does two SELECTs by primary key for one ticket, not one. Left as-is
    # rather than refactoring ai_support.py's signature to accept an
    # already-fetched ticket (out of scope for this file, and a single
    # extra indexed PK lookup is a minor cost on what's a low-frequency
    # path compared to payment processing). Worth collapsing to one lookup
    # if ai_support.py's signature gets revisited for other reasons.
    try:
        ai_response = generate_ai_response(db=db, ticket_id=ticket_id, user_query=payload.user_query)
    except TicketNotFoundError as exc:
        # Belt-and-suspenders: the ownership check above already confirmed
        # this ticket exists moments ago, so reaching this in practice
        # would mean a genuine race (the ticket deleted in between) --
        # handled per instruction rather than assumed impossible.
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception:
        logger.exception("Unexpected failure generating AI response (ticket_id=%s)", ticket_id)
        raise

    return AskAIResponse(ticket_id=ticket_id, ai_response=ai_response)