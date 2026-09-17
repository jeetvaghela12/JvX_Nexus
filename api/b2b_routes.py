"""
API: b2b_routes.py

Endpoints the partner bank calls. Not the customer — the bank's own
systems.

SIGNATURE ORDERING IS LOAD-BEARING. The raw body is read and verified
before anything parses JSON. This is why the routes below take
`request: Request` rather than a typed Pydantic body: a typed parameter
makes FastAPI parse the body before the function runs, which puts
verification after parsing — exactly backwards, and exactly the gap a
forged payload needs. Do not "simplify" this by adding a typed body
parameter without moving verification upstream of it.
"""
import hashlib
import hmac
import json
import logging
from decimal import Decimal

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from core.config import settings
from core.database import get_db
from services.bank_webhook import (
    WebhookProcessingError,
    apply_status_update,
    process_bank_signal,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/b2b", tags=["Bank Integration"])


class PaymentSignalResponse(BaseModel):
    bank_reference: str
    status: str
    was_duplicate: bool
    matched_declaration: str | None


class StatusUpdateResponse(BaseModel):
    bank_reference: str
    status: str


def _verify_signature(raw_body: bytes, signature: str) -> bool:
    """
    HMAC-SHA256 over the raw request body.

    hmac.compare_digest, never ==. A plain string comparison returns as
    soon as it finds a mismatched byte, and the time that takes tells an
    attacker how many leading bytes were right. Repeated, that recovers a
    valid signature one byte at a time. compare_digest takes the same time
    regardless of where the first difference is.

    An unconfigured secret rejects everything rather than accepting
    everything. A misconfiguration should fail closed and be obvious in
    the logs, not silently disable authentication on the one endpoint that
    accepts instructions from outside.
    """
    secret = settings.BANK_WEBHOOK_HMAC_SECRET
    if not secret:
        logger.error(
            "BANK_WEBHOOK_HMAC_SECRET is not configured. Rejecting all webhook traffic."
        )
        return False

    if not signature or not signature.strip():
        return False

    expected = hmac.new(
        secret.get_secret_value().encode("utf-8"),
        raw_body,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected, signature.strip())


async def _read_verified_payload(request: Request, signature: str) -> dict:
    """
    Read the raw body, verify it, and only then parse.

    parse_float=Decimal so that a bare numeric literal in the JSON becomes
    a Decimal directly and never passes through float. An amount that
    round-trips through a float has already lost precision before any of
    our code sees it, and no amount of careful Decimal handling downstream
    recovers it.
    """
    raw_body = await request.body()

    if not _verify_signature(raw_body, signature):
        raise HTTPException(status_code=401, detail="Invalid webhook signature.")

    try:
        return json.loads(raw_body, parse_float=Decimal)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"Malformed JSON body: {exc}") from exc


@router.post("/payment-signal", response_model=PaymentSignalResponse)
async def receive_payment_signal(
    request: Request,
    response: Response,
    x_bank_reference: str = Header(...),
    x_signature: str = Header(...),
    db: Session = Depends(get_db),
) -> PaymentSignalResponse:
    """
    The bank tells us money arrived in one of its virtual accounts.

    Returns 201 for a newly recorded payment, 200 for a replay of one
    already held. Banks redeliver — on timeout, on retry, on an operator
    pressing resend — and a replay is a normal event, not an error. The
    status code is the only difference the bank needs to see.
    """
    payload = await _read_verified_payload(request, x_signature)

    try:
        result = process_bank_signal(
            db=db, payload=payload, bank_reference=x_bank_reference.strip()
        )
    except WebhookProcessingError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception:
        logger.exception(
            "Unexpected failure processing payment signal (bank_reference=%s)",
            x_bank_reference,
        )
        raise

    response.status_code = 200 if result.was_duplicate else 201

    return PaymentSignalResponse(
        bank_reference=result.payment.bank_reference,
        status=result.payment.status,
        was_duplicate=result.was_duplicate,
        matched_declaration=(
            result.matched_declaration.reference if result.matched_declaration else None
        ),
    )


@router.post("/payment-status", response_model=StatusUpdateResponse)
async def receive_status_update(
    request: Request,
    x_bank_reference: str = Header(...),
    x_signature: str = Header(...),
    db: Session = Depends(get_db),
) -> StatusUpdateResponse:
    """
    The bank reports what it did with a payment: credited, held, returned,
    FIRA issued.

    We record the bank's account of its own actions. There is no
    validation here that a transition is legal, because the bank's systems
    are the authority on the lifecycle of the bank's payment. A state
    machine on this side that disagreed would simply be wrong.
    """
    payload = await _read_verified_payload(request, x_signature)

    try:
        payment = apply_status_update(
            db=db, bank_reference=x_bank_reference.strip(), payload=payload
        )
    except WebhookProcessingError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception:
        logger.exception(
            "Unexpected failure applying status update (bank_reference=%s)", x_bank_reference
        )
        raise

    return StatusUpdateResponse(
        bank_reference=payment.bank_reference,
        status=payment.status,
    )