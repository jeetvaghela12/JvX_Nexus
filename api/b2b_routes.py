"""
API: b2b_routes.py
Exposes strictly authenticated B2B endpoints (like the Nostro Bank Webhook).

SIGNATURE VERIFICATION ORDERING: request.body() is read and checked
against x_signature BEFORE anything touches JSON -- that ordering is the
entire point of the Payload Injection Guard rule, not an implementation
detail. A route parameter typed as a Pydantic model or plain dict would
make FastAPI parse the JSON body automatically before this function even
runs, which would put verification (if it happened at all) after parsing
-- exactly backwards, and exactly what a forged/tampered payload would
need to slip past signature checking. Using `request: Request` instead of
a typed body parameter is what keeps that from happening; don't
"simplify" this by adding a typed body parameter later without moving the
signature check somewhere upstream of it.

RawWebhookLog NOTE: the earlier decision was to log 100% of raw incoming
payloads to a RawWebhookLog (or NoSQL dump) at this layer before calling
process_bank_signal, marking it FAILED on UnrecognizedAccountError, so
unmatched signals stay auditable without a nullable user_id on the
ledger. That isn't implemented in this file -- there's no RawWebhookLog
model yet to write to, and today's instructions didn't ask for it here.
Flagging rather than skipping silently: this route is complete against
what was actually asked this turn, but the audit-trail decision from two
turns ago isn't realized until that model (and this route's write to it)
both exist.
"""
import hashlib
import hmac
import json
import logging
from decimal import Decimal

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from core.database import get_db
from services.bank_onboarding_client import get_virtual_account_provider
from services.bank_webhook import WebhookProcessingError, process_bank_signal, trigger_settlement_dispatch

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/b2b", tags=["B2B Webhooks"])


class BankWebhookResponse(BaseModel):
    transaction_reference: str
    status: str
    was_duplicate: bool


def _verify_hmac_signature_mock(raw_body: bytes, signature: str) -> bool:
    """
    MOCK -- stands in for real HMAC-SHA256 verification of the webhook
    payload. There's no settings.BANK_WEBHOOK_HMAC_SECRET in config.py
    yet, so there's no real secret to check against.

    Real implementation, once that setting exists:

        expected = hmac.new(
            settings.BANK_WEBHOOK_HMAC_SECRET.get_secret_value().encode("utf-8"),
            raw_body,
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, signature)

    hmac.compare_digest specifically, never == : a plain string comparison
    short-circuits on the first mismatched byte, which leaks timing
    information an attacker can use to infer the correct signature one
    byte at a time (a timing attack). That detail matters for the real
    implementation regardless of what this mock does below -- verified
    the snippet above actually works correctly (accepts a valid signature,
    rejects a tampered body) before writing it into this docstring.

    For now: deterministic and honest about being fake. Rejects only the
    unambiguously-invalid case (empty/whitespace signature header) and
    accepts everything else, since there's no real secret configured yet
    to check against. This keeps the 401 path genuinely reachable (send
    an empty signature) without needing a test-only parameter a real
    caller couldn't produce.
    """
    return bool(signature and signature.strip())


@router.post("/bank-webhook", response_model=BankWebhookResponse)
async def handle_bank_webhook(
    request: Request,
    response: Response,
    x_idempotency_key: str = Header(...),
    x_signature: str = Header(...),
    db: Session = Depends(get_db),
) -> BankWebhookResponse:
    """
    Receives the raw webhook from the partner bank, verifies its
    signature, and hands the parsed payload to process_bank_signal.

    x_idempotency_key / x_signature map to X-Idempotency-Key /
    X-Signature via FastAPI's standard underscore-to-hyphen header
    convention -- no explicit alias needed.
    """
    # 1. Raw bytes first. Nothing below this line touches JSON until the
    #    signature is verified against these exact bytes.
    raw_body = await request.body()

    # 2. Verify BEFORE parsing -- see module docstring for why this
    #    ordering is load-bearing, not stylistic.
    if not _verify_hmac_signature_mock(raw_body, x_signature):
        raise HTTPException(status_code=401, detail="Invalid webhook signature.")

    # 3. Only now parse JSON. parse_float=Decimal so a bare numeric
    #    literal in the body becomes Decimal directly, never float --
    #    this is the upstream fix bank_webhook.py's own docstring flags
    #    as the real solution; the Decimal(str(x)) fallback there is now
    #    defensive redundancy rather than the primary safeguard.
    try:
        payload = json.loads(raw_body, parse_float=Decimal)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"Malformed JSON body: {exc}") from exc

    # 4. Hand off to the business service.
    try:
        result = process_bank_signal(db=db, payload=payload, idempotency_key=x_idempotency_key)
    except WebhookProcessingError as exc:
        # Catches MalformedPayloadError and UnrecognizedAccountError (both
        # subclass this) plus any future WebhookProcessingError subclass
        # bank_webhook.py might gain later, without this route needing an
        # update every time that happens.
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception:
        # Anything unexpected (DB connectivity, etc.): log it server-side
        # with the idempotency key for traceability, then let it propagate
        # -- FastAPI's default handling turns an uncaught exception into a
        # 500 on its own; this adds the log entry that behavior doesn't.
        logger.exception("Unexpected failure processing bank webhook (idempotency_key=%s)", x_idempotency_key)
        raise

    # 5. Dispatch settlement -- reads the (possibly just-created) ledger
    # row's recipient's preferred_payout_route and routes to CBDC or FIAT
    # settlement. Skips entirely on a duplicate, and never raises past
    # this point -- see trigger_settlement_dispatch's own docstring for
    # why a downstream settlement failure must not turn into a 500
    # returned to the bank for a webhook that itself succeeded.
    #
    # Runs BEFORE the response is built below, on the same db session --
    # if settlement completes synchronously (the mock always does),
    # result.ledger_entry.status below will already reflect COMPLETED/
    # FAILED, not just the PENDING state it had right after creation.
    # Deliberate, not accidental: a more accurate response is a genuine
    # improvement, worth calling out explicitly since it's not obvious
    # from reading this function alone why the status could differ from
    # what process_bank_signal itself set a few lines up.
    trigger_settlement_dispatch(db, result)

    # 6. Map the result to the response. 201 for a genuinely new ledger
    # entry, 200 when this call was a replay of an already-processed
    # signal -- the idempotency guarantee succeeding, not an error.
    response.status_code = 200 if result.was_duplicate else 201
    return BankWebhookResponse(
        transaction_reference=result.ledger_entry.transaction_reference,
        status=result.ledger_entry.status,
        was_duplicate=result.was_duplicate,
    )


class DecentroCallbackAckResponse(BaseModel):
    """
    Decentro's own reference page shows only HTTP 200/400 status examples
    for this callback, not a documented required response body -- most
    webhook consumers only check the status code for acknowledgment, so
    this minimal body is a safe default, not a confirmed contract.
    """

    status: str = "received"


@router.post("/decentro-callback", response_model=DecentroCallbackAckResponse)
async def handle_decentro_balance_callback(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> DecentroCallbackAckResponse:
    """
    Decentro-specific counterpart to /bank-webhook above -- a SEPARATE
    route, not a modification to the generic one, because Decentro's
    actual callback contract is different in two structural ways,
    confirmed directly against their documentation: auth is a shared
    custom header value, not HMAC, and the payload shape has nothing in
    common with what process_bank_signal expects. This route's whole job
    is translating Decentro's shape into that existing, already-tested
    shape and handing off -- process_bank_signal itself is completely
    untouched by any of this.

    REGISTRATION IS NOT SELF-SERVICE: this URL needs to actually be
    registered with Decentro's team by email before they will ever call
    it (see core/config.py's DECENTRO_WEBHOOK_HEADER_NAME/VALUE comments)
    -- deploying this code alone does not make Decentro start sending
    callbacks here.
    """
    raw_body = await request.body()
    headers = dict(request.headers)

    provider = get_virtual_account_provider()
    if not provider.verify_webhook_signature(headers, raw_body):
        raise HTTPException(status_code=401, detail="Invalid or missing Decentro callback header.")

    try:
        payload = json.loads(raw_body, parse_float=Decimal)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"Malformed JSON body: {exc}") from exc

    # PUSH-ONLY FILTER: only a Credit callback represents new inbound
    # funds -- the event this platform's ledger actually models. A Debit
    # callback (a refund, or Decentro's own settlement sweep out of this
    # account) is a structurally different event that process_bank_signal
    # isn't built to record as an incoming transaction; acknowledge it and
    # stop here rather than forcing it through logic built for the other
    # case.
    callback_type = payload.get("type")
    if callback_type != "Credit":
        logger.info("Decentro callback type=%s acknowledged, not processed as an inbound transaction.", callback_type)
        return DecentroCallbackAckResponse()

    idempotency_key = payload.get("callback_txn_id")
    if not idempotency_key:
        raise HTTPException(status_code=400, detail="Missing callback_txn_id.")

    # TRANSLATION LAYER -- see this route's docstring. currency and
    # exchange_rate are hardcoded, not extracted, because Decentro's VA
    # collections are domestic NEFT/RTGS/IMPS only: there is no FX
    # component, and Decentro's callback doesn't send either field.
    # purpose_code is the genuinely awkward one: compliance_purpose_code
    # (models/ledger_model.py) was designed around FEMA cross-border
    # purpose codes, which don't have a natural equivalent for a purely
    # domestic collection. "DOMESTIC_COLLECTION" below is a clearly-
    # labeled placeholder, not a real code -- worth a deliberate decision
    # on whether that column's meaning should broaden, or domestic and
    # cross-border transactions eventually need different handling
    # entirely, rather than this route quietly deciding that on its own.
    translated_payload = {
        "amount": payload.get("amount"),
        "currency": "INR",
        "recipient_account": payload.get("payee_account_number"),
        "exchange_rate": "1.0",
        "purpose_code": "DOMESTIC_COLLECTION",
    }

    try:
        result = process_bank_signal(db=db, payload=translated_payload, idempotency_key=idempotency_key)
    except WebhookProcessingError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception:
        logger.exception("Unexpected failure processing Decentro callback (callback_txn_id=%s)", idempotency_key)
        raise

    # Settlement dispatch, same as the generic /bank-webhook route above --
    # deliberately not duplicated logic beyond this one call, since both
    # routes share trigger_settlement_dispatch rather than each
    # reimplementing the was_duplicate check and error handling.
    trigger_settlement_dispatch(db, result)

    response.status_code = 200 if result.was_duplicate else 201
    return DecentroCallbackAckResponse()