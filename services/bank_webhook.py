"""
Services: bank_webhook.py

Processes a payment signal from the partner bank.

WHAT THIS DOES: resolves which customer the money belongs to, records the
payment, and tries to match it against a pre-declaration.

WHAT THIS NO LONGER DOES, and must not do again: calculate a margin,
dispatch a settlement, or move anything. Those belonged to an earlier
design in which this platform held funds. The bank credits its own
customer; we record that it happened.

SCOPE: this function receives an already-parsed payload. HMAC verification
against the raw request bytes happens upstream in api/b2b_routes.py,
before JSON parsing, and that ordering is the entire point — a signature
checked after parsing has already let a forged payload through the parser.
"""
import logging
from dataclasses import dataclass
from datetime import date
from decimal import Decimal, InvalidOperation
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from models.declaration_model import Declaration
from models.payment_model import InboundPayment
from models.user_model import User
from models.virtual_account_model import VirtualAccount

logger = logging.getLogger(__name__)

# How far the amount may differ from a pre-declaration and still match.
# Intermediary banks deduct their own charges in transit, so the amount
# that lands is routinely a little under what the payer sent. Too tight
# and nothing ever matches; too loose and a declaration attaches itself
# to an unrelated payment of similar size.
_AMOUNT_TOLERANCE = Decimal("0.02")


class WebhookProcessingError(Exception):
    """Business-logic rejection of a bank signal. Infrastructure failures propagate as themselves."""


class MalformedPayloadError(WebhookProcessingError):
    """A required field is missing, or a value cannot be parsed into the type it needs."""


class UnrecognizedAccountError(WebhookProcessingError):
    """The account identifier matches no known VirtualAccount."""


@dataclass(frozen=True, slots=True)
class WebhookResult:
    payment: InboundPayment
    was_duplicate: bool
    matched_declaration: Declaration | None


def _require(payload: dict[str, Any], key: str) -> Any:
    if key not in payload or payload[key] is None:
        raise MalformedPayloadError(f"Payload is missing required field {key!r}.")
    return payload[key]


def _to_decimal(value: Any, field: str) -> Decimal:
    """
    Parse to Decimal via str.

    Decimal(str(value)) rather than Decimal(value): if the JSON parser
    produced a float, Decimal(float) preserves the binary representation
    error exactly, so 0.1 becomes 0.1000000000000000055511151231257827.
    Going through str truncates at the decimal representation, which is
    the value the bank actually meant.
    """
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        raise MalformedPayloadError(f"Field {field!r} is not a valid decimal: {value!r}.")
    if parsed <= 0:
        raise MalformedPayloadError(f"Field {field!r} must be positive, got {parsed}.")
    return parsed


def _resolve_account(db: Session, account_number: str) -> tuple[VirtualAccount, User]:
    """
    Find the virtual account and its owner.

    Two queries rather than a join, matching this codebase's style
    elsewhere. A webhook handler is not a hot path, so the extra round
    trip costs nothing worth optimising away.

    scalar_one_or_none rather than first(): account_number is unique, so
    at most one row can match. If that is ever violated it is a data
    integrity problem, and this raises loudly instead of silently picking
    one of several.
    """
    account = db.execute(
        select(VirtualAccount).where(VirtualAccount.account_number == account_number)
    ).scalar_one_or_none()
    if account is None:
        raise UnrecognizedAccountError(
            f"No virtual account matches {account_number!r}. This signal references an account we do not know."
        )

    user = db.execute(select(User).where(User.id == account.user_id)).scalar_one_or_none()
    if user is None:
        raise UnrecognizedAccountError(
            f"Virtual account {account_number!r} points to user_id={account.user_id}, which does not exist. "
            "This is a data integrity problem, not a normal rejection."
        )
    return account, user


def _find_matching_declaration(
    db: Session, user: User, amount: Decimal, currency: str
) -> Declaration | None:
    """
    Look for an open pre-declaration this payment plausibly satisfies.

    Matching is deliberately conservative. A wrong match is worse than no
    match: it attaches a purpose code the customer did not intend to money
    they did not mean it for, and the bank files that with RBI. When in
    doubt, return None and let the payment arrive undeclared, which is the
    status quo and harms nothing.

    Criteria: same user, same currency, still FILED, not past its expected
    date, amount within tolerance. Oldest first, so a customer with two
    similar open declarations gets the one they have been waiting on
    longest.
    """
    lower = amount * (Decimal("1") - _AMOUNT_TOLERANCE)
    upper = amount * (Decimal("1") + _AMOUNT_TOLERANCE)

    candidates = db.execute(
        select(Declaration)
        .where(
            Declaration.user_id == user.id,
            Declaration.kind == "PRE_PAYMENT",
            Declaration.status == "FILED",
            Declaration.currency == currency,
            Declaration.expected_amount >= lower,
            Declaration.expected_amount <= upper,
            Declaration.expected_by >= date.today(),
        )
        .order_by(Declaration.created_at.asc())
    ).scalars().all()

    if not candidates:
        return None

    if len(candidates) > 1:
        # Ambiguity resolved by not resolving it. Two open declarations of
        # similar size means we cannot tell which this payment satisfies,
        # and guessing would file a purpose code on a coin flip.
        logger.info(
            "Payment of %s %s for user_id=%s matches %d open declarations. Leaving unmatched.",
            amount,
            currency,
            user.id,
            len(candidates),
        )
        return None

    return candidates[0]


def process_bank_signal(
    db: Session, payload: dict[str, Any], bank_reference: str
) -> WebhookResult:
    """
    Record one inbound payment.

    IDEMPOTENCY: bank_reference is unique. A redelivered signal — and
    banks redeliver, on timeout, on retry, on operator action — finds the
    existing row and returns it rather than creating a second record of
    the same money. The unique constraint is the guarantee; the lookup
    below is the fast path.
    """
    existing = db.execute(
        select(InboundPayment).where(InboundPayment.bank_reference == bank_reference)
    ).scalar_one_or_none()
    if existing is not None:
        logger.info("Replay of bank_reference=%s, returning existing payment.", bank_reference)
        return WebhookResult(payment=existing, was_duplicate=True, matched_declaration=None)

    account_number = str(_require(payload, "account_number")).strip()
    amount = _to_decimal(_require(payload, "amount"), "amount")

    currency = str(_require(payload, "currency")).strip().upper()
    if len(currency) != 3:
        raise MalformedPayloadError(f"currency must be a 3-letter ISO 4217 code, got {currency!r}.")

    account, user = _resolve_account(db, account_number)

    declaration = _find_matching_declaration(db, user, amount, currency)

    payment = InboundPayment(
        bank_reference=bank_reference,
        user_id=user.id,
        virtual_account_id=account.id,
        status="RECEIVED",
        amount=amount,
        currency=currency,
        payer_name=(str(payload["payer_name"]).strip() if payload.get("payer_name") else None),
        payer_country=(
            str(payload["payer_country"]).strip().upper() if payload.get("payer_country") else None
        ),
        # Taken from the declaration where one matched. The bank confirms
        # or overrides it — we suggest, they file.
        purpose_code=(declaration.purpose_code if declaration else None),
        declaration_id=(declaration.id if declaration else None),
        bank_remark=(str(payload["remark"]).strip() if payload.get("remark") else None),
    )

    try:
        db.add(payment)
        db.flush()

        if declaration is not None:
            declaration.status = "MATCHED"
            declaration.matched_payment_id = payment.id
            declaration.matched_at = payment.received_at

        db.commit()
    except IntegrityError:
        # Two concurrent deliveries of the same signal. Both passed the
        # lookup above; one wins the insert. Re-read and return the
        # winner's row rather than failing the loser's request, because
        # from the bank's perspective the payment was recorded either way.
        db.rollback()
        winner = db.execute(
            select(InboundPayment).where(InboundPayment.bank_reference == bank_reference)
        ).scalar_one_or_none()
        if winner is not None:
            return WebhookResult(payment=winner, was_duplicate=True, matched_declaration=None)
        raise
    except Exception:
        db.rollback()
        logger.exception("Failed to record payment bank_reference=%s", bank_reference)
        raise

    db.refresh(payment)
    return WebhookResult(payment=payment, was_duplicate=False, matched_declaration=declaration)


def apply_status_update(
    db: Session, bank_reference: str, payload: dict[str, Any]
) -> InboundPayment:
    """
    Apply a status change the bank reported for a payment we already hold.

    The bank tells us it credited, held, or returned the money. We write
    down what it said. There is no state machine here validating which
    transitions are legal, and that is deliberate: the bank's systems are
    the authority on the lifecycle of its own payment, and a client-side
    machine that disagrees would be wrong by construction.
    """
    payment = db.execute(
        select(InboundPayment).where(InboundPayment.bank_reference == bank_reference)
    ).scalar_one_or_none()
    if payment is None:
        raise UnrecognizedAccountError(
            f"No payment recorded for bank_reference={bank_reference!r}."
        )

    new_status = str(_require(payload, "status")).strip().upper()
    if new_status not in ("RECEIVED", "CREDITED", "RETURNED", "ON_HOLD"):
        raise MalformedPayloadError(f"Unrecognised status {new_status!r}.")

    payment.status = new_status

    if payload.get("credited_amount_inr") is not None:
        payment.credited_amount_inr = _to_decimal(
            payload["credited_amount_inr"], "credited_amount_inr"
        )
    if payload.get("exchange_rate") is not None:
        payment.exchange_rate = _to_decimal(payload["exchange_rate"], "exchange_rate")
    if payload.get("purpose_code"):
        # The bank's own classification overrides whatever we suggested
        # from the declaration. Theirs is the one filed with RBI.
        payment.purpose_code = str(payload["purpose_code"]).strip().upper()
    if payload.get("fira_reference"):
        payment.fira_reference = str(payload["fira_reference"]).strip()
        payment.fira_issued_at = payment.updated_at
    if payload.get("remark"):
        payment.bank_remark = str(payload["remark"]).strip()

    db.commit()
    db.refresh(payment)
    return payment