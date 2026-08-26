"""
Services: bank_webhook.py
Handles incoming signals from partner banks, verifying idempotency and initiating the ledger entry.

SCOPE NOTE: this file starts from an already-parsed JSON payload (dict)
and an already-extracted idempotency_key. HMAC-SHA256 signature
verification of the raw request body happens strictly BEFORE JSON
parsing, in the API route (not built yet) -- by the time payload/
idempotency_key reach this function, the signature has already been
checked upstream. This file has no raw request bytes to verify against
and isn't the right layer to do it even if it did.

PAYLOAD ASSUMPTION FLAG: the brief only confirmed 'amount' and 'currency'
as payload keys. Building a valid TransactionLedger row also needs a way
to identify which platform user the funds belong to, an FX rate, and a
compliance purpose code -- none of those were specified, and none are
invented as dummy values here. The extraction below assumes 'recipient_
account', 'exchange_rate', and 'purpose_code' as the additional keys;
treat those three names as placeholders to confirm against the real bank
message format, not as settled fact. base_usd_exchange_rate in particular
is worth a second look: it's assumed here to come from the bank's own
payload, but since ledger_model.py documents it as existing purely for
independent dashboard reporting, sourcing it from an independent market
FX feed instead of the bank's self-reported rate may be the better design
-- flagging rather than deciding that here.
"""
import logging
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from models.ledger_model import TransactionLedger
from models.user_model import User
from models.virtual_account_model import VirtualAccount
from services.margin_engine import calculate_transaction_splits
from services.settlement_engine import dispatch_settlement

logger = logging.getLogger(__name__)


class WebhookProcessingError(Exception):
    """Base class for business-logic rejections of a bank signal, as opposed to unexpected infrastructure failures (DB connectivity, etc.), which propagate as whatever they naturally are."""


class MalformedPayloadError(WebhookProcessingError):
    """The payload is missing a required field, or a field's value can't be parsed into the type it needs to be."""


class UnrecognizedAccountError(WebhookProcessingError):
    """The payload's account identifier doesn't match any known VirtualAccount.account_number."""


@dataclass(frozen=True, slots=True)
class WebhookProcessingResult:
    """
    ledger_entry: the TransactionLedger row for this idempotency_key --
    either newly created, or the pre-existing one if this call was a
    replay of an already-processed signal.
    was_duplicate: lets the future API layer distinguish "just created"
    (e.g. respond 201) from "already existed, here it is again" (e.g.
    respond 200) without querying anything itself.
    """
    ledger_entry: TransactionLedger
    was_duplicate: bool


def _resolve_recipient(db: Session, account_number: str) -> User:
    """
    Look up which platform user this signal's funds belong to.

    Two queries, not a join: VirtualAccount -> User, matching this
    codebase's established style everywhere else (no ORM relationship()
    objects, explicit selects at the call site) rather than introducing a
    join pattern used nowhere else in this project. This isn't a hot
    path -- a webhook handler, not a request loop -- so the extra
    round-trip costs nothing that matters.

    scalar_one_or_none() rather than .first(): account_number is
    unique=True on VirtualAccount, so at most one row can ever match.
    Using the "exactly zero or one" method makes that assumption explicit
    and self-verifying -- if it's ever violated (a data integrity
    problem, not something that should be possible), this raises loudly
    instead of .first() silently picking one of several matches and
    hiding the bug.
    """
    virtual_account = db.execute(
        select(VirtualAccount).where(VirtualAccount.account_number == account_number)
    ).scalar_one_or_none()
    if virtual_account is None:
        raise UnrecognizedAccountError(
            f"No VirtualAccount found with account_number={account_number!r} -- "
            "this webhook references an account the platform doesn't recognize."
        )

    user = db.execute(select(User).where(User.id == virtual_account.user_id)).scalar_one_or_none()
    if user is None:
        # Should be unreachable given VirtualAccount.user_id's
        # ondelete=RESTRICT -- a VirtualAccount row can't outlive the User
        # it points to. Raised explicitly anyway rather than trusting
        # that guarantee silently: "should be unreachable" and "is
        # unreachable" aren't the same claim, and a data integrity
        # problem here deserves a loud failure, not a None slipping
        # further into this function.
        raise UnrecognizedAccountError(
            f"VirtualAccount {account_number!r} references user_id={virtual_account.user_id}, "
            "but no such user exists -- this indicates a data integrity problem, not a "
            "normal rejection."
        )
    return user


def process_bank_signal(db: Session, payload: dict[str, Any], idempotency_key: str) -> WebhookProcessingResult:
    """
    Process one bank webhook signal: resolve the recipient, run the
    amount through margin_engine, and stage a PENDING TransactionLedger
    row -- idempotently.

    HOW IDEMPOTENCY IS ENFORCED
    ----------------------------
    idempotency_key becomes transaction_reference, which is unique=True
    on TransactionLedger. The actual guarantee is that DB-level unique
    constraint, not application logic -- application logic only has to
    cooperate with it correctly, via two layers:

    1. Fast path: a plain SELECT by transaction_reference, first thing in
       this function. If a row's already there, return it immediately --
       no point spending a DB round-trip resolving the user or running
       the fee/split math for a signal we've already processed.

    2. The actual guarantee: even after the fast path finds nothing, this
       function still INSERTS first and only finds out it lost a race via
       a caught IntegrityError, rather than trusting the fast-path SELECT
       as proof nothing exists. A "SELECT to check, then INSERT if
       missing" approach LOOKS sufficient but has a real race window: two
       concurrent calls for the same idempotency_key (a genuine
       possibility -- bank retries and near-simultaneous redeliveries are
       exactly what idempotency exists to handle) can both pass the
       SELECT before either commits, and then both attempt to insert.
       Only the database's unique constraint can arbitrate that atomically;
       no amount of application-level checking before the write can.

    When the INSERT does lose that race, IntegrityError is caught, the
    session is rolled back (mandatory -- a session can't be reused after
    a failed flush without rolling back first), and the row is re-queried
    by transaction_reference to return the winner's copy with
    was_duplicate=True. That re-query is also what keeps this from
    mishandling a DIFFERENT constraint violation: IntegrityError isn't
    unique to the idempotency case -- a bad user_id FK, or the revenue-
    split / exchange-rate CHECK constraints firing from a margin_engine
    bug, would ALSO raise IntegrityError. If the re-query finds nothing,
    it wasn't a duplicate; the exception is re-raised rather than
    silently treated as "just a retry".
    """
    # --- Idempotency fast path -----------------------------------------
    existing = db.execute(
        select(TransactionLedger).where(TransactionLedger.transaction_reference == idempotency_key)
    ).scalar_one_or_none()
    if existing is not None:
        return WebhookProcessingResult(ledger_entry=existing, was_duplicate=True)

    # --- Extract & validate payload fields -------------------------------
    # Decimal(str(x)), never Decimal(x), for anything that came out of
    # parsed JSON: a bare JSON numeric literal (1234.56, not "1234.56")
    # parses into a Python float, and Decimal(that_float) captures the
    # float's exact binary imprecision (Decimal(1234.56) is actually
    # Decimal('1234.55999999999994543031789362430572509765625')) --
    # exactly the kind of silent corruption Numeric(18, 4)/Decimal
    # elsewhere in this codebase exists to prevent. Decimal(str(x)) goes
    # through the clean decimal string instead. The real fix belongs one
    # layer up, in whatever parses the raw webhook body (json.loads(...,
    # parse_float=Decimal)) -- this is the defensive fallback for this
    # function specifically, in case that upstream fix isn't in place.
    try:
        gross_amount = Decimal(str(payload["amount"]))
        source_currency = str(payload["currency"]).strip().upper()
        recipient_account_number = str(payload["recipient_account"]).strip()
        base_usd_exchange_rate = Decimal(str(payload["exchange_rate"]))
        compliance_purpose_code = str(payload["purpose_code"]).strip()
    except (KeyError, InvalidOperation, TypeError) as exc:
        raise MalformedPayloadError(f"Webhook payload missing or malformed field: {exc}") from exc

    if len(source_currency) != 3:
        raise MalformedPayloadError(f"currency must be a 3-letter ISO 4217 code, got {source_currency!r}.")
    if base_usd_exchange_rate <= 0:
        raise MalformedPayloadError(f"exchange_rate must be positive, got {base_usd_exchange_rate}.")

    # --- Fee/tax/split math (pure, no DB access -- fails fast on a bad
    # amount before spending a round-trip on the user lookup below) ------
    split = calculate_transaction_splits(gross_amount)

    # --- Resolve which platform user this signal belongs to -------------
    recipient = _resolve_recipient(db, recipient_account_number)

    # --- Stage and attempt the insert ------------------------------------
    new_entry = TransactionLedger(
        transaction_reference=idempotency_key,
        user_id=recipient.id,
        status="PENDING",
        gross_amount=split.gross_amount,
        source_currency=source_currency,
        base_usd_exchange_rate=base_usd_exchange_rate,
        platform_fee_charged=split.platform_fee_charged,
        tax_collected=split.tax_collected,
        net_platform_revenue=split.net_platform_revenue,
        partner_bank_revenue=split.partner_bank_revenue,
        compliance_purpose_code=compliance_purpose_code,
    )

    try:
        db.add(new_entry)
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = db.execute(
            select(TransactionLedger).where(TransactionLedger.transaction_reference == idempotency_key)
        ).scalar_one_or_none()
        if existing is not None:
            # Confirmed: a concurrent call for this exact idempotency_key
            # won the race and committed first. This IS the idempotency
            # guarantee working as designed, not a failure.
            return WebhookProcessingResult(ledger_entry=existing, was_duplicate=True)
        # No row exists for this transaction_reference, so the
        # IntegrityError was caused by something else entirely (bad FK,
        # a CHECK constraint tripped by bad data). Don't mask a real
        # failure as a benign retry.
        raise
    except Exception:
        # Anything else unexpected mid-write: roll back so this session
        # isn't left holding a half-open transaction for whatever runs
        # next on it, then propagate -- this function doesn't try to
        # interpret failures it has no specific handling for.
        db.rollback()
        raise

    db.refresh(new_entry)  # populate id / created_at, generated server-side, before handing the row back
    return WebhookProcessingResult(ledger_entry=new_entry, was_duplicate=False)


def trigger_settlement_dispatch(db: Session, result: WebhookProcessingResult) -> None:
    """
    Called by the route layer (api/b2b_routes.py) AFTER process_bank_signal
    returns successfully -- deliberately a SEPARATE function, not folded
    into process_bank_signal itself. That function is the most tested,
    most proven piece of this entire codebase (idempotent, exhaustively
    verified split math); adding settlement dispatch to its own body would
    mean modifying it for a concern that has nothing to do with what makes
    it correct. This function sits right next to it instead, callable by
    both /b2b/bank-webhook and /b2b/decentro-callback without either
    duplicating this logic.

    was_duplicate SKIPS dispatch entirely, not just avoids redundant work:
    a duplicate means process_bank_signal found a pre-existing row for
    this idempotency_key, which means dispatch already ran (or is running)
    for it via the ORIGINAL, non-duplicate call. Re-dispatching here would
    at best be a guaranteed no-op (mint_digital_currency/
    execute_fiat_settlement both refuse a non-PENDING row) and at worst a
    race against a dispatch still in flight -- skipping is correct
    behavior, not an optimization.

    Exceptions from dispatch_settlement are caught and logged here, NOT
    re-raised: by the time this function is even called, the webhook's own
    job -- correctly recording that a payment signal was received -- has
    already succeeded and committed. A downstream orchestration failure
    shouldn't turn into a 500 returned to the bank; retrying the webhook
    wouldn't even help, since the retry would immediately hit was_duplicate
    and skip dispatch again. What this DOES mean: a ledger row can be left
    genuinely stuck PENDING with funds already received and no automatic
    retry to un-stick it -- a real, human-actionable problem, which is
    exactly why this is logged loudly rather than swallowed silently.
    """
    if result.was_duplicate:
        return

    try:
        outcome = dispatch_settlement(db, result.ledger_entry)
    except Exception:
        logger.exception(
            "Unexpected failure during settlement dispatch for ledger_entry_id=%s -- funds received, "
            "settlement not completed, no automatic retry exists yet.",
            result.ledger_entry.id,
        )
        return

    if not outcome.dispatched:
        logger.warning(
            "Settlement not dispatched for ledger_entry_id=%s: %s", result.ledger_entry.id, outcome.reason
        )
    elif not outcome.success:
        logger.error(
            "Settlement dispatched but failed for ledger_entry_id=%s (%s rail): %s",
            result.ledger_entry.id,
            outcome.rail,
            outcome.reason,
        )