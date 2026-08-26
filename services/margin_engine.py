"""
Services: margin_engine.py
Calculates platform fees, taxes, and revenue splits securely.

Pure calculation module: no I/O, no DB session, no randomness. Same
gross_amount + same settings always produces the same TransactionSplit --
that determinism is what makes this function auditable and safe to unit
test against fixed expected values.
"""
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal

from core.config import settings

_LEDGER_QUANTUM = Decimal("0.0001")  # matches TransactionLedger's Numeric(18, 4) columns


def _round_to_ledger_precision(value: Decimal) -> Decimal:
    """Round to exactly 4 decimal places with ROUND_HALF_UP, matching Numeric(18, 4)."""
    return value.quantize(_LEDGER_QUANTUM, rounding=ROUND_HALF_UP)


def _resolve_percentage(custom_value: Decimal | None, fallback: Decimal, param_name: str) -> Decimal:
    """
    B2B custom-pricing override resolution: return custom_value if one was
    given, otherwise fall back to the global setting.

    A provided override is validated against the same (0, 1) exclusive
    bounds config.py's Field(gt=0, lt=1) enforces on the global settings --
    those constraints only run at app startup, on the settings object
    itself, so a per-call override bypasses them entirely unless this
    function re-checks. Never trust an override input to already be sane.
    fallback itself isn't re-validated here: it already passed this same
    check when settings was constructed.
    """
    if custom_value is None:
        return fallback
    if not (Decimal("0") < custom_value < Decimal("1")):
        raise ValueError(f"{param_name} must be between 0 and 1 (exclusive), got {custom_value}.")
    return custom_value


@dataclass(frozen=True, slots=True)
class TransactionSplit:
    """
    Everything calculate_transaction_splits produces for one transaction,
    matching TransactionLedger's Financials / Revenue Split columns.

    frozen=True: a computed financial result shouldn't be mutable after
    the fact -- if a value needs to change, recompute it, don't overwrite
    a field on an existing instance. slots=True: this gets instantiated
    once per transaction at platform scale, so skipping the per-instance
    __dict__ is a real memory saving, not a micro-optimization.
    """
    gross_amount: Decimal
    platform_fee_charged: Decimal
    tax_collected: Decimal
    net_platform_revenue: Decimal
    partner_bank_revenue: Decimal


def calculate_transaction_splits(
    gross_amount: Decimal,
    custom_fee_percentage: Decimal | None = None,
    custom_tax_percentage: Decimal | None = None,
    custom_split_platform: Decimal | None = None,
) -> TransactionSplit:
    """
    Takes the gross amount signaled by the bank and computes the exact fees,
    taxes, and splits, based on configured percentages -- or on B2B
    custom-pricing overrides when a caller supplies them.

    gross_amount is in the transaction's native currency (see
    ledger_model.py's architecture note) -- this function never touches
    base_usd_exchange_rate; fees/tax/split are always native-currency math.

    B2B CUSTOM PRICING: custom_fee_percentage, custom_tax_percentage, and
    custom_split_platform each independently override the matching global
    setting (PLATFORM_FEE_PERCENTAGE, TAX_PERCENTAGE, NET_SPLIT_PLATFORM)
    when provided; any left as None fall back to settings -- a caller can
    override just one of the three and get the global value for the other
    two. Existing call sites (e.g. bank_webhook.py) that only ever pass
    gross_amount are unaffected: all three default to None, which is
    exactly today's global-settings-only behavior. There's no
    custom_split_partner parameter -- see THE LEDGER CHECK below for why
    the partner side was never independently configurable in the first
    place, custom pricing or not.

    Every override is validated against the same (0, 1) exclusive bounds
    config.py's Field(gt=0, lt=1) enforces on the corresponding global
    setting (see _resolve_percentage) -- those Pydantic constraints only
    run once, at settings construction; a raw Decimal handed to this
    function bypasses them unless this function checks again itself.

    All arithmetic is Decimal, never float, whether the percentages come
    from settings or from a custom override. Each multiplication is
    rounded to 4 decimal places with ROUND_HALF_UP immediately after
    computing it, matching Numeric(18, 4) -- values are never left at raw,
    unrounded precision and rounded "later" somewhere else.

    THE LEDGER CHECK: net_platform_revenue + partner_bank_revenue must
    exactly equal platform_fee_charged - tax_collected (this is also
    enforced at the DB layer by TransactionLedger's
    ck_ledger_revenue_split_equals_net_fee CHECK constraint -- this
    function is what has to actually uphold it before a row is ever
    built). net_platform_revenue is rounded from the resolved platform
    split, and partner_bank_revenue is derived as net_fee minus that --
    NOT independently rounded from a partner-side percentage (which is
    exactly why there's no custom_split_partner parameter: there's nothing
    for it to independently control). Rounding both sides independently
    can lose or gain 0.0001: e.g. a net_fee of 10.0001 split 50/50 rounds
    each half to 5.0001 under ROUND_HALF_UP, summing to 10.0002. This
    platform's default split happens to be 60/40, which avoids that
    specific case mathematically -- but a B2B custom_split_platform can be
    any ratio in (0, 1), and most ratios don't share that same lucky
    property. Derive-the-remainder is correct for every ratio this
    function could ever be handed, default or custom, so it doesn't matter
    whether today's default happens to be rounding-safe.
    """
    if gross_amount <= Decimal("0"):
        raise ValueError(f"gross_amount must be positive, got {gross_amount}.")

    fee_percentage = _resolve_percentage(custom_fee_percentage, settings.PLATFORM_FEE_PERCENTAGE, "custom_fee_percentage")
    tax_percentage = _resolve_percentage(custom_tax_percentage, settings.TAX_PERCENTAGE, "custom_tax_percentage")
    split_platform = _resolve_percentage(custom_split_platform, settings.NET_SPLIT_PLATFORM, "custom_split_platform")

    platform_fee_charged = _round_to_ledger_precision(gross_amount * fee_percentage)
    tax_collected = _round_to_ledger_precision(platform_fee_charged * tax_percentage)

    # Exact, not rounded again: both operands above are already quantized
    # to 4dp, and Decimal subtraction of two 4dp values can't introduce
    # additional precision -- there's nothing left to round here.
    net_fee = platform_fee_charged - tax_collected

    net_platform_revenue = _round_to_ledger_precision(net_fee * split_platform)
    partner_bank_revenue = net_fee - net_platform_revenue

    # Self-consistency check, not input validation -- given the derivation
    # above, this is mathematically guaranteed to hold. A deliberate `if
    # ...: raise` rather than `assert`, since assert statements are
    # stripped out entirely when Python runs with -O, which would silently
    # disable this in some production configurations. If this ever fires,
    # it means a future edit broke the remainder-derivation above, not
    # that the input data was bad.
    if net_platform_revenue + partner_bank_revenue != net_fee:
        raise RuntimeError(
            "Revenue split invariant broken: "
            f"{net_platform_revenue} + {partner_bank_revenue} != {net_fee}. "
            "This should be mathematically impossible given partner_bank_revenue "
            "is derived as net_fee's remainder -- check for an edit that "
            "independently rounded both sides instead."
        )

    return TransactionSplit(
        gross_amount=gross_amount,
        platform_fee_charged=platform_fee_charged,
        tax_collected=tax_collected,
        net_platform_revenue=net_platform_revenue,
        partner_bank_revenue=partner_bank_revenue,
    )


# ----------------------------------------------------------------------
# calculate_wholesale_margin -- the independent-rate variant. Deliberately
# a separate function, not a mode flag on calculate_transaction_splits
# above: the two aren't the same formula with different numbers, they're
# structurally different calculations (see the docstring below), and nothing
# above this line is touched by what follows -- calculate_transaction_splits,
# TransactionSplit, and both existing private helpers are byte-for-byte
# unchanged, kept intact for future B2B revenue-share integrations where
# that proportional model is the actually correct one.
# ----------------------------------------------------------------------
def _validate_rate(value: Decimal, param_name: str) -> Decimal:
    """
    (0, 1) exclusive bounds check for a standalone required rate --
    deliberately a NEW, separate helper rather than a change to
    _resolve_percentage above, which stays untouched. Duplicates two
    lines of logic rather than share it, which is a fine trade for
    leaving the existing function's helpers exactly as they were.
    """
    if not (Decimal("0") < value < Decimal("1")):
        raise ValueError(f"{param_name} must be between 0 and 1 (exclusive), got {value}.")
    return value


class UnsustainablePricingError(ValueError):
    """
    Raised when platform_retail_rate is priced too low relative to
    bank_wholesale_rate for platform_margin to be non-negative -- JvX
    would be paying the bank more than it collected from the customer on
    this transaction. A ValueError subclass, not a bare Exception: this is
    fundamentally the same class of problem as gross_amount <= 0 or a
    rate outside (0, 1) above -- the inputs handed to this function don't
    make sense together -- so it's catchable specifically
    (UnsustainablePricingError) or generically (ValueError) depending on
    what a caller needs.
    """


@dataclass(frozen=True, slots=True)
class WholesaleMarginResult:
    """
    Everything calculate_wholesale_margin produces for one transaction.
    Same frozen=True / slots=True reasoning as TransactionSplit above --
    a computed financial result shouldn't be mutable, and this is
    instantiated once per transaction at platform scale.
    """
    gross_amount: Decimal
    bank_owed: Decimal
    customer_charged: Decimal
    tax_collected: Decimal
    platform_margin: Decimal


def calculate_wholesale_margin(
    gross_amount: Decimal,
    bank_wholesale_rate: Decimal,
    platform_retail_rate: Decimal,
    custom_tax_percentage: Decimal | None = None,
) -> WholesaleMarginResult:
    """
    The independent-rate wholesale model: the bank is owed a fixed rate on
    gross_amount regardless of what JvX charges the customer, and JvX
    charges the customer its own independently-set retail rate -- two
    unrelated numbers, not one number split proportionally.

    THE BUG THIS STRUCTURALLY PREVENTS: in calculate_transaction_splits
    above, partner_bank_revenue is derived from net_fee, which is itself
    derived from what the platform charges the customer
    (platform_fee_charged) -- so the bank's revenue is mathematically
    tied to the platform's retail pricing decision. Run a promotional
    discount, and the bank's cut shrinks right along with it, silently,
    with no error, because the formula makes that "correct" behavior by
    construction. That's the right shape for a genuine revenue-share
    arrangement (both sides jointly price and split what comes in) but
    the wrong shape for a wholesale relationship, where the bank wants
    its fixed rate independent of the platform's retail pricing entirely.

    WHY bank_owed IS COMPUTED FROM gross_amount, NOT FROM
    customer_charged: this is the one design choice that actually fixes
    the bug above, not just relabels it. If bank_owed were derived from
    customer_charged (e.g. as a percentage of it), it would still move
    every time platform_retail_rate moves -- the exact coupling being
    eliminated here. Computing bank_owed directly from gross_amount, with
    its own independent rate, is what makes it genuinely immune to
    whatever JvX decides to charge the customer. A bank's wholesale quote
    is priced against the value of money it's actually moving/converting
    -- the transaction's gross value -- not against the platform's own
    markup decision on top of it.

    WHY tax_collected IS COMPUTED ON customer_charged, NOT ON gross_amount
    OR bank_owed: this is GST on JvX's own fee to its own customer for
    JvX's own taxable supply of service -- the bank's wholesale amount is
    the bank's separate taxable transaction, handled in the bank's own
    books, not something this function has any business computing tax on.

    WHY platform_margin IS DERIVED AS A REMAINDER, NOT INDEPENDENTLY
    ROUNDED: same drift-avoidance discipline as
    calculate_transaction_splits' partner_bank_revenue, just applied to a
    different pair. platform_margin + bank_owed must exactly equal
    net_after_tax -- rounding both sides independently from the same base
    can lose or gain 0.0001, exactly as documented above for the
    proportional-split case. bank_owed is the one computed directly and
    rounded on its own, because it's an externally-fixed amount JvX has
    zero discretion to round differently than what's actually owed to the
    bank; platform_margin is whatever's left after that, which guarantees
    the two sum exactly with no drift, for any pair of rates this
    function is ever handed.

    WHY A NEGATIVE platform_margin RAISES INSTEAD OF RETURNING A NEGATIVE
    NUMBER: calculate_transaction_splits' partner_bank_revenue is
    mathematically incapable of exceeding net_fee, by construction --
    it's derived as net_fee's own remainder, so there's no formula that
    could make it larger than the whole it's a piece of. Deriving
    bank_owed independently of what the customer pays reintroduces
    exactly the possibility that structural guarantee eliminated: nothing
    stops bank_wholesale_rate from exceeding platform_retail_rate, which
    would mean JvX owes the bank more than it collected from the customer
    on this transaction. That has to be checked explicitly here, and
    raising loudly -- rather than silently returning a negative
    platform_margin that might not surface until a financial review much
    later -- is the same "fail loud, not silent" discipline as the
    RuntimeError (not a bare assert) in calculate_transaction_splits
    above.

    bank_wholesale_rate and platform_retail_rate are REQUIRED, with no
    settings fallback -- deliberately, unlike calculate_transaction_splits'
    custom_* parameters. Those values don't exist yet: no bank has quoted
    a wholesale rate, so there is no real value a settings default could
    hold today that wouldn't risk being mistaken for a real one later.
    custom_tax_percentage still falls back to settings.TAX_PERCENTAGE,
    since GST is a known, stable regulatory constant today, unlike the
    bank/retail rates. Wiring bank_wholesale_rate/platform_retail_rate
    into config.py as real settings, once real negotiated numbers exist,
    is a natural next step -- not done here since those numbers don't
    exist yet and adding required, no-default settings fields for them
    now would just break app startup until the .env is also updated.
    """
    if gross_amount <= Decimal("0"):
        raise ValueError(f"gross_amount must be positive, got {gross_amount}.")

    _validate_rate(bank_wholesale_rate, "bank_wholesale_rate")
    _validate_rate(platform_retail_rate, "platform_retail_rate")
    tax_percentage = _resolve_percentage(custom_tax_percentage, settings.TAX_PERCENTAGE, "custom_tax_percentage")

    bank_owed = _round_to_ledger_precision(gross_amount * bank_wholesale_rate)
    customer_charged = _round_to_ledger_precision(gross_amount * platform_retail_rate)
    tax_collected = _round_to_ledger_precision(customer_charged * tax_percentage)

    # Exact, not rounded again -- same reasoning as calculate_transaction_splits'
    # net_fee: both operands are already quantized to 4dp, so Decimal
    # subtraction can't introduce additional precision needing a further round.
    net_after_tax = customer_charged - tax_collected

    # DERIVED, not independently rounded -- see the docstring above for why
    # this is the piece that actually prevents 0.0001 drift between
    # platform_margin and bank_owed.
    platform_margin = net_after_tax - bank_owed

    if platform_margin < Decimal("0"):
        raise UnsustainablePricingError(
            f"platform_retail_rate ({platform_retail_rate}) is priced too low relative to "
            f"bank_wholesale_rate ({bank_wholesale_rate}) on gross_amount={gross_amount}: "
            f"after collecting {customer_charged} and paying {tax_collected} tax, {net_after_tax} "
            f"remains, which doesn't cover the {bank_owed} owed to the bank. platform_margin "
            f"would be {platform_margin} -- JvX would be paying the bank more than it collected "
            "from the customer on this transaction."
        )

    return WholesaleMarginResult(
        gross_amount=gross_amount,
        bank_owed=bank_owed,
        customer_charged=customer_charged,
        tax_collected=tax_collected,
        platform_margin=platform_margin,
    )