"""
Models: ledger_model.py
Financial ledger representing all processed transactions, fee distributions, 
and RBI/FEMA compliance tracking (E-FIRA).

ARCHITECTURE NOTE: this table is a signal/tech-layer record of what a
partner bank told us about a transaction issuing e-Rupee, not a currency-
converted set of platform books. gross_amount and every fee/tax/split
column are recorded in the currency the bank actually signaled
(source_currency) -- there is no premature conversion to USD anywhere in
this row. base_usd_exchange_rate exists solely so a dashboard can compute
a USD-equivalent total on demand; it is never used to derive
platform_fee_charged, tax_collected, or the revenue split below.
"""

import datetime
import decimal

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Numeric,
    String,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base


class TransactionLedger(Base):
    __tablename__ = "transaction_ledger"

    # ------------------------------------------------------------------
    # Transaction Identity
    # ------------------------------------------------------------------
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    transaction_reference: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    # Idempotency anchor for the payout pipeline: bank webhook handlers
    # enforce an x-idempotency-key header and rely on this unique=True
    # constraint (caught as an IntegrityError on retry) to make
    # double-processing the same bank event impossible at the DB layer,
    # not just in application logic.

    user_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("users.id", ondelete="RESTRICT"),
        index=True,
    )
    # ondelete="RESTRICT" made explicit (Postgres's default NO ACTION
    # already behaves this way for a non-deferred FK): a user row can never
    # be deleted while ledger rows reference it. Financial records must
    # never disappear via cascade -- an audit requirement, and almost
    # certainly an RBI/FEMA recordkeeping one given this table's purpose.

    # ------------------------------------------------------------------
    # Status (fraud / failed-transaction tracking)
    # ------------------------------------------------------------------
    status: Mapped[str] = mapped_column(String(20), server_default=text("'PENDING'"), index=True)
    # PENDING -> COMPLETED / FAILED / REJECTED, enforced by the CHECK
    # constraint below. FAILED and REJECTED rows are never deleted -- they
    # are the audit trail for fraud/dispute review, so the operation this
    # codebase should never issue is a DELETE against this table for any
    # non-PENDING row. That's really an operational guarantee (the app's DB
    # role should have DELETE revoked on this table in production, or a
    # BEFORE DELETE trigger blocking it) more than something this model
    # file alone can enforce -- flagging it here since it's the kind of
    # rule that's easy to lose track of once several services touch this
    # table. Happy to draft that trigger/permissions change separately if
    # useful.
    #
    # The revenue dashboard sums net_platform_revenue / partner_bank_revenue
    # filtered to status = 'COMPLETED' only -- see the composite index below.

    # ------------------------------------------------------------------
    # Financials -- all in source_currency, no premature USD conversion
    # ------------------------------------------------------------------
    # Mapped[decimal.Decimal] below, not Mapped[float]. SQLAlchemy's Numeric
    # type already returns decimal.Decimal at runtime (asdecimal=True by
    # default) -- annotating these as float would be a lie the type checker
    # believes, and it's exactly the mismatch that lets a stray float
    # assignment slip into a money field, reintroducing the salami-slicing
    # risk Numeric(18, 4) exists to eliminate.
    gross_amount: Mapped[decimal.Decimal] = mapped_column(Numeric(18, 4))
    # Exact amount in source_currency, as signaled by the partner bank --
    # NOT converted to USD. (Previously gross_amount_usd; renamed because
    # this row no longer represents a USD-settled amount.)

    source_currency: Mapped[str] = mapped_column(String(3))
    # ISO 4217 alpha-3 code (e.g. "GBP", "EUR", "AED") for the currency
    # every monetary column in this row is denominated in -- gross_amount,
    # platform_fee_charged, tax_collected, net_platform_revenue, and
    # partner_bank_revenue are ALL in this currency, not USD.

    base_usd_exchange_rate: Mapped[decimal.Decimal] = mapped_column(Numeric(18, 6))
    # USD per 1 unit of source_currency, stored ONLY so a dashboard can
    # compute a USD-equivalent total on demand
    # (gross_amount * base_usd_exchange_rate). NOT used anywhere in this
    # row's own fee/tax/split arithmetic -- fees are deducted from the
    # native-currency amount, never from a USD conversion of it.
    # (Previously exchange_rate; renamed to make that reporting-only role
    # explicit rather than implying it feeds settlement math.)

    platform_fee_charged: Mapped[decimal.Decimal] = mapped_column(Numeric(18, 4))
    tax_collected: Mapped[decimal.Decimal] = mapped_column(Numeric(18, 4))
    # Both in source_currency. tax_collected is the flat 18% tax on
    # platform_fee_charged (not on gross_amount) -- see Revenue Split below.

    # ------------------------------------------------------------------
    # Revenue Split (Net Profit Split) -- in source_currency
    # ------------------------------------------------------------------
    # Formula, applied once at transaction time in the service layer
    # (services/margin_engine.py) using the locked 60/40 constants from
    # config.py -- NOT recomputed here or anywhere else on read, and NOT
    # derived from any USD conversion:
    #
    #   net_fee              = platform_fee_charged - tax_collected
    #   net_platform_revenue = net_fee * settings.PLATFORM_SPLIT     (0.60)
    #   partner_bank_revenue = net_fee * settings.PARTNER_BANK_SPLIT (0.40)
    #
    # Worked example (currency-agnostic, values in source_currency):
    #   fee=100.0000, tax=18.0000 -> net_fee=82.0000
    #   -> platform=49.2000, partner=32.8000
    #
    # These two columns are STORED, not derived on read, on purpose: they
    # record the split actually paid out for THIS transaction, in the
    # currency it was actually paid out in. If config.py's percentages
    # change next quarter, every past ledger row must keep showing the
    # split that was in effect when the money moved -- recomputing from
    # current config on read would silently rewrite financial history. The
    # CheckConstraint below only guards internal consistency (the two parts
    # add up to the net fee); it deliberately does not pin the 60/40 ratio
    # itself, since that's config's job, not the schema's.
    #
    # Rounding note for whoever implements margin_engine.py: derive one
    # side as the remainder of the other (e.g. platform = round(net_fee *
    # Decimal("0.60"), 4); partner = net_fee - platform) rather than
    # independently rounding both percentages -- two independently-rounded
    # Decimals can miss the exact net_fee total by 0.0001 and trip the
    # constraint below.
    net_platform_revenue: Mapped[decimal.Decimal] = mapped_column(Numeric(18, 4))
    partner_bank_revenue: Mapped[decimal.Decimal] = mapped_column(Numeric(18, 4))

    # ------------------------------------------------------------------
    # Compliance
    # ------------------------------------------------------------------
    compliance_purpose_code: Mapped[str] = mapped_column(String(20))
    # RBI/FEMA purpose code for the cross-border remittance. Not indexed
    # yet -- add a (compliance_purpose_code, created_at) composite if/when
    # regulatory reporting queries actually filter on it; every extra index
    # is extra write cost on a table built to absorb high-frequency inserts,
    # so it's not added speculatively.

    fira_certificate_id: Mapped[str | None] = mapped_column(String(100))
    # E-FIRA (Foreign Inward Remittance Certificate) reference, issued by
    # the partner bank after settlement -- null until completed_at is set.

    cbdc_reference_number: Mapped[str | None] = mapped_column(String(100), unique=True)
    # The OTHER gap flagged in e_rupee_mint.py's docstring alongside
    # error_reason -- that file computes this on a successful mint
    # (MintResult.cbdc_reference_number) but had nowhere to persist it
    # until now. unique=True wasn't explicitly requested, only "String,
    # nullable" -- added since each successful mint should correspond to
    # exactly one CBDC network reference, and two ledger rows sharing one
    # would indicate a duplicate-mint bug worth surfacing loudly (an
    # IntegrityError) rather than silently allowing. Flagging the
    # deviation from the literal spec rather than adding it silently.
    #
    # NOTE: this column existed for a while before e_rupee_mint.py's
    # mint_digital_currency actually wrote to it -- the function computed
    # outcome.cbdc_reference_number and returned it in MintResult, but
    # never assigned it to the locked ledger row. Fixed alongside this
    # column's FIAT counterpart below, since building the FIAT settlement
    # path properly required noticing the CBDC path wasn't actually
    # complete either.

    fiat_settlement_utr: Mapped[str | None] = mapped_column(String(100), unique=True)
    # FIAT-rail counterpart to cbdc_reference_number above, same shape and
    # same reasoning: UTR (Unique Transaction Reference) is the standard
    # identifier for a completed NEFT/RTGS/IMPS transfer in India.
    # unique=True for the identical reason as cbdc_reference_number --
    # two ledger rows sharing one UTR would indicate a duplicate-transfer
    # bug worth surfacing loudly, not silently allowing.

    error_reason: Mapped[str | None] = mapped_column(String(500))
    # Human-readable reason for a FAILED status, set by whatever service
    # transitions the row there -- now genuinely shared by BOTH rails
    # (services/e_rupee_mint.py's mock CBDC call and services/
    # fiat_settlement.py's mock bank transfer), not just the CBDC path
    # this comment originally described. Also read back by services/
    # ai_support.py for support context. Null for PENDING/COMPLETED/REJECTED.

    # ------------------------------------------------------------------
    # Timestamps
    # ------------------------------------------------------------------
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    completed_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))
    # Distinct from status: completed_at is a timestamp, status is the
    # lifecycle state. Whether completed_at should also get set for FAILED
    # / REJECTED rows (i.e. "time it reached a terminal state" rather than
    # strictly "time it succeeded") isn't pinned down by what's been
    # specified so far -- worth deciding explicitly, since it affects any
    # reconciliation query that reads this column.

    # ------------------------------------------------------------------
    # Indexing & integrity strategy (high-frequency transaction table)
    # ------------------------------------------------------------------
    __table_args__ = (
        CheckConstraint(
            "status IN ('PENDING', 'COMPLETED', 'FAILED', 'REJECTED')",
            name="ck_ledger_status_valid",
        ),

        # Ledger accounting invariant, enforced at the DB layer so a bug in
        # application code can never silently persist a split that doesn't
        # add up to the net fee. Numeric/Decimal arithmetic is exact here
        # (no float rounding to worry about), so this is a hard equality,
        # not a tolerance check. Holds regardless of source_currency, since
        # all four values in it are already in the same currency.
        CheckConstraint(
            "net_platform_revenue + partner_bank_revenue = platform_fee_charged - tax_collected",
            name="ck_ledger_revenue_split_equals_net_fee",
        ),

        # An FX rate of zero or negative is never valid -- guards against a
        # bad upstream rate feed writing a nonsensical conversion.
        CheckConstraint("base_usd_exchange_rate > 0", name="ck_ledger_exchange_rate_positive"),

        # "This user's transaction history / statement" is the dominant
        # read pattern on this table. Composite index serves that directly,
        # and still covers user_id-only lookups via the B-tree leftmost-
        # prefix rule -- the standalone index=True above isn't doing
        # separate work once this exists, kept as-is per the zero-change
        # rule on what was already there.
        Index("ix_ledger_user_id_created_at", "user_id", "created_at"),

        # Revenue dashboard's exact query shape: SUM(...) WHERE status =
        # 'COMPLETED', almost certainly scoped to a date range too (a
        # month's revenue, not all-time). status alone is low-selectivity
        # once COMPLETED rows are the vast majority of the table, so the
        # win here is the composite with created_at, not status in
        # isolation -- Postgres can jump straight to the requested date
        # range within COMPLETED rows instead of scanning everything.
        Index("ix_ledger_status_created", "status", "created_at"),

        # Partial index: only rows still awaiting settlement. Reconciliation
        # / stuck-transaction jobs scan for old pending rows constantly, and
        # a partial index stays a tiny fraction of total table size forever
        # (PENDING is transient; COMPLETED/FAILED/REJECTED accumulate) even
        # as the base table grows into the billions of rows this platform
        # is sized for. Uses status now rather than the old completed_at IS
        # NULL check, since status distinguishes "still pending" from
        # "reached a terminal FAILED/REJECTED state" -- completed_at IS
        # NULL doesn't. Postgres-specific (postgresql_where); compiles to a
        # regular index on other dialects.
        Index(
            "ix_ledger_pending_status",
            "created_at",
            postgresql_where=text("status = 'PENDING'"),
        ),
    )