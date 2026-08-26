"""
Models: cbdc_model.py
Scaffolding for a future CBDC-to-CBDC cross-border corridor -- CbdcWallet
(inbound receiving identifiers, one per user per CBDC type) and
AtomicFxSwap (two-leg atomic settlement between two such wallets).

STRUCTURALLY SEPARATE FROM OUTBOUND PAYOUT, ON PURPOSE: User.
digital_wallet_address / preferred_payout_route / local_bank_account_number
(models/user_model.py) are the OUTBOUND side -- where THIS platform sends
funds TO a user as a payout choice. CbdcWallet here is the INBOUND side --
a corridor-facing receiving address, the CBDC-rail counterpart to
VirtualAccount (models/virtual_account_model.py), which plays the same
role for traditional banking rails. Opposite directions of money flow,
kept apart the same way VirtualAccount and the outbound payout fields
already are today -- this file doesn't touch, import, or reference any
of those four User columns, api/payout_routes.py, or services/
e_rupee_mint.py, and shouldn't ever need to for what it represents.

NO REAL CORRIDOR EXISTS YET: unlike virtual_account_model.py (Decentro is
real, if unauthenticated), there is no bank, corridor, or DLT node this
scaffolding could actually be tested against. Every field below reflects
best-available reasoning about what an atomic CBDC swap needs to record,
not a confirmed contract from any real integration -- see services/
cbdc_corridor_client.py's module docstring for the fuller version of this
caveat.
"""
import datetime
from decimal import Decimal

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Numeric,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base


class CbdcWallet(Base):
    """
    An inbound, corridor-facing CBDC receiving address -- the DLT-native
    counterpart to VirtualAccount. One row per (user, cbdc_type): a user
    can hold multiple different CBDC wallets (e.g. both a Digital AED and
    a Digital SGD wallet) but not two wallets for the same CBDC type.
    """

    __tablename__ = "cbdc_wallets"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="RESTRICT"), index=True)
    # RESTRICT, matching VirtualAccount.user_id's reasoning exactly: a
    # wallet having ever existed is an audit-relevant fact in its own
    # right, so a User row can't be deleted out from under one.

    cbdc_type: Mapped[str] = mapped_column(String(20), index=True)
    # NOT an ISO 4217 currency code, deliberately -- these are specific
    # sovereign CBDC issuances, not traditional currencies. "E_INR",
    # "DIGITAL_AED", "DIGITAL_SGD" are this scaffolding's own naming
    # choice, not a standard -- no ISO-style registry for CBDC
    # identifiers exists the way ISO 4217 does for currencies. Whatever
    # naming a real corridor integration eventually uses should replace
    # this rather than be forced to match it.

    wallet_address: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    # Width is deliberately generous, not computed the way VirtualAccount.
    # account_number's width was: DLT address formats vary widely by
    # platform (Ethereum-style addresses run ~42 characters; a
    # permissioned/consortium chain like mBridge's own could use something
    # entirely different), and no real corridor exists yet to confirm
    # against. 255 is headroom against genuine uncertainty, not a
    # precise bound. NOT EncryptedString -- same reasoning as VirtualAccount.
    # account_number: this is a provider/corridor-issued identifier, not a
    # government ID: the categories FLE is applied to elsewhere in this
    # codebase (PAN, GST, IEC, bank account numbers).

    corridor_provider_name: Mapped[str] = mapped_column(String(50))
    # Which bank/bridge this wallet was actually provisioned through --
    # "mock" during scaffolding, a real bank/corridor name once one
    # exists. Same reasoning as VirtualAccount.provider_name: meaningful
    # from day one rather than added retroactively once more than one
    # real corridor exists.

    status: Mapped[str] = mapped_column(String(20), server_default=text("'PENDING'"))
    # PENDING / ACTIVE / FAILED -- identical semantics to VirtualAccount.
    # status, same lifecycle shape for the same kind of thing (a
    # provisioned receiving identifier), just on a different rail.

    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        CheckConstraint("status IN ('PENDING', 'ACTIVE', 'FAILED')", name="ck_cbdc_wallets_status"),
        UniqueConstraint("user_id", "cbdc_type", name="uq_cbdc_wallets_user_cbdc_type"),
        Index("ix_cbdc_wallets_user_id_status", "user_id", "status"),
    )


class AtomicFxSwap(Base):
    """
    A two-leg atomic settlement between two CbdcWallets -- e.g. an
    inbound Digital AED receipt converted to e-INR. "Atomic" is load-
    bearing here, not decorative: both legs settle together or neither
    does, which is why status has no partial/in-between state below.

    KEPT SEPARATE FROM TransactionLedger, DELIBERATELY: that table is the
    most tested, most proven part of this entire codebase (idempotent,
    exhaustively verified revenue-split math) and represents a single-
    currency, single-leg signal. Forcing a two-leg, dual-currency swap
    into that shape would mean touching the one piece of this system with
    the least room for error, for a feature with no real corridor to test
    it against yet. Instead, this table stands alone and OPTIONALLY links
    to up to two TransactionLedger rows (one per leg) for reporting --
    TransactionLedger's own columns, constraints, and logic are entirely
    untouched by this file.
    """

    __tablename__ = "atomic_fx_swaps"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    source_wallet_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("cbdc_wallets.id", ondelete="RESTRICT"), index=True)
    source_cbdc_type: Mapped[str] = mapped_column(String(20))
    # Denormalized from the wallet at swap-creation time, not read via a
    # join -- same discipline TransactionLedger.source_currency already
    # follows: an audit row should reflect what was true at the moment of
    # the transaction, not depend on foreign state that could (even if it
    # shouldn't) change later.
    source_amount: Mapped[Decimal] = mapped_column(Numeric(18, 4))

    destination_wallet_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("cbdc_wallets.id", ondelete="RESTRICT"), index=True
    )
    destination_cbdc_type: Mapped[str] = mapped_column(String(20))
    destination_amount: Mapped[Decimal] = mapped_column(Numeric(18, 4))

    fx_rate_applied: Mapped[Decimal] = mapped_column(Numeric(18, 6))
    # Numeric(18, 6), not (18, 4) -- matching TransactionLedger.
    # base_usd_exchange_rate's precision exactly, for the same reason: an
    # exchange rate needs finer resolution than a money amount does.

    status: Mapped[str] = mapped_column(String(20), server_default=text("'PENDING'"))
    # PENDING -> SETTLED or FAILED. No partial state on purpose -- an
    # atomic swap that's "half done" isn't a valid state to represent,
    # it's a contradiction of what atomic means. If a real corridor
    # integration ever needs to model an in-flight, not-yet-confirmed
    # state, that's a new value added deliberately later, not implied by
    # this scaffolding.

    linked_source_ledger_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("transaction_ledger.id", ondelete="SET NULL"), index=True
    )
    linked_destination_ledger_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("transaction_ledger.id", ondelete="SET NULL"), index=True
    )
    # Both optional, both SET NULL -- mirroring CommercialInvoice.
    # related_transaction_id's exact reasoning: nothing in this codebase
    # sets these automatically yet (there is no real corridor to produce
    # ledger rows from), and if a linked ledger row were ever deleted,
    # this swap record shouldn't disappear with it, just lose the
    # reference.

    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    settled_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint("status IN ('PENDING', 'SETTLED', 'FAILED')", name="ck_atomic_fx_swaps_status"),
        CheckConstraint("source_amount > 0", name="ck_atomic_fx_swaps_source_amount_positive"),
        CheckConstraint("destination_amount > 0", name="ck_atomic_fx_swaps_destination_amount_positive"),
        CheckConstraint("fx_rate_applied > 0", name="ck_atomic_fx_swaps_rate_positive"),
        CheckConstraint("source_wallet_id != destination_wallet_id", name="ck_atomic_fx_swaps_distinct_wallets"),
        # A swap resolving to itself is a data error, not a valid
        # (if unusual) transaction -- same class of invariant as
        # TransactionLedger's own revenue-split equality constraint:
        # enforced at the database level, not just trusted to
        # application code.
        Index("ix_atomic_fx_swaps_status_created", "status", "created_at"),
    )