"""
Models: declaration_model.py

Two things the customer tells the bank about money, before or instead of
an invoice.

PRE_PAYMENT — filed before the money arrives. "A US client is sending me
$2,000 next week, here is the invoice and the purpose code." Today the
money lands first and the bank starts asking questions afterwards. This
inverts that order so the bank already has context when the credit hits.

SELF_DECLARATION — filed where no formal invoice exists at all. A
freelancer paid via a platform, a royalty, a recurring retainer with no
per-payment invoice. FEMA still requires the purpose to be stated; this
is how it gets stated.

WHAT THIS DOCUMENT IS NOT: it is not a FIRA, not a bank certificate, and
not evidence of anything the bank has confirmed. It is the customer's own
statement, recorded and fingerprinted. The `disclaimer` property below
exists so that no surface in this system can render one without saying so.
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
    Text,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base

DECLARATION_KINDS = ("PRE_PAYMENT", "SELF_DECLARATION")

# MATCHED and EXPIRED apply only to PRE_PAYMENT. A SELF_DECLARATION is
# filed about money that already arrived, so it goes straight to FILED and
# stays there.
DECLARATION_STATUSES = ("FILED", "MATCHED", "EXPIRED", "WITHDRAWN")


class Declaration(Base):
    """
    A customer's stated expectation or explanation for an inbound payment.

    content_fingerprint carries the same idea as the invoice dual-hash,
    adapted to a record with no file: a SHA-256 over the normalised
    business fields. Two declarations claiming the same amount, from the
    same payer, on the same date, for the same user collide on it. That
    catches an accidental double-file, and it catches a customer filing
    twice to claim one payment against two different purpose codes.
    """

    __tablename__ = "declarations"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    # Human-readable, shown to the customer and quotable to the bank.
    # Format: JVX-PD-A3F2C1D4 (pre-payment) or JVX-SD-A3F2C1D4 (self).
    reference: Mapped[str] = mapped_column(String(32), unique=True, index=True)

    user_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("users.id", ondelete="RESTRICT"),
        index=True,
    )

    kind: Mapped[str] = mapped_column(String(20), index=True)
    status: Mapped[str] = mapped_column(
        String(20), server_default=text("'FILED'"), index=True
    )

    expected_amount: Mapped[decimal.Decimal] = mapped_column(Numeric(18, 4))
    currency: Mapped[str] = mapped_column(String(3))

    payer_name: Mapped[str] = mapped_column(String(255))
    payer_country: Mapped[str | None] = mapped_column(String(2))

    purpose_code: Mapped[str] = mapped_column(String(20), index=True)
    description: Mapped[str] = mapped_column(Text)

    # PRE_PAYMENT only. A declaration filed for money that never arrives
    # cannot sit open forever, or the matching window grows until it
    # produces false matches against unrelated later payments.
    expected_by: Mapped[datetime.date | None] = mapped_column()

    # Optional link to an already-uploaded invoice. Nullable by design:
    # SELF_DECLARATION exists precisely because there is no invoice, and a
    # pre-declaration may be filed before the customer has raised one.
    invoice_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("commercial_invoices.id", ondelete="SET NULL"),
        index=True,
    )

    # Set when an inbound payment is matched to this declaration. The
    # reverse side (InboundPayment.declaration_id) is what the dashboard
    # reads; this side is what the matcher writes.
    matched_payment_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("inbound_payments.id", ondelete="SET NULL"),
    )
    matched_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))

    content_fingerprint: Mapped[str] = mapped_column(String(64), unique=True, index=True)

    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        CheckConstraint(
            "kind IN ('PRE_PAYMENT', 'SELF_DECLARATION')",
            name="ck_declarations_kind",
        ),
        CheckConstraint(
            "status IN ('FILED', 'MATCHED', 'EXPIRED', 'WITHDRAWN')",
            name="ck_declarations_status",
        ),
        CheckConstraint("expected_amount > 0", name="ck_declarations_amount_positive"),
        # A pre-declaration without a date would never expire. Enforced in
        # the database rather than only in the route, because a second
        # caller written later will not remember the rule.
        CheckConstraint(
            "kind <> 'PRE_PAYMENT' OR expected_by IS NOT NULL",
            name="ck_declarations_prepayment_needs_date",
        ),
        # The matcher's query: this user's open pre-declarations.
        Index("ix_declarations_user_status_kind", "user_id", "status", "kind"),
    )

    @property
    def disclaimer(self) -> str:
        """
        Must appear on every rendered self-declaration receipt.

        A document that looks official but is not is worse than no
        document. This sentence is the difference between a useful record
        and a compliance problem for the bank that accepted it.
        """
        return (
            "This is a self-declaration by the account holder. "
            "It is not a bank-issued certificate and has not been verified "
            "or endorsed by any bank or regulatory authority."
        )

    def __repr__(self) -> str:
        return (
            f"<Declaration {self.reference!r} kind={self.kind} "
            f"{self.expected_amount} {self.currency} status={self.status}>"
        )