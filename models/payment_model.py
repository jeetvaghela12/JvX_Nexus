"""
Models: payment_model.py

A record of what the bank told us about an inbound cross-border payment.

This is NOT a ledger in the accounting sense, and the rename away from
"TransactionLedger" is deliberate. JvX Nexus does not hold funds, does not
move them, and does not compute a revenue split. The bank receives the
money, converts it, settles it to its own customer, and reports the
outcome to us. This table stores that report so the customer's dashboard
and the bank's compliance queue have something to read.

Every monetary column is Numeric, never Float. Binary floating point
cannot represent 0.1 exactly, and a cent of drift per row compounds into
a reconciliation dispute nobody can trace.
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

# The lifecycle as the bank reports it. We observe these; we never advance
# a payment between them ourselves.
#   RECEIVED  - funds landed in the virtual account
#   CREDITED  - bank settled to the customer's account
#   RETURNED  - bank sent the funds back
#   ON_HOLD   - bank is holding pending a query or document
PAYMENT_STATUSES = ("RECEIVED", "CREDITED", "RETURNED", "ON_HOLD")


class InboundPayment(Base):
    """
    One inbound cross-border payment, as reported by the partner bank.

    bank_reference is the bank's own identifier for this payment and is
    unique. It is what makes webhook replay safe: a redelivered signal
    collides on this column and is recognised as a duplicate rather than
    creating a second row for the same money.
    """

    __tablename__ = "inbound_payments"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    # The bank's identifier, not ours. Unique, because the same payment
    # must never appear twice however many times the webhook fires.
    bank_reference: Mapped[str] = mapped_column(String(128), unique=True, index=True)

    user_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("users.id", ondelete="RESTRICT"),
        index=True,
    )

    virtual_account_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("virtual_accounts.id", ondelete="RESTRICT"),
        index=True,
    )

    status: Mapped[str] = mapped_column(
        String(20), server_default=text("'RECEIVED'"), index=True
    )

    # As the payment arrived, in the currency it arrived in. We do not
    # convert. The bank does the FX and reports the INR result separately
    # below, if and when it has settled.
    amount: Mapped[decimal.Decimal] = mapped_column(Numeric(18, 4))
    currency: Mapped[str] = mapped_column(String(3))

    payer_name: Mapped[str | None] = mapped_column(String(255))
    payer_country: Mapped[str | None] = mapped_column(String(2))

    # What the bank credited, once it has. Both nullable because a payment
    # that is RECEIVED but not yet CREDITED has neither.
    credited_amount_inr: Mapped[decimal.Decimal | None] = mapped_column(Numeric(18, 4))
    exchange_rate: Mapped[decimal.Decimal | None] = mapped_column(Numeric(18, 6))

    # FEMA reporting. The purpose code classifies why the money came in;
    # the bank files it. We suggest it from the linked declaration and the
    # bank confirms or overrides.
    purpose_code: Mapped[str | None] = mapped_column(String(20), index=True)

    # Set once the bank issues the FIRA. We store the reference, not the
    # document itself, and we never issue one ourselves.
    fira_reference: Mapped[str | None] = mapped_column(String(128))
    fira_issued_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))

    # Links to a pre-declaration the customer filed before the money
    # arrived, if one matched. Nullable: plenty of payments arrive with no
    # advance notice, which is the normal case today and precisely the
    # problem pre-declaration exists to reduce.
    declaration_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("declarations.id", ondelete="SET NULL"),
        index=True,
    )

    # Populated on ON_HOLD or RETURNED, straight from the bank's message.
    # We record the bank's stated reason verbatim rather than paraphrasing
    # it, because the customer will eventually be shown this and a
    # reworded reason is a support call waiting to happen.
    bank_remark: Mapped[str | None] = mapped_column(String(500))

    received_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('RECEIVED', 'CREDITED', 'RETURNED', 'ON_HOLD')",
            name="ck_inbound_payments_status",
        ),
        CheckConstraint("amount > 0", name="ck_inbound_payments_amount_positive"),
        CheckConstraint(
            "credited_amount_inr IS NULL OR credited_amount_inr > 0",
            name="ck_inbound_payments_credited_positive",
        ),
        CheckConstraint(
            "exchange_rate IS NULL OR exchange_rate > 0",
            name="ck_inbound_payments_rate_positive",
        ),
        # The dashboard's main query: this user's payments, newest first.
        Index("ix_inbound_payments_user_received", "user_id", "received_at"),
        # The bank ops queue: everything currently held, oldest first,
        # because the oldest hold is the one costing the most goodwill.
        Index("ix_inbound_payments_status_received", "status", "received_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<InboundPayment id={self.id} ref={self.bank_reference!r} "
            f"{self.amount} {self.currency} status={self.status}>"
        )