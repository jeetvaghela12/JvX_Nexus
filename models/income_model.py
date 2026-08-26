"""
Models: income_model.py
Pillar 2 (Consolidator) -- ForeignIncomeRecord (one row per income event,
whether JvX-processed or externally reported) and ExportProofDocument
(the evidence attached to it, if any).

RECONSTRUCTED, NOT RE-VERIFIED: my working sandbox reset since this
architecture was first designed several turns back -- this file matches
my best, careful record of that design and this session's established
conventions (RESTRICT/SET NULL FK reasoning, EncryptedString for
third-party identifying data, CheckConstraint-backed status/type
columns), but it has not been cross-compiled against your actual
core/encryption.py, models/user_model.py, or models/ledger_model.py the
way every other file this session was. Check the import path for
EncryptedString and the exact column name/type of TransactionLedger.id
and User.id against your real files before treating this as final.
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
from core.encryption import EncryptedString  # AES-256-GCM field-level encryption, see core/encryption.py


class ForeignIncomeRecord(Base):
    """
    One row per income event -- money JvX itself processed (auto-linked
    via related_transaction_id) or money the user reports having received
    elsewhere (Upwork, AdSense, PayPal, Wise, a direct wire). This table
    deliberately does NOT reuse TransactionLedger: that table's columns
    (platform_fee_charged, idempotency_key, net_platform_revenue) all
    describe money JvX itself settled, which most rows here never were.
    """

    __tablename__ = "foreign_income_records"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="RESTRICT"), index=True)
    # RESTRICT, same reasoning as every other user-owned record in this
    # codebase: a logged income event having existed is itself a fact
    # worth preserving, not something that should vanish if the account
    # is later deleted.

    source: Mapped[str] = mapped_column(String(30), index=True)
    # JVX_NEXUS / UPWORK / ADSENSE / PAYPAL / WISE / DIRECT_WIRE / OTHER --
    # which platform the money actually arrived through, independent of
    # how well-documented it is (see ExportProofDocument.document_type
    # below for that axis).

    related_transaction_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("transaction_ledger.id", ondelete="SET NULL"), index=True
    )
    # Only ever set when source == "JVX_NEXUS" -- auto-links this record
    # to the real settlement JvX itself processed, so Pillar 1 income
    # populates the Consolidator dashboard without the user re-entering
    # it by hand. SET NULL, not RESTRICT: if the linked ledger row were
    # ever deleted, this income record shouldn't disappear with it, just
    # lose the cross-reference -- same pattern as CommercialInvoice.
    # related_transaction_id from Pillar 1.

    amount: Mapped[decimal.Decimal] = mapped_column(Numeric(18, 4))
    currency: Mapped[str] = mapped_column(String(3))
    received_date: Mapped[datetime.date] = mapped_column(DateTime(timezone=True))

    client_name: Mapped[str | None] = mapped_column(EncryptedString(255))
    # Encrypted -- this is identifying information about a third party
    # (the foreign client), the same sensitivity category as every other
    # EncryptedString field in this codebase, not because the platform
    # itself is regulated here but because the underlying data is.

    notes: Mapped[str | None] = mapped_column(String(500))

    external_reference_id: Mapped[str | None] = mapped_column(String(255), index=True)
    # Only set for records created by an automated sync (e.g. AdSense) --
    # the source platform's own identifier for this specific payment.
    # Without this, re-running a sync would have no way to tell "already
    # imported this one" from "new payment," and would duplicate every
    # record on every sync. Nullable because manually-logged and
    # JvX-processed records have no external system to key off.

    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        CheckConstraint(
            "source IN ('JVX_NEXUS','UPWORK','ADSENSE','PAYPAL','WISE','DIRECT_WIRE','OTHER')",
            name="ck_foreign_income_source",
        ),
        CheckConstraint("amount > 0", name="ck_foreign_income_amount_positive"),
        Index("ix_foreign_income_user_received", "user_id", "received_date"),
        Index(
            "ix_foreign_income_user_source_external_ref",
            "user_id", "source", "external_reference_id",
            unique=True,
            postgresql_where=text("external_reference_id IS NOT NULL"),
        ),
        # Partial unique index, not a plain UniqueConstraint: most rows
        # have external_reference_id = NULL (manual entries), and a
        # normal unique constraint would treat multiple NULLs as
        # violations under some backends' semantics or, worse, silently
        # allow true duplicates for the one column that's actually
        # supposed to be deduplicated. Restricting the uniqueness check
        # to non-NULL rows is what actually enforces "never import the
        # same AdSense payment twice" without touching manual entries.
    )


class ExportProofDocument(Base):
    """
    The evidence attached to a ForeignIncomeRecord, if any -- and
    critically, WHAT KIND of evidence, since that's not a uniform
    category. A bank-issued FIRC/FIRA carries FEMA/RBI-recognized
    evidentiary weight. A platform-issued receipt (Upwork, PayPal) is an
    independent, externally-generated document, but per this session's
    own earlier research, Upwork explicitly does NOT issue a FIRC --
    platform receipts are real evidence, just not the same tier as a
    bank-recognized document. A self-declared receipt is neither: it's
    the user's own attestation, generated by JvX itself for genuinely
    undocumented small payments, and it must never be allowed to look
    like the other two in an export a CA or tax reviewer relies on.
    """

    __tablename__ = "export_proof_documents"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    income_record_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("foreign_income_records.id", ondelete="CASCADE"), index=True
    )
    # CASCADE, deliberately different from every other FK pattern in this
    # codebase: a proof document has no independent meaning without the
    # income record it documents. This is a personal record-keeping tool,
    # not a regulatory audit trail like TransactionLedger or
    # CommercialInvoice -- a user cleaning up a mistaken entry should be
    # able to delete it and its attached document together.

    document_type: Mapped[str] = mapped_column(String(30))
    # FIRC / FIRA / PLATFORM_RECEIPT / FORM_1042S / SELF_DECLARED_RECEIPT / OTHER.
    # SELF_DECLARED_RECEIPT is named to be unmistakably different from
    # PLATFORM_RECEIPT at a glance -- the whole point of this column is
    # that these must never be visually or semantically conflated.

    storage_key: Mapped[str] = mapped_column(String(500))
    uploaded_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        CheckConstraint(
            "document_type IN ('FIRC','FIRA','PLATFORM_RECEIPT','FORM_1042S','SELF_DECLARED_RECEIPT','OTHER')",
            name="ck_export_proof_document_type",
        ),
    )


class ConnectedIncomeSource(Base):
    """
    An OAuth-connected external income source -- today, only AdSense; the
    shape is deliberately generic so a future PayPal or Wise partnership
    integration (see Pillar 2's own staged roadmap) can reuse this table
    rather than each needing its own bespoke credential storage.

    Deliberately NOT a column on User: a connected account is closer in
    spirit to a permission grant than to identity, and this keeps User
    focused on auth/identity rather than accumulating one column per
    future integration.
    """

    __tablename__ = "connected_income_sources"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="RESTRICT"), index=True)

    source: Mapped[str] = mapped_column(String(30))
    # Only 'ADSENSE' is wired up today; the CheckConstraint below lists
    # PAYPAL and WISE too so the schema doesn't need another migration
    # the moment either partnership lands -- see consolidator_engine.py's
    # own "Stage 2" notes on this.

    encrypted_refresh_token: Mapped[str] = mapped_column(EncryptedString(1024))
    # This is a long-lived credential granting ongoing read access to the
    # user's earnings data -- the single most sensitive value this table
    # holds, encrypted at rest for exactly that reason, same AES-256-GCM
    # treatment as every other sensitive field in this codebase.

    connected_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_synced_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint("source IN ('ADSENSE','PAYPAL','WISE')", name="ck_connected_source"),
        Index("ix_connected_income_source_user_source", "user_id", "source", unique=True),
        # One connection per source per user -- reconnecting should
        # update the existing row (new consent, new refresh token), not
        # create a second, competing credential for the same source.
    )