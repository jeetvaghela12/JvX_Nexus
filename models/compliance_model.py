"""
Models: compliance_model.py
Audit and compliance infrastructure that sits alongside the core payment
ledger: RawWebhookLog captures every incoming bank signal before any
validation happens, and CommercialInvoice supports the pre-invoice
compliance workflow for T+2 settlement reduction.

Both tables are new to models/ -- Stage 1 had originally scoped
user_model.py / ledger_model.py / ticket_model.py as the complete set of
model files; this is a deliberate expansion for the Super Set Integration
Phase, not an oversight of that original scope.
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
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base


class RawWebhookLog(Base):
    """
    Records 100% of incoming bank webhook signals before process_bank_signal
    ever runs -- this is the audit-trail mechanism decided on to cover
    webhooks that reference an account this platform doesn't recognize
    (UnrecognizedAccountError), which TransactionLedger can't store given
    its NOT NULL user_id. Populated by api/b2b_routes.py, immediately after
    signature verification and before (or alongside) the call to
    process_bank_signal -- not built into that route yet as of this file;
    wiring the actual write is a separate change to b2b_routes.py.

    Like TransactionLedger, rows here are never expected to be deleted --
    it's an audit trail specifically because the corresponding ledger row
    might not exist to reconstruct what happened otherwise.
    """

    __tablename__ = "raw_webhook_logs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    payload: Mapped[dict] = mapped_column(JSONB)
    # JSONB, not Text: the brief offered either. JSONB stores as parsed
    # binary rather than a plain string, which means this column stays
    # queryable/indexable (e.g. "find every raw log where payload->>
    # 'currency' = 'GBP'") without re-parsing text on every query --
    # meaningfully better fit than Text for a table whose whole purpose is
    # being inspected during incident review. Postgres-specific
    # (sqlalchemy.dialects.postgresql.JSONB), consistent with the rest of
    # this codebase already assuming Postgres (e.g. the partial indexes in
    # ledger_model.py).

    headers: Mapped[dict] = mapped_column(JSONB)
    # SECURITY NOTE for whoever writes to this column: don't dump the raw
    # header dict verbatim if it could ever contain a real Authorization
    # header, a cookie, or (once HMAC verification is real, not the mock
    # in b2b_routes.py) the actual signature value. This table is an audit
    # log, not a secrets store -- redact/exclude sensitive header names at
    # the point where this row gets written, not here (a model file can't
    # enforce that; it's a caller responsibility to flag).

    status: Mapped[str] = mapped_column(String(20), server_default=text("'RECEIVED'"), index=True)
    # Full value set defined fresh here (no prior version to preserve),
    # so -- unlike kyc_status/entity_type elsewhere -- a CheckConstraint
    # is appropriate: RECEIVED (default, written before any processing
    # attempt), PROCESSED (process_bank_signal completed, regardless of
    # whether the resulting ledger row ended up COMPLETED or FAILED --
    # that's TransactionLedger.status's job to track, not this column's),
    # FAILED (process_bank_signal raised), INVALID_SIGNATURE (rejected
    # before process_bank_signal was ever called).

    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        CheckConstraint(
            "status IN ('RECEIVED', 'PROCESSED', 'FAILED', 'INVALID_SIGNATURE')",
            name="ck_raw_webhook_logs_status_valid",
        ),
        # Incident review's dominant query: "show recent FAILED /
        # INVALID_SIGNATURE entries." Composite over the standalone
        # index=True above once this exists, same leftmost-prefix
        # reasoning used throughout this codebase's other tables.
        Index("ix_raw_webhook_logs_status_created", "status", "created_at"),
    )


class CommercialInvoice(Base):
    """
    Pre-invoice compliance record: commercial invoice documentation
    submitted ahead of a cross-border transaction so bank/regulatory
    approval can happen before money moves, cutting settlement time
    (T+2 reduction) versus submitting this after the fact. Not linked to
    a specific TransactionLedger row by a FK here -- the brief's column
    list didn't include one, and given invoices are meant to be submitted
    BEFORE the corresponding transaction, there may not be a ledger row
    yet at creation time. Worth a nullable FK, populated once the actual
    transaction happens, if that linkage turns out to matter -- flagging
    rather than adding it speculatively.
    """

    __tablename__ = "commercial_invoices"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    user_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("users.id", ondelete="RESTRICT"),
        index=True,
    )
    # RESTRICT, same reasoning as user_id on TransactionLedger: a
    # compliance document shouldn't disappear because the account was
    # later deleted.

    related_transaction_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("transaction_ledger.id", ondelete="SET NULL"),
        index=True,
    )
    # NEW: closes the gap this file's own docstring originally flagged --
    # "not linked to a specific TransactionLedger row by a FK." Nullable
    # and SET NULL, mirroring SupportTicket.related_transaction_id's
    # exact pattern above in the same codebase: an invoice is meant to be
    # submitted BEFORE its corresponding transaction exists (there may be
    # no ledger row yet at creation time), and if the linked transaction
    # were ever deleted, this invoice record shouldn't disappear with it
    # -- it just loses the reference. NOTHING in this codebase sets this
    # column automatically yet -- matching a submitted invoice to the
    # transaction it corresponds to needs matching logic (by amount,
    # currency, user, timing) that was explicitly scoped out as future
    # work when the Pre-Invoice Engine was built. This column exists so
    # that linkage, once built, has somewhere to go -- api/compliance_routes.py's
    # e-FIRA bundle generator below accepts it as an explicit, caller-
    # supplied parameter instead, not something it infers on its own.

    invoice_number: Mapped[str] = mapped_column(String(100))
    # Not globally unique=True: different users' businesses plausibly use
    # overlapping numbering schemes independently (two different
    # companies both issuing an "INV-001" isn't a collision worth
    # rejecting). Uniqueness is scoped to (user_id, invoice_number)
    # instead -- see __table_args__ -- so it's each user's own numbering
    # that has to stay internally consistent, not the whole table's.
    # Wasn't specified either way in the brief; flagging this as a
    # judgment call, not a literal instruction. Now populated by
    # services/compliance_engine.py's mock invoice extraction, not typed
    # directly by the user -- see api/invoice_routes.py.

    amount: Mapped[decimal.Decimal] = mapped_column(Numeric(18, 4))
    # Numeric(18, 4)/Decimal per this session's absolute rule on monetary
    # columns, even though the brief just said "amount" -- not treated as
    # optional given how explicit and repeated that rule has been.

    currency: Mapped[str] = mapped_column(String(3))
    # ISO 4217 alpha-3, matching source_currency's convention on
    # TransactionLedger.

    buyer_name: Mapped[str | None] = mapped_column(String(255))
    # NEW: the counterparty name as read off the invoice by extraction --
    # needed for the "buyer names... match exactly" cross-check the
    # Pre-Invoice Engine is specifically for. Nullable because extraction
    # can fail to find a name without that necessarily being fraud (a
    # poorly-formatted invoice, for instance) -- the route decides what
    # to do with a null buyer_name, this column just records what came
    # back.

    file_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    # SHA-256 hex digest (64 hex chars) of the raw uploaded PDF bytes.
    # unique=True GLOBALLY -- not scoped to user_id, and this is
    # deliberate: the checklist point this implements was specifically
    # about catching the same invoice submitted across DIFFERENT merchant
    # nodes, exactly the fraud pattern a per-user constraint can't catch.
    # Plain unique index, not encrypted -- a hash isn't PII, it's a
    # derived fingerprint with no path back to the original content.

    content_fingerprint: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    # A SEPARATE hash from file_hash, over the extracted metadata fields
    # (buyer_name + invoice_number + amount + currency, normalized), not
    # the raw file bytes. Necessary because file_hash alone has a real
    # gap: a regenerated PDF with byte-for-byte different output (re-
    # saved, re-exported, watermark added/removed) but IDENTICAL
    # underlying invoice content defeats raw file hashing entirely, while
    # still being the same double-invoicing fraud attempt. Also globally
    # unique for the same cross-merchant reasoning as file_hash.

    storage_key: Mapped[str] = mapped_column(String(512))
    # RENAMED from pdf_url: this is the first turn any code path actually
    # WRITES to this column, since no upload route existed until now,
    # which makes this the right moment to fix the gap flagged when this
    # column was first created rather than carry a known-wrong shape
    # forward. A presigned/expiring URL stored directly would go stale
    # independent of anything else about the row; a provider-agnostic
    # storage key, resolved to a real URL on read through config.py's
    # CLOUD_PROVIDER adapter, doesn't have that problem. No prior code
    # ever populated pdf_url, so this isn't a live-data rename -- the
    # column has never actually been used yet.

    status: Mapped[str] = mapped_column(String(30), server_default=text("'pending_bank_approval'"))
    # No CheckConstraint: only one example value was given ("e.g.
    # 'pending_bank_approval'"), not a full set, so -- same reasoning as
    # kyc_status on User -- nothing is guessed here. Note the casing
    # convention (lowercase_with_underscores) differs from
    # TransactionLedger/SupportTicket's status columns (UPPERCASE /
    # lowercase-no-underscores respectively); followed exactly as given
    # rather than normalized to match, but flagging the inconsistency
    # across the schema's status columns as something worth deciding on
    # once, rather than each new table picking its own convention.
    #
    # A duplicate submission is NEVER actually saved as a row with a
    # "rejected" status here, despite that seeming like a natural value
    # to add -- file_hash/content_fingerprint's own unique=True
    # constraints make that structurally impossible, since inserting a
    # second row sharing either value is exactly what those constraints
    # exist to block. api/invoice_routes.py rejects the request outright
    # (409) instead. A genuine audit trail of rejected duplicate attempts
    # (who tried, when, against which existing invoice) would need a
    # separate table without that constraint -- RawWebhookLog above is
    # exactly that pattern for a different rejection case -- but isn't
    # built here; flagging the gap rather than adding a status value that
    # would never actually get used.

    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        UniqueConstraint("user_id", "invoice_number", name="uq_commercial_invoices_user_invoice_number"),
        # Bank-approval queue's dominant query: "show pending invoices,
        # oldest first." Same composite-index reasoning as the ledger's
        # status+created_at index.
        Index("ix_commercial_invoices_status_created", "status", "created_at"),
    )


class EFiraLog(Base):
    """
    A generated e-FIRA compliance bundle -- packaged transaction metadata
    plus linked invoice references, ready to hand to the AD-1 bank's own
    compliance interface. IMPORTANT DISTINCTION, not just a naming detail:
    this platform does not, and legally cannot, issue an actual e-FIRA/
    FIRA/FIRC itself -- per the earlier compliance research, only the AD
    Category-I bank can issue that document, after filing an Inward
    Remittance Message on RBI's EDPMS. What's generated and stored here is
    the supporting DATA BUNDLE this platform supplies TO the bank for that
    purpose, not a substitute for the bank's own issuance. api/compliance_routes.py's
    response messaging says this explicitly, not just this docstring.

    Multiple rows CAN exist for the same transaction_id -- not unique=True
    -- since a bank might request a re-submission if an earlier bundle had
    an issue; each generation is preserved as its own timestamped record
    rather than overwriting history.
    """

    __tablename__ = "efira_logs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    transaction_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("transaction_ledger.id", ondelete="RESTRICT"),
        index=True,
    )
    # RESTRICT, not SET NULL: unlike CommercialInvoice's optional
    # related_transaction_id above, this link is this row's entire
    # reason for existing -- a bundle that no longer refers to any real
    # transaction isn't a degraded record, it's a meaningless one.

    bundle_payload: Mapped[dict] = mapped_column(JSONB)
    # The full generated bundle (see services/compliance_engine.py's
    # EFiraBundleData), stored as JSONB for the same reasoning as
    # RawWebhookLog.payload above -- queryable/inspectable without
    # re-parsing text, and this platform's own record of exactly what was
    # (or will be) handed to the bank.

    bundle_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    # SHA-256 over the bundle's canonical content (see
    # generate_efira_bundle) -- an integrity check the bank can use to
    # confirm what it received matches what this platform generated,
    # directly implementing the checklist's own "transaction hashes"
    # language. unique=True is a genuine, meaningful constraint here (not
    # just an index): a bundle with byte-for-byte identical content
    # already exists and generating another one adds no information, so
    # this catches an accidental duplicate submission attempt at the
    # database level.

    status: Mapped[str] = mapped_column(String(20), server_default=text("'GENERATED'"))
    # GENERATED (default -- this platform has produced the bundle and it
    # exists, nothing more). No SUBMITTED/ACKNOWLEDGED states yet -- there
    # is no outbound integration to the bank's compliance interface built
    # here, matching this file's docstring: this is the DATA, not the
    # transmission of it. CheckConstraint appropriate here (unlike
    # CommercialInvoice.status above) since, like RawWebhookLog.status,
    # the full value set is being defined fresh in this same step, not
    # inherited from an earlier, only-partially-specified design.

    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        CheckConstraint("status IN ('GENERATED')", name="ck_efira_logs_status_valid"),
        Index("ix_efira_logs_transaction_created", "transaction_id", "created_at"),
    )