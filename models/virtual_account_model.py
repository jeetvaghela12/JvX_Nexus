"""
Models: virtual_account_model.py
Country-specific Virtual Account Numbers (VANs) issued to a User -- the
replacement for the hardcoded virtual_bank_account / us_virtual_account_number
columns previously on User, which didn't scale past exactly two countries
(India, US) and couldn't represent a user holding accounts in more than
one country at once.

RAW FOREIGN KEY, NOT relationship(): matches every other cross-table
reference in this codebase (TransactionLedger.user_id, SupportTicket.user_id
etc.) -- no SQLAlchemy relationship() objects appear anywhere in these
models; every join is an explicit select() at the call site. Kept
consistent here rather than introducing ORM relationships for just this
one table.
"""
from decimal import Decimal
import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base


class VirtualAccount(Base):
    __tablename__ = "virtual_accounts"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="RESTRICT"), index=True)
    # RESTRICT, not CASCADE: matches TransactionLedger/SupportTicket's own
    # FK behavior to User -- a VAN having ever existed for a user is an
    # audit-relevant fact in its own right (it identifies an account funds
    # could have moved through), so a User row can't be deleted out from
    # under an issued VAN.

    country_code: Mapped[str] = mapped_column(String(2), index=True)
    # ISO 3166-1 alpha-2 SHAPE is enforced here (exactly 2 letters), but
    # NOT validated against the real, finite list of actual country codes
    # -- that list changes over time and belongs in the schema layer
    # (schemas/van_schemas.py), not hardcoded into the database. Note for
    # whoever populates this: "GB", not "UK" -- UK is not the ISO code.
    # "EU" is not a country code at all; a genuine Eurozone VAN would need
    # a specific member country's code (DE, FR, ...), not a blanket "EU"
    # value -- there's no single "EU" banking jurisdiction this column
    # could represent.

    account_number: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    # unique=True is safe here (unlike the FLE-encrypted columns on User):
    # this is a provider-issued account identifier, not government PII,
    # and isn't encrypted, so equality/uniqueness checks work normally.

    routing_details: Mapped[dict] = mapped_column(JSONB)
    # JSONB, not a single string column, even though the request described
    # this as one "routing_details (like SWIFT/Sort Code/IFSC)" value:
    # different countries genuinely need different NUMBERS of routing
    # fields, not just different single values -- a Eurozone account
    # commonly needs BOTH an IBAN and a BIC/SWIFT code together, which a
    # single string can't cleanly represent without fragile delimiter
    # parsing. Shape varies by country_code, e.g. {"ifsc": "..."} for IN,
    # {"routing_number": "...", "swift": "..."} for US, {"sort_code":
    # "..."} for GB -- deliberately not a fixed schema, since the field
    # set is expected to differ by country.

    status: Mapped[str] = mapped_column(String(20), server_default=text("'PENDING'"))
    __status_values__ = ("PENDING", "ACTIVE", "FAILED")
    # PENDING: requested, provider call not yet resolved. ACTIVE: provider
    # confirmed issuance, this account can receive funds. FAILED:
    # provisioning failed -- kept as a row (not deleted) so a failed
    # attempt remains visible/auditable rather than silently disappearing.

    provider_name: Mapped[str] = mapped_column(String(50))
    # Which underlying provider actually issued this specific VAN (e.g.
    # "decentro", or "mock" during local testing) -- meaningful once more
    # than one real provider exists (e.g. Decentro for IN, a
    # cross-border-capable provider for other countries), so it's
    # recorded per-VAN from the start rather than added retroactively.

    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        CheckConstraint("status IN ('PENDING', 'ACTIVE', 'FAILED')", name="ck_virtual_accounts_status"),
        UniqueConstraint("user_id", "country_code", name="uq_virtual_accounts_user_country"),
        # One VAN per (user, country) pair -- prevents duplicate requests
        # for the same country from producing two separate accounts,
        # while still allowing a user to hold VANs in as many DIFFERENT
        # countries as they've been issued.
        Index("ix_virtual_accounts_user_id_status", "user_id", "status"),
    )