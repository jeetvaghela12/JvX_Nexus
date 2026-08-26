"""
Models: user_model.py
Defines the core User entity for freelancers and B2B agencies.
Handles identity, authentication, compliance status, and payout routing details.
"""
import datetime

from sqlalchemy import BigInteger, Boolean, CheckConstraint, DateTime, Index, String, func, text
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base
from core.encryption import EncryptedString  # AES-256-GCM field-level encryption, see core/encryption.py


class User(Base):
    __tablename__ = "users"

    # ------------------------------------------------------------------
    # Core Identity
    # ------------------------------------------------------------------
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    # BigInteger (not Integer) is intentional: a 32-bit PK caps out around
    # 2.1B rows. At 10M+ concurrent users, plus every transaction/audit row
    # that FKs back to users.id, that ceiling is reachable -- BigInteger
    # avoids the painful PK-widening migration companies run in production
    # once they hit it.

    entity_type: Mapped[str] = mapped_column(String(50), index=True)
    # Left as plain String, unchanged -- the exact set of valid values
    # (freelancer / agency / ...?) wasn't given here. If the full set is
    # fixed and known, this is a good candidate for a Python Enum
    # (Mapped[EntityType] backed by the same String(50) column, no
    # migration needed) for compile-time type safety. Not applied
    # speculatively, to avoid guessing at values not in the original code.

    full_name: Mapped[str] = mapped_column(String(255))

    email_address: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    # unique=True alone already creates a unique index in Postgres; the
    # explicit index=True here collapses into that same index rather than
    # creating a second structure. Harmless, left exactly as provided.

    # ------------------------------------------------------------------
    # Security
    # ------------------------------------------------------------------
    password_hash: Mapped[str | None] = mapped_column(String(255))
    # NOW NULLABLE: a user who signs up exclusively via "Sign in with
    # Google" never sets a platform password at all. api/auth_routes.py's
    # login() must treat a None password_hash as "reject this login
    # attempt" (same generic 401 as a wrong password), not let it reach
    # verify_password() unguarded. Expectation (enforced upstream in the
    # auth service, not in this model): this holds an adaptive, salted
    # hash -- bcrypt, per core/security.py -- never a fast general-purpose
    # hash (SHA-256/MD5) and never the raw password. 255 chars comfortably
    # fits bcrypt's encoded output.

    google_id: Mapped[str | None] = mapped_column(String(255), unique=True)
    # Google's "sub" claim -- the stable, unique identifier for a Google
    # account. Deliberately NOT the email address: matching on Google's
    # own subject identifier is the technically correct way to recognize
    # "this is the same Google account", since (rare as it is) an email
    # can change while sub does not. NOT the FLE/EncryptedString pattern
    # tax_id_number etc. use above -- this needs unique=True for lookups
    # by google_id, and is an OAuth identifier issued by Google, not a
    # government ID.

    mfa_secret: Mapped[str | None] = mapped_column(EncryptedString(128))
    # TOTP shared secret (RFC 6238), base32-encoded (~32 chars raw for a
    # standard 160-bit secret) -- EncryptedString, not plain String, and
    # this is a more sensitive case for FLE than tax_id_number above: PAN
    # data is regulated PII, but this secret is the SECOND AUTHENTICATION
    # FACTOR itself. Anyone who obtains it in plaintext can generate valid
    # codes indefinitely, silently and completely defeating MFA -- unlike
    # a leaked password hash, which at least can't be reversed. Set (but
    # mfa_enabled left False) as soon as /auth/mfa/setup is called, before
    # the user has proven they can actually generate a valid code --
    # /auth/mfa/confirm is what flips mfa_enabled to True, only after
    # verifying one real TOTP code against this secret. Width 128, not a
    # computed value: base32 secrets can vary in configured byte length,
    # and the EncryptedString ciphertext overhead means comfortable
    # headroom costs nothing here.

    mfa_enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    # The actual enforcement gate at login time -- api/auth_routes.py's
    # login() checks this, not merely mfa_secret being non-null, since a
    # secret can exist mid-setup (post /mfa/setup, pre /mfa/confirm)
    # without MFA actually being active on the account yet.

    # ------------------------------------------------------------------
    # Compliance & KYC
    # ------------------------------------------------------------------
    is_kyc_verified: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))

    kyc_status: Mapped[str] = mapped_column(String(30), server_default=text("'PENDING'"))
    # OVERLAP WORTH RESOLVING, not silently papered over: this and
    # is_kyc_verified above now both describe KYC state on the same row.
    # is_kyc_verified is a simple boolean; kyc_status is presumably a
    # richer lifecycle (PENDING and at least one "done" state, maybe more
    # for zero-touch onboarding's automated review steps) -- but the full
    # value set wasn't specified, so no CheckConstraint is added here (see
    # entity_type above for the same reasoning: not guessing at values not
    # given). Left as a plain String rather than invent one. Until this is
    # settled, both columns can drift out of sync with each other (e.g.
    # kyc_status='VERIFIED' while is_kyc_verified is still false) since
    # nothing enforces they move together. The existing
    # ix_users_entity_type_kyc_verified index below still references
    # is_kyc_verified specifically -- if kyc_status ends up being the
    # source of truth, that index should be reconsidered too, not just
    # this column added alongside it.

    tax_id_number: Mapped[str | None] = mapped_column(EncryptedString(255))
    # FIELD-LEVEL ENCRYPTION (FLE): government tax/PAN identifiers are
    # regulated PII and must never be persisted in plaintext. EncryptedString
    # (core/encryption.py) is a SQLAlchemy TypeDecorator that
    # transparently encrypts with AES-256-GCM on write and decrypts on read.
    # The Python-level type is still `str` -- nothing about how the rest of
    # the app reads/writes this attribute changes.
    #
    # Column widened 100 -> 255: ciphertext (+ nonce + auth tag, base64-
    # encoded) is larger than the plaintext it replaces. This is the one
    # deliberate width change in this file, made necessary by encryption
    # itself -- not a naming or logic change.
    #
    # NOW NULLABLE: per the Zero-Touch VAM Onboarding architecture, this
    # (and virtual_bank_account below) is KYC-stage data -- signup collects
    # only identity + credentials, the tax ID arrives later when the user
    # actually uploads their business KYC documents. Previously NOT NULL,
    # which made it impossible to insert a User row at signup time at all;
    # this is the fix for that.
    #
    # Deliberately left NOT unique/indexed: this scheme uses a random nonce
    # per write, so the same tax ID encrypts to a different stored value
    # every time. A uniqueness constraint or equality index on this column
    # would silently stop working. (This is also why virtual_bank_account
    # and digital_wallet_address below are NOT wrapped in EncryptedString,
    # even though they're sensitive -- both rely on unique=True at the DB
    # level, which this style of encryption is incompatible with without a
    # deterministic scheme or a separate blind-index column. Flagging for a
    # follow-up rather than changing that logic here.)

    gst_number: Mapped[str | None] = mapped_column(EncryptedString(64))
    # GST (Goods and Services Tax) registration number -- one of the
    # business KYC documents the Zero-Touch Onboarding flow collects
    # (alongside PAN/tax_id_number and IEC below). Same FLE treatment as
    # tax_id_number and for the same reason: a government-issued business
    # tax identifier is regulated PII regardless of which specific
    # document it comes from. String(64) sized the same way
    # tax_id_number's width was: India's GST format is a fixed 15
    # characters, and (15 plaintext bytes + 12-byte nonce + 16-byte tag)
    # base64-encoded needs 60 characters -- 64 gives a little headroom
    # without being an arbitrary guess.
    #
    # No unique=True, for the identical reason tax_id_number doesn't have
    # one: random-nonce encryption makes equality/uniqueness checks on the
    # ciphertext meaningless.

    iec_code: Mapped[str | None] = mapped_column(EncryptedString(64))
    # IEC (Importer Exporter Code) -- the other business KYC document this
    # flow collects, required for cross-border trade specifically. Same
    # FLE treatment and same reasoning as gst_number immediately above;
    # sized the same width (64) even though IEC's own raw format is
    # shorter (10 characters, needing 52 chars encrypted) -- keeping both
    # new columns at one consistent width rather than two different
    # narrow ones.

    # ------------------------------------------------------------------
    # Financial Routing
    # ------------------------------------------------------------------
    # virtual_bank_account and us_virtual_account_number REMOVED from
    # here -- superseded by models/virtual_account_model.py's
    # VirtualAccount table (one-to-many with User via user_id), which
    # supports any number of countries rather than hardcoding exactly two
    # (India, US) as separate columns. See that file for the replacement.
    # Every place that referenced these two columns needed updating, not
    # just User itself -- most importantly services/bank_webhook.py's
    # recipient lookup, which this same change updates to query
    # VirtualAccount instead.
    digital_wallet_address: Mapped[str | None] = mapped_column(String(128), unique=True)
    # Unrelated to the VAN removal above and deliberately untouched:
    # this is where the PLATFORM sends money OUT to the user (a payout
    # method, managed via api/payout_routes.py), not an inbound VAN the
    # user receives funds INTO -- opposite direction of money flow, kept
    # as its own concern.

    preferred_payout_route: Mapped[str] = mapped_column(String(10), server_default=text("'FIAT'"))
    # Full value set was given explicitly (FIAT or CBDC), unlike
    # kyc_status/entity_type above -- so unlike those, this gets a
    # CheckConstraint (see __table_args__) rather than being left
    # unconstrained.

    local_bank_account_number: Mapped[str | None] = mapped_column(EncryptedString(64))
    # NOW ENCRYPTED, applying the FLE flag left open when this column was
    # first added. Width 64: raw Indian account numbers run roughly 9-18
    # digits depending on the bank; using 20 as a safe upper bound, (20
    # plaintext bytes + 12-byte nonce + 16-byte tag) base64-encoded needs
    # 64 characters exactly -- computed, not guessed.
    #
    # local_bank_ifsc, right below, is deliberately LEFT UNENCRYPTED,
    # even though it was flagged alongside this column and asked for
    # again this step: an IFSC identifies a bank BRANCH, not a person --
    # it's public information (RBI publishes searchable IFSC directories),
    # not PII. Encrypting it would cost real things (can't query/group by
    # bank, can't use it for branch-based routing logic later) for no
    # actual privacy benefit, since it was never sensitive to begin with.
    # Applying FLE here anyway just because it was asked would be doing
    # something because it was requested rather than because it's right --
    # worth deciding this deliberately rather than defaulting to "encrypt
    # everything that touches a bank account."
    local_bank_ifsc: Mapped[str | None] = mapped_column(String(11))
    # IFSC (Indian Financial System Code) is always exactly 11 characters
    # -- 4-letter bank code + 0 + 6-character branch code -- so String(11)
    # is an exact fit, not a guess.

    # ------------------------------------------------------------------
    # Timestamps
    # ------------------------------------------------------------------
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # ------------------------------------------------------------------
    # Indexing strategy (10M+ concurrent-user scale)
    # ------------------------------------------------------------------
    __table_args__ = (
        # Compliance/ops queries realistically filter by entity_type AND
        # verification status together far more often than entity_type
        # alone (e.g. "list unverified agencies pending KYC review"). A
        # composite index serves that filter in a single index scan, and
        # still serves entity_type-only lookups via the B-tree leftmost-
        # prefix rule -- additive, not a second thing to maintain on
        # every write.
        Index("ix_users_entity_type_kyc_verified", "entity_type", "is_kyc_verified"),

        CheckConstraint(
            "preferred_payout_route IN ('FIAT', 'CBDC')",
            name="ck_users_preferred_payout_route_valid",
        ),
    )
    # Not added, for consideration once there's a real access pattern to
    # serve: a BRIN index on created_at. BRIN indexes are dramatically
    # smaller than B-tree and well-suited to naturally-ordered, append-
    # mostly timestamp columns at this row count -- worth it for
    # time-range reporting/cohort queries if those materialize.