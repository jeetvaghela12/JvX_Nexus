"""
Models: clientshield_model.py
Pillar 3 -- ClientShieldReport, one row per pre-engagement risk check a
user runs on a prospective foreign client.

RECONSTRUCTED, NOT RE-VERIFIED against your real core/encryption.py or
core/database.py -- same standing caveat as every model file in this
rebuild. Check the EncryptedString import path against your real file
before treating this as final.
"""
import datetime

from sqlalchemy import BigInteger, Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base
from core.encryption import EncryptedString


class ClientShieldReport(Base):
    """
    One row per risk check. Deliberately stores every individual signal
    (domain age, registry match, sanctions hit, MX validity, disposable
    email, Web Risk flag) as its OWN column, not just the final score --
    a user revisiting an old report needs to see WHY it scored the way
    it did, not just a number. This is what makes "show your work"
    possible on the frontend, and it's the same instinct behind every
    other weighted-signal design decision in this build: a risk score
    with no visible reasoning is a black box nobody should trust.
    """

    __tablename__ = "clientshield_reports"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="RESTRICT"), index=True)

    client_name: Mapped[str] = mapped_column(EncryptedString(255))
    # Encrypted -- identifying information about a third party, same
    # sensitivity treatment as client_name on ForeignIncomeRecord.

    client_domain: Mapped[str | None] = mapped_column(String(255))
    client_country: Mapped[str | None] = mapped_column(String(2))
    # ISO 3166-1 alpha-2, used to route which registry check applies
    # (e.g. "GB" -> Companies House). Optional: a user may not know or
    # may be wrong about the client's actual country, and the check
    # should still run on whatever signals ARE available rather than
    # refusing to proceed.

    domain_age_days: Mapped[int | None] = mapped_column(Integer)
    registry_match_found: Mapped[bool | None] = mapped_column(Boolean)
    # NULL, deliberately distinct from False: NULL means "no registry
    # check was even attempted for this country" (e.g. US, where no free
    # self-serve option exists per the feasibility research); False
    # means "a check ran and found no match." Conflating these into one
    # boolean would silently misrepresent an uncovered jurisdiction as a
    # verified negative -- a materially different, and worse, claim.

    sanctions_hit: Mapped[bool] = mapped_column(Boolean, default=False)
    mx_valid: Mapped[bool | None] = mapped_column(Boolean)
    disposable_email: Mapped[bool | None] = mapped_column(Boolean)
    web_risk_flagged: Mapped[bool | None] = mapped_column(Boolean)

    risk_score: Mapped[str] = mapped_column(String(10))
    risk_points: Mapped[int] = mapped_column(Integer)
    # The raw weighted score, alongside the LOW/MEDIUM/HIGH bucket it
    # produced -- stored separately so the bucket thresholds can be
    # retuned later without losing the ability to recompute historical
    # reports under new thresholds.

    status: Mapped[str] = mapped_column(String(20), default="COMPLETED")
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        CheckConstraint("risk_score IN ('LOW','MEDIUM','HIGH')", name="ck_clientshield_risk_score"),
        CheckConstraint("status IN ('PENDING','COMPLETED','FAILED')", name="ck_clientshield_status"),
        Index("ix_clientshield_user_created", "user_id", "created_at"),
    )