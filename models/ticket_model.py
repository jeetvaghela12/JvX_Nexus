"""
Models: ticket_model.py
Support ticket entity for the AI-assisted support desk -- tracks ticket
lifecycle, human/AI ownership, and the fields the support dashboard filters
and sorts on at high volume.
"""

import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    SmallInteger,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base

# NOTE ON NAMING: this file has no prior version to preserve, unlike
# user_model.py / ledger_model.py -- table name (support_tickets), column
# names, and the two design choices below (plain String+CHECK for status
# rather than a native Enum, integer priority rather than a string label)
# are this file's own new design. Flag anything you'd rather name
# differently and it's a one-line change before this becomes "Done".


class SupportTicket(Base):
    __tablename__ = "support_tickets"

    # ------------------------------------------------------------------
    # Ticket Identity
    # ------------------------------------------------------------------
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    ticket_reference: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    # Human-facing reference shown on the dashboard / emailed to the user
    # (e.g. "TCK-2026-000123"), generated in the service layer. Kept
    # unique+indexed the same way transaction_reference is on the ledger,
    # for fast direct lookup.

    # ------------------------------------------------------------------
    # Relationships
    # ------------------------------------------------------------------
    user_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("users.id", ondelete="RESTRICT"),
        index=True,
    )
    # The user who filed the ticket. RESTRICT, same reasoning as
    # ledger_model.py: a user's support history shouldn't disappear because
    # their account was deleted.

    assigned_agent_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("users.id", ondelete="SET NULL"),
        index=True,
    )
    # The support agent currently owning this ticket -- also a row in
    # `users` (internal staff distinguished via entity_type, same table).
    # Nullable: unassigned while AI is still handling it, or before triage.
    # SET NULL, not RESTRICT: if an agent's account is later removed, their
    # past tickets should stay in history rather than blocking the
    # deletion -- they just fall back to unassigned for re-triage.

    related_transaction_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("transaction_ledger.id", ondelete="SET NULL"),
        index=True,
    )
    # Which transaction this ticket is about, if any -- e.g. "my payout
    # failed" tickets. Nullable: plenty of tickets (account questions,
    # feature requests) aren't about a specific transaction. Added because
    # nothing on this model previously linked a ticket to a transaction at
    # all, which services/ai_support.py needs in order to know which
    # TransactionLedger row counts as "related" for a given ticket.
    # SET NULL rather than RESTRICT: a ledger row is never expected to be
    # deleted in practice (see the "never delete FAILED/REJECTED rows"
    # rule on TransactionLedger), so this is mostly a formality, but a
    # support ticket shouldn't be able to block that non-deletion policy
    # from being reconsidered later either.

    # ------------------------------------------------------------------
    # Ticket Content
    # ------------------------------------------------------------------
    subject: Mapped[str] = mapped_column(String(255))

    description: Mapped[str] = mapped_column(Text)
    # Text, not String(n): support messages are open-ended and routinely
    # exceed any reasonable VARCHAR bound.

    category: Mapped[str | None] = mapped_column(String(50), index=True)
    # e.g. "payout_delay", "kyc", "billing" -- nullable since AI
    # classification may land shortly after ticket creation, not atomically
    # with it. Indexed: filtering the dashboard by category is a primary view.

    # ------------------------------------------------------------------
    # Status & Priority -- the dashboard's primary filter/sort columns
    # ------------------------------------------------------------------
    status: Mapped[str] = mapped_column(String(20), server_default=text("'open'"), index=True)
    # Plain String + CHECK constraint (below) rather than a SQLAlchemy/
    # Postgres native Enum: adding a new status later is a metadata-only
    # migration instead of ALTER TYPE ... ADD VALUE. A companion Python
    # enum for application code is a natural addition once services/
    # ai_support.py exists -- deliberately not defined here, so the schema
    # and the service layer's constants can evolve independently.
    # Valid values (enforced below): open, pending, escalated, resolved, closed.

    priority: Mapped[int] = mapped_column(SmallInteger, server_default=text("3"), index=True)
    # Integer, not a string label, specifically so ORDER BY priority sorts
    # correctly (most urgent first) without a CASE expression -- "high" <
    # "low" alphabetically would otherwise sort backwards from severity.
    # 1 = Urgent, 2 = High, 3 = Medium (default), 4 = Low.

    # ------------------------------------------------------------------
    # AI Handling
    # ------------------------------------------------------------------
    is_ai_resolved: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    # True if AI closed this ticket without human escalation.

    ai_confidence_score: Mapped[float | None] = mapped_column(Float)
    # Float is correct here, not Numeric/Decimal -- this is a 0.0-1.0 model
    # confidence score, not currency, so none of the salami-slicing concern
    # that rules out float for money columns applies. Null until an AI pass
    # actually scores the ticket.

    # ------------------------------------------------------------------
    # Timestamps
    # ------------------------------------------------------------------
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    resolved_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))
    # Null until actually resolved/closed -- resolved_at minus created_at is
    # the SLA/resolution-time metric the dashboard will almost certainly
    # want to report on.

    # ------------------------------------------------------------------
    # Indexing & integrity strategy (high-volume, read-heavy dashboard)
    # ------------------------------------------------------------------
    __table_args__ = (
        CheckConstraint(
            "status IN ('open', 'pending', 'escalated', 'resolved', 'closed')",
            name="ck_tickets_status_valid",
        ),
        CheckConstraint("priority BETWEEN 1 AND 4", name="ck_tickets_priority_valid"),
        CheckConstraint(
            "ai_confidence_score IS NULL OR ai_confidence_score BETWEEN 0 AND 1",
            name="ck_tickets_ai_confidence_range",
        ),

        # Primary triage queue: "open tickets, most urgent and oldest first"
        # is the dashboard's default view. This table is far more read-heavy
        # relative to its write volume than the transaction ledger, so a
        # wider composite index is a better trade here than it would be on
        # a high-frequency-insert table.
        Index("ix_tickets_status_priority_created", "status", "priority", "created_at"),

        # An agent's personal queue: "my open tickets".
        Index("ix_tickets_agent_status", "assigned_agent_id", "status"),
    )