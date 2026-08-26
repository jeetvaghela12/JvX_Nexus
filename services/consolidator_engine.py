"""
Services: consolidator_engine.py
Pillar 2's business logic: gap detection (which income records lack any
proof at all) and self-declared receipt generation (for the genuinely
undocumented small-payment case this turn is about).

RECONSTRUCTED, NOT RE-VERIFIED -- see income_model.py's module docstring
for the same caveat. Cross-check against your real models/user_model.py
before trusting this blind.
"""
import datetime
import hashlib
import logging
from dataclasses import dataclass, field
from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.orm import Session

from models.income_model import ExportProofDocument, ForeignIncomeRecord
from services.file_storage_client import save_document
# save_document(document_type, file_hash, file_bytes, extension="pdf") --
# this exact signature was directly verified against the real file a
# couple turns before my sandbox reset, so importing it directly (rather
# than injecting it as a parameter) is consistent with how every other
# service-to-service call in this codebase works. Still worth a quick
# confirmation against your real file_storage_client.py before trusting
# this blind, same as everything else in this rebuild.

logger = logging.getLogger(__name__)


class AlreadyDocumentedError(Exception):
    """
    Raised when a self-declared receipt is requested for an income
    record that already has real (bank- or platform-issued) proof
    attached. Generating a self-attestation for something already
    independently documented is at best pointless and at worst
    confusing -- if a CA later sees both a real FIRC and a self-declared
    receipt for the same record, which one are they supposed to trust?
    Refusing outright avoids that question ever coming up.
    """


@dataclass(frozen=True, slots=True)
class IncomeGapEntry:
    income_record_id: int
    source: str
    amount: Decimal
    currency: str
    received_date: datetime.date


@dataclass(frozen=True, slots=True)
class DocumentationGapReport:
    total_income_records: int
    records_with_proof: int
    records_missing_proof: list[IncomeGapEntry] = field(default_factory=list)
    # "Missing proof" here means zero linked documents of ANY kind --
    # including self-declared. A record with only a self-declared
    # receipt is NOT a gap for this report's purposes; it has something,
    # even if that something is a weaker tier of evidence. The tier
    # distinction is surfaced separately, in the export, not conflated
    # with "has nothing at all."


def compute_documentation_gaps(db: Session, user_id: int) -> DocumentationGapReport:
    """
    Finds every ForeignIncomeRecord belonging to user_id that has zero
    linked ExportProofDocument rows of any kind.
    """
    records = db.execute(
        select(ForeignIncomeRecord).where(ForeignIncomeRecord.user_id == user_id)
    ).scalars().all()

    gaps: list[IncomeGapEntry] = []
    records_with_proof = 0

    for record in records:
        has_any_proof = db.execute(
            select(ExportProofDocument.id).where(ExportProofDocument.income_record_id == record.id).limit(1)
        ).scalar_one_or_none()

        if has_any_proof is None:
            gaps.append(
                IncomeGapEntry(
                    income_record_id=record.id,
                    source=record.source,
                    amount=record.amount,
                    currency=record.currency,
                    received_date=record.received_date,
                )
            )
        else:
            records_with_proof += 1

    return DocumentationGapReport(
        total_income_records=len(records),
        records_with_proof=records_with_proof,
        records_missing_proof=gaps,
    )


def generate_self_declared_receipt_content(
    income_record: ForeignIncomeRecord,
    recipient_full_name: str,
) -> str:
    """
    Produces the TEXT CONTENT of a self-declared receipt -- deliberately
    plain text, not a rendered PDF. Same scope discipline as everywhere
    else this session: a polished PDF generator is real, separate work;
    an honest, clearly-labeled text record is what today's build
    actually needs. The caller is responsible for storing this via
    file_storage_client and creating the ExportProofDocument row with
    document_type="SELF_DECLARED_RECEIPT".

    Every line of the warning banner below is deliberate, not
    boilerplate -- this is the one place in the whole system where a
    document could be mistaken for something it isn't, and the words
    doing that work belong in the artifact itself, not just in a UI
    label a reviewer three steps removed from this file might never see.
    """
    generated_at = datetime.datetime.now(datetime.timezone.utc)

    return f"""\
================================================================
SELF-DECLARED PAYMENT RECEIPT -- NOT BANK OR PLATFORM ISSUED
================================================================
This document is a self-attestation by the recipient. It is NOT
a Foreign Inward Remittance Certificate (FIRC), NOT a Foreign
Inward Remittance Advice (FIRA), and was NOT issued by any bank
or payment platform. It carries no independent verification and
should be treated accordingly by anyone relying on it.

Generated for: genuinely undocumented income where no external
proof of receipt exists (e.g. a small, informal payment with no
invoice or platform receipt available).

----------------------------------------------------------------
Recipient:        {recipient_full_name}
Payer / Client:    {income_record.client_name or "(not specified)"}
Amount:           {income_record.amount} {income_record.currency}
Date received:     {income_record.received_date}
Reported source:   {income_record.source}
Notes:            {income_record.notes or "(none)"}
----------------------------------------------------------------
Generated by JvX Nexus on {generated_at.isoformat()}
Record ID: {income_record.id}
================================================================
"""


@dataclass(frozen=True, slots=True)
class ExportedDocument:
    document_type: str
    storage_key: str


@dataclass(frozen=True, slots=True)
class ExportedIncomeRecord:
    income_record_id: int
    source: str
    amount: Decimal
    currency: str
    received_date: datetime.date
    documents: list[ExportedDocument]
    # Deliberately a list, not a single optional document -- a record
    # could have more than one attached (e.g. both a bank FIRC and an
    # earlier self-declared receipt that's now superseded), and the
    # export should show all of it, not silently pick one.


@dataclass(frozen=True, slots=True)
class CaExportReport:
    generated_at: datetime.datetime
    total_income_records: int
    total_documented: int
    total_missing_documentation: int
    records: list[ExportedIncomeRecord]


def compute_ca_export(db: Session, user_id: int) -> CaExportReport:
    """
    The '1-click audit-ready export' -- every income record for the user,
    each with every document attached to it, in one structured object a
    CA can work from. Deliberately returns structured data, not a
    rendered PDF: a polished PDF bundler is real, separate work (same
    scope discipline as everywhere else this build), and this is what
    actually matters for the CA -- a complete, correct record, not a
    stylized document. JSON-to-PDF rendering is a natural next step once
    there's a reason to prioritize it over other work.
    """
    records = db.execute(
        select(ForeignIncomeRecord).where(ForeignIncomeRecord.user_id == user_id)
    ).scalars().all()

    exported_records: list[ExportedIncomeRecord] = []
    total_documented = 0

    for record in records:
        documents = db.execute(
            select(ExportProofDocument).where(ExportProofDocument.income_record_id == record.id)
        ).scalars().all()

        if documents:
            total_documented += 1

        exported_records.append(
            ExportedIncomeRecord(
                income_record_id=record.id,
                source=record.source,
                amount=record.amount,
                currency=record.currency,
                received_date=record.received_date,
                documents=[
                    ExportedDocument(document_type=doc.document_type, storage_key=doc.storage_key)
                    for doc in documents
                ],
            )
        )

    return CaExportReport(
        generated_at=datetime.datetime.now(datetime.timezone.utc),
        total_income_records=len(exported_records),
        total_documented=total_documented,
        total_missing_documentation=len(exported_records) - total_documented,
        records=exported_records,
    )


def create_self_declared_receipt(
    db: Session,
    income_record: ForeignIncomeRecord,
    recipient_full_name: str,
) -> ExportProofDocument:
    """
    Orchestrates the guard + generation + storage + row-creation for a
    self-declared receipt.
    """
    existing_real_proof = db.execute(
        select(ExportProofDocument)
        .where(
            ExportProofDocument.income_record_id == income_record.id,
            ExportProofDocument.document_type != "SELF_DECLARED_RECEIPT",
        )
        .limit(1)
    ).scalar_one_or_none()

    if existing_real_proof is not None:
        raise AlreadyDocumentedError(
            f"Income record {income_record.id} already has a "
            f"{existing_real_proof.document_type} document attached -- "
            "refusing to generate a self-declared receipt for a record "
            "that already has real proof."
        )

    content = generate_self_declared_receipt_content(income_record, recipient_full_name)
    content_bytes = content.encode("utf-8")
    file_hash = hashlib.sha256(content_bytes).hexdigest()

    storage_key = save_document(
        document_type="self_declared_receipt",
        file_hash=file_hash,
        file_bytes=content_bytes,
        extension="txt",
    )

    document = ExportProofDocument(
        income_record_id=income_record.id,
        document_type="SELF_DECLARED_RECEIPT",
        storage_key=storage_key,
    )

    try:
        db.add(document)
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Unexpected failure saving self-declared receipt (income_record_id=%s)", income_record.id)
        raise

    db.refresh(document)
    return document