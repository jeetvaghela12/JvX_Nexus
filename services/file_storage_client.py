"""
Services: file_storage_client.py
Where uploaded invoice PDFs actually get written. Deliberately NOT a full
provider abstraction (unlike services/bank_onboarding_client.py's
VirtualAccountProvider Protocol) -- this is a single local-disk
implementation, not a mock/real pair behind an interface. Scope choice,
not an oversight: this turn's actual subject is the extraction/hashing/
dedup logic, and building a second full provider abstraction (S3, Azure
Blob, swappable via CLOUD_PROVIDER) alongside it would be a second large
feature bolted onto this one. save_invoice_pdf's signature is intentionally
narrow enough that swapping its body for a real CLOUD_PROVIDER-gated
implementation later doesn't require touching any caller.
"""
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_STORAGE_ROOT = Path("./local_invoice_storage")
# Relative to wherever the app process runs -- not an absolute path tied
# to any particular machine. Created on first write if it doesn't exist.
# This directory holding real (if locally-stored) uploaded documents:
# worth adding to .gitignore, the same way .env already is, so uploaded
# files never end up committed to source control.


def save_invoice_pdf(file_hash: str, pdf_bytes: bytes) -> str:
    """
    Writes pdf_bytes to local disk, keyed by file_hash (already computed
    by the caller -- this function doesn't hash anything itself, just
    stores). Returns a storage_key (models/compliance_model.py's
    CommercialInvoice.storage_key), not a URL -- resolving a storage_key
    to something servable/downloadable is a separate concern for whatever
    eventually reads this column, not this function's job.
    """
    _STORAGE_ROOT.mkdir(parents=True, exist_ok=True)
    file_path = _STORAGE_ROOT / f"{file_hash}.pdf"
    file_path.write_bytes(pdf_bytes)
    storage_key = f"local://{file_path}"
    logger.info("Saved invoice PDF to %s (%d bytes)", storage_key, len(pdf_bytes))
    return storage_key


def save_document(document_type: str, file_hash: str, file_bytes: bytes, extension: str = "pdf") -> str:
    """
    Pillar 2 (Consolidator)'s generic counterpart to save_invoice_pdf
    above -- added here because services/consolidator_engine.py and
    api/consolidator_routes.py both import this exact name, but this
    file only ever had the invoice-specific function. save_invoice_pdf
    itself is untouched; this is a new, separate function alongside it,
    not a replacement.

    Genuinely generic across document types (FIRC, self-declared
    receipts, platform screenshots), which save_invoice_pdf's hardcoded
    ".pdf" extension can't represent -- a self-declared receipt is saved
    as plain text (.txt), not a PDF. document_type is folded into the
    filename so multiple different document types sharing this one
    storage root stay visually distinguishable on disk, not just
    distinguishable by hash.
    """
    _STORAGE_ROOT.mkdir(parents=True, exist_ok=True)
    file_path = _STORAGE_ROOT / f"{document_type}_{file_hash}.{extension}"
    file_path.write_bytes(file_bytes)
    storage_key = f"local://{file_path}"
    logger.info("Saved %s document to %s (%d bytes)", document_type, storage_key, len(file_bytes))
    return storage_key