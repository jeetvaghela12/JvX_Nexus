"""
Schemas: compliance_schemas.py
Input/output for e-FIRA compliance bundle generation and retrieval.
"""
from decimal import Decimal

from pydantic import BaseModel


class EFiraGenerateRequest(BaseModel):
    transaction_id: int
    invoice_ids: list[int] = []
    # Explicit, caller-supplied list, not auto-matched -- see
    # models/compliance_model.py's note on CommercialInvoice.related_
    # transaction_id: automatically matching invoices to a transaction is
    # a separate, not-yet-built feature. Empty list is valid -- a bundle
    # can legitimately be generated with no linked invoices.


class EFiraBundleResponse(BaseModel):
    id: int
    bundle_hash: str
    bundle: dict
    message: str = (
        "e-FIRA compliance bundle generated. This is the data package supplied TO the "
        "AD-1 bank -- only the bank can issue the actual e-FIRA/FIRA/FIRC document."
    )