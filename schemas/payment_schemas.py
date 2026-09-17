"""
Schemas: payment_schemas.py
Read-only shapes for inbound payments.

There is no create schema here on purpose. Payments are never created by
a customer request — they arrive from the bank's webhook, which has its
own verified shape in api/b2b_routes.py. If a POST /payments ever appears
in this file, something has gone wrong with the architecture.
"""
import datetime
from decimal import Decimal

from pydantic import BaseModel


class PaymentResponse(BaseModel):
    bank_reference: str
    status: str
    amount: Decimal
    currency: str
    payer_name: str | None
    payer_country: str | None
    credited_amount_inr: Decimal | None
    exchange_rate: Decimal | None
    purpose_code: str | None
    fira_reference: str | None
    fira_issued_at: datetime.datetime | None
    declaration_reference: str | None
    bank_remark: str | None
    received_at: datetime.datetime

    model_config = {"from_attributes": True}


class PaymentSummary(BaseModel):
    """
    Dashboard header figures.

    received_count and credited_count are kept separate rather than
    reported as one total. "Nine payments arrived, seven have been
    credited" answers the question a customer actually has; a single total
    of nine does not.
    """

    total_received_count: int
    total_credited_count: int
    on_hold_count: int
    credited_total_inr: Decimal