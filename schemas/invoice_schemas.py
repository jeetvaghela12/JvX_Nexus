"""
Schemas: invoice_schemas.py
Response shapes for invoice upload -- there is deliberately no Pydantic
request model here. The upload endpoint is multipart/form-data (a file
plus form fields), which FastAPI handles via File()/Form() parameters
directly on the route rather than a single JSON request body Pydantic
model -- see api/invoice_routes.py.
"""
from decimal import Decimal

from pydantic import BaseModel


class InvoiceUploadResponse(BaseModel):
    id: int
    invoice_number: str
    amount: Decimal
    currency: str
    buyer_name: str | None
    status: str
    message: str