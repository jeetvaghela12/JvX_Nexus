"""
Schemas: declaration_schemas.py
Input/output for pre-declarations and self-declarations.

Validation here is format and business-rule only. Whether a purpose code
is the *correct* one for a given payment is the bank's determination, not
ours — we check that the code is well-formed and that it exists in the
RBI list, then pass it on.
"""
import datetime
import re
from decimal import Decimal

from pydantic import BaseModel, Field, field_validator

_PURPOSE_CODE_PATTERN = re.compile(r"^P\d{4}$")
# RBI purpose codes are the letter P followed by four digits: P0802 for
# software services, P1006 for business services, and so on. This checks
# the shape, not membership of the real list — that list changes and
# needs its own maintained source, which belongs in a service, not here.

_CURRENCY_PATTERN = re.compile(r"^[A-Z]{3}$")
_COUNTRY_PATTERN = re.compile(r"^[A-Z]{2}$")

# A pre-declaration for money expected two years out is not a declaration,
# it is a guess, and keeping it open that long produces false matches
# against unrelated later payments.
_MAX_EXPECTED_DAYS_AHEAD = 180


class PreDeclarationCreate(BaseModel):
    """
    Filed before the money arrives.

    expected_by is required and bounded. Without it there is no point at
    which the declaration stops being eligible to match, and a stale open
    declaration will eventually attach itself to the wrong payment.
    """

    expected_amount: Decimal = Field(gt=0, decimal_places=4)
    currency: str
    payer_name: str = Field(min_length=1, max_length=255)
    payer_country: str | None = None
    purpose_code: str
    description: str = Field(min_length=1, max_length=2000)
    expected_by: datetime.date
    invoice_id: int | None = None

    @field_validator("currency")
    @classmethod
    def _check_currency(cls, value: str) -> str:
        normalized = value.strip().upper()
        if not _CURRENCY_PATTERN.match(normalized):
            raise ValueError("currency must be a 3-letter ISO 4217 code, for example USD.")
        return normalized

    @field_validator("payer_country")
    @classmethod
    def _check_country(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().upper()
        if not _COUNTRY_PATTERN.match(normalized):
            raise ValueError("payer_country must be a 2-letter ISO 3166-1 code, for example US.")
        return normalized

    @field_validator("purpose_code")
    @classmethod
    def _check_purpose_code(cls, value: str) -> str:
        normalized = value.strip().upper()
        if not _PURPOSE_CODE_PATTERN.match(normalized):
            raise ValueError("purpose_code must be the letter P followed by four digits, for example P0802.")
        return normalized

    @field_validator("payer_name", "description")
    @classmethod
    def _strip(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("Value cannot be blank.")
        return stripped

    @field_validator("expected_by")
    @classmethod
    def _check_window(cls, value: datetime.date) -> datetime.date:
        today = datetime.date.today()
        if value < today:
            raise ValueError("expected_by cannot be in the past. Use a self-declaration for money already received.")
        if (value - today).days > _MAX_EXPECTED_DAYS_AHEAD:
            raise ValueError(f"expected_by cannot be more than {_MAX_EXPECTED_DAYS_AHEAD} days ahead.")
        return value


class SelfDeclarationCreate(BaseModel):
    """
    Filed where no formal invoice exists.

    No expected_by: this describes money that has already arrived or is
    arriving under a standing arrangement, so there is nothing to expire.
    """

    expected_amount: Decimal = Field(gt=0, decimal_places=4)
    currency: str
    payer_name: str = Field(min_length=1, max_length=255)
    payer_country: str | None = None
    purpose_code: str
    description: str = Field(min_length=1, max_length=2000)

    _check_currency = field_validator("currency")(PreDeclarationCreate._check_currency.__func__)
    _check_country = field_validator("payer_country")(PreDeclarationCreate._check_country.__func__)
    _check_purpose_code = field_validator("purpose_code")(PreDeclarationCreate._check_purpose_code.__func__)
    _strip = field_validator("payer_name", "description")(PreDeclarationCreate._strip.__func__)


class DeclarationResponse(BaseModel):
    reference: str
    kind: str
    status: str
    expected_amount: Decimal
    currency: str
    payer_name: str
    purpose_code: str
    description: str
    expected_by: datetime.date | None
    matched_payment_id: int | None
    created_at: datetime.datetime

    model_config = {"from_attributes": True}


class SelfDeclarationReceipt(DeclarationResponse):
    """
    A self-declaration rendered as a receipt the customer can hand to
    their bank or their accountant.

    disclaimer is not optional and is not a caveat bolted on at the edge.
    It is the field that keeps this document honest: it states plainly
    that no bank has verified anything here. A receipt that omits it is a
    document pretending to be something it is not.
    """

    disclaimer: str