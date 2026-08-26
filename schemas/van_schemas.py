"""
Schemas: van_schemas.py
Input/output for requesting and listing country-specific Virtual Account
Numbers (VANs) -- decoupled from KYC submission, see api/van_routes.py.
"""
import re

from pydantic import BaseModel, field_validator

_COUNTRY_CODE_PATTERN = re.compile(r"^[A-Z]{2}$")
# ISO 3166-1 alpha-2 SHAPE only (exactly 2 letters) -- not validated
# against the real, finite list of ~250 actual country codes, which
# changes over time and would need its own maintained source of truth.
# This is a schema-level format check, not a claim that any 2-letter
# code passed here is guaranteed to be issuable -- that's a business/
# provider-capability question the route and provider answer separately.


class VanRequest(BaseModel):
    country_code: str

    @field_validator("country_code")
    @classmethod
    def _validate_country_code(cls, value: str) -> str:
        normalized = value.strip().upper()
        if not _COUNTRY_CODE_PATTERN.match(normalized):
            raise ValueError("country_code must be exactly 2 letters (ISO 3166-1 alpha-2, e.g. 'IN', 'US', 'GB').")
        return normalized


class VanResponse(BaseModel):
    country_code: str
    masked_account_number: str
    # Last 4 characters only -- same minimal-exposure choice made for
    # bank account numbers in schemas/payout_schemas.py, applied here too.
    status: str
    provider_name: str