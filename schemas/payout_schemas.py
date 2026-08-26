"""
Schemas: payout_schemas.py
Input/output validation for managing a user's outbound payout methods
(bank account, digital wallet) and their preferred_payout_route.
"""
import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator

_IFSC_PATTERN = re.compile(r"^[A-Z]{4}0[A-Z0-9]{6}$")
# 4-letter bank code + literal 0 (reserved) + 6-character branch code --
# the real, complete IFSC format, same precision as PAN/GST elsewhere in
# this codebase.


class BankAccountRequest(BaseModel):
    account_number: str = Field(min_length=1, max_length=30)
    # NOT format-validated beyond length/non-blank: unlike PAN/GST/IFSC,
    # Indian bank account numbers have no single universal format --
    # length and character rules vary by issuing bank (roughly 9-18
    # digits in practice, occasionally alphanumeric). A rigid pattern
    # here risks rejecting real, valid account numbers; the actual
    # verification of whether this number is real happens via the
    # penny-drop check in the route, not a format regex.
    ifsc: str = Field(min_length=11, max_length=11)

    @field_validator("account_number")
    @classmethod
    def _normalize_account_number(cls, value: str) -> str:
        return value.strip()

    @field_validator("ifsc")
    @classmethod
    def _validate_ifsc(cls, value: str) -> str:
        normalized = value.strip().upper()
        if not _IFSC_PATTERN.match(normalized):
            raise ValueError("ifsc is not a validly formatted 11-character IFSC code.")
        return normalized


class WalletRequest(BaseModel):
    wallet_address: str = Field(min_length=1, max_length=128)

    @field_validator("wallet_address")
    @classmethod
    def _normalize_wallet_address(cls, value: str) -> str:
        return value.strip()


class PreferredRouteRequest(BaseModel):
    preferred_payout_route: Literal["FIAT", "CBDC"]


class PayoutMethodResponse(BaseModel):
    """Shared response shape returned by all three payout routes, so a caller always sees the full, current picture after any single change."""

    has_bank_account: bool
    masked_account_number: str | None = None
    # Last 4 digits only (e.g. "••••1234") -- enough for a user to
    # visually confirm which account is on file without the response ever
    # carrying the full number back out, even though it's encrypted at
    # rest, matching the same minimal-exposure choice made for KYC data
    # in api/kyc_routes.py.
    has_digital_wallet: bool
    preferred_payout_route: str | None
    message: str