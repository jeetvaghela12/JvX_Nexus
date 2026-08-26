"""
Schemas: kyc_schemas.py
Input validation for the KYC document submission flow.

NEW FILE, NOT ADDED TO auth_schemas.py: that file's own module docstring
scopes it to "the authentication flow (signup, login, token issuance)" --
KYC submission is a distinct concern (compliance/onboarding data, not
credentials), so it gets its own schema file rather than stretching
auth_schemas.py's scope. Same "flag the folder/file expansion" pattern as
schemas/ itself, compliance_model.py, and auth_model.py earlier.

VALIDATION SCOPE NOTE: pan_number's format is deliberately NOT re-validated
here -- services/compliance_engine.py's verify_pan_linkage already does
that (and is the actual source of truth the route rejects on), so
duplicating the check here would just be two places that could drift out
of sync. gst_number and iec_code ARE format-validated here, because
neither has a corresponding compliance_engine function yet -- this is the
only check either one gets right now. To be explicit about what that
means: this confirms the STRING is shaped like a real GST/IEC, not that
it's an actually-active registration. Verifying that for real needs MCA/
GST-network/DGFT lookups this codebase doesn't have yet -- flagging the
gap rather than implying more assurance than this schema actually provides.
"""
import re
from decimal import Decimal

from pydantic import BaseModel, Field, field_validator

_GST_PATTERN = re.compile(r"^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$")
# Standard 15-character GSTIN format: 2-digit state code + 10-char PAN
# (5 letters, 4 digits, 1 letter) + 1 alphanumeric entity code + literal
# 'Z' + 1 alphanumeric checksum character.

_IEC_LENGTH = 10
# IEC format is intentionally NOT pattern-matched as strictly as PAN/GST:
# DGFT's older IEC format was 10 numeric digits, but IECs issued since the
# 2018 policy change reuse the holder's PAN (10 alphanumeric characters,
# same shape as a PAN) -- a rigid single pattern would incorrectly reject
# one of the two valid formats still in circulation. Length + alphanumeric
# is checked; the internal letter/digit arrangement isn't.


class OwnerInput(BaseModel):
    """One entry in KycSubmissionRequest.owners -- feeds directly into services.compliance_engine.OwnerRecord."""

    full_name: str = Field(min_length=1, max_length=255)
    ownership_percentage: Decimal = Field(ge=0, le=100)


class KycSubmissionRequest(BaseModel):
    pan_number: str = Field(min_length=1, max_length=20)
    gst_number: str | None = None
    # Optional, deliberately: GST registration is only legally mandatory
    # above Rs 20 lakh annual turnover (Rs 10 lakh in special-category
    # states) -- including for export of services, per Notification
    # 10/2017-IGST as amended by 10/2019. It is NOT mandatory purely
    # because a client is foreign. A small freelancer genuinely,
    # compliantly may have no GST number; requiring one here would block
    # legitimate users at onboarding rather than reflect any real rule.
    iec_code: str
    entity_name: str = Field(min_length=1, max_length=255)
    owners: list[OwnerInput]

    @field_validator("pan_number", "gst_number", "iec_code")
    @classmethod
    def _normalize(cls, value: str | None) -> str | None:
        """Strip + uppercase before any further validation or storage --
        same normalization verify_pan_linkage already applies to
        pan_number internally, applied consistently to all three
        identifiers here. None-safe specifically for gst_number, now
        optional -- pan_number and iec_code remain required at the field
        level, so Pydantic rejects a null value for either before this
        validator ever runs on them; only gst_number can genuinely arrive
        here as None."""
        if value is None:
            return None
        return value.strip().upper()

    @field_validator("gst_number")
    @classmethod
    def _validate_gst_format(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _GST_PATTERN.match(value):
            raise ValueError("gst_number is not a validly formatted 15-character GSTIN.")
        return value

    @field_validator("iec_code")
    @classmethod
    def _validate_iec_format(cls, value: str) -> str:
        if len(value) != _IEC_LENGTH or not value.isalnum():
            raise ValueError(f"iec_code must be exactly {_IEC_LENGTH} alphanumeric characters.")
        return value


class KycVerificationRequest(BaseModel):
    """
    Input for the mock POST /kyc/verify -- standing in for a real bank's
    compliance verification callback. user_id is a plain int here, not a
    JWT-derived identity: the caller of this endpoint is the bank/admin
    tooling, verifying someone ELSE's KYC, not authenticating as the user
    being verified.
    """

    user_id: int
    approved: bool = True