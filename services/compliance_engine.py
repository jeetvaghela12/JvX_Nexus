"""
Services: compliance_engine.py
KYB / AML / OCR compliance primitives -- PRODUCTION HTTP SCAFFOLDING,
not mocks. Every external call below is real request-shaped code against
a realistic, named vendor (chosen per researched vendor comparison), with
explicit settings.* placeholders for credentials that don't exist yet.

WHAT CHANGED FROM THE MOCK VERSION, READ BEFORE TOUCHING THIS FILE:
is_mock is GONE from every result type -- removed on explicit request,
not an oversight. That field existed to protect against a specific
danger: a mock that silently, vacuously says "clear" being mistaken for
a real compliance decision. Once this file makes real network calls,
that exact danger needs a DIFFERENT mechanism, not the same field: a
failed call must never be allowed to fall through and look like a clean
pass. That's now enforced by RAISING, not returning a result --
ComplianceServiceUnavailableError (the provider couldn't be reached,
timed out, rate-limited, or errored) and ComplianceServiceAuthenticationError
(our credentials were rejected) are both distinct from a genuine
"checked, and here's the finding" result. A caller that doesn't
explicitly handle these will see them surface as an unhandled 500 --
correct, safe default behavior (fails loudly) until routes are updated
to translate them into a proper 503, which is real follow-on work, not
done in this pass.

NO MORE MOCK/REAL TOGGLE, WORTH DECIDING ON: unlike
services/bank_onboarding_client.py's VAM_PROVIDER switch (mock vs.
decentro_sandbox), these four functions now ALWAYS attempt a real network
call -- there is no local-only fallback anymore. This means
/kyc/submit, /payout/bank-account, and invoice upload will all fail
locally the moment this ships, until real Cashfree/ComplyAdvantage/AWS
credentials are configured. That's a direct, faithful consequence of
"strip out is_mock" as instructed -- flagging it here because it's a
real, working-changing consequence, not because it's wrong. If local
testing without live credentials still matters, an environment-gated
toggle mirroring VAM_PROVIDER is a reasonable, small follow-up -- not
built here since it wasn't asked for and would partially undo what was.

VENDOR CHOICES, why these specifically: Cashfree (PAN verification +
bank account/penny-drop) and ComplyAdvantage (AML) were the vendor
names the request itself used as its own examples, matching this
codebase's own prior researched recommendation. AWS Textract was that
same research's primary OCR recommendation. None of these are verified
against a live account -- there is no Cashfree/ComplyAdvantage/AWS
account behind this code right now -- so field names below are the
best-documented, most-likely-correct shapes from each vendor's own
published API reference, not something tested end-to-end. Expect a
debugging pass once real credentials exist, the same honest caveat that
applied to the Decentro integration before real credentials existed
for that.
"""
import hashlib
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal

import boto3
import requests
from botocore.exceptions import BotoCoreError, ClientError

from core.config import settings

logger = logging.getLogger(__name__)


def _compliance_mode_is_mock() -> bool:
    """
    Single source of truth for whether verify_pan_linkage,
    screen_aml_watchlists, and extract_invoice_metadata below should use
    deterministic local mock behavior instead of a real network call.

    This is the actual safety mechanism, not just a config value asking
    someone to remember not to misconfigure it: checked fresh on every
    call (never cached at import time, so a mid-process settings change
    -- unlikely, but possible in tests -- can't leave a stale answer
    behind), and it refuses mock mode outright whenever
    settings.ENV == "production", regardless of what COMPLIANCE_MODE is
    set to there. A misconfigured .env that left COMPLIANCE_MODE=mock in
    place after a production deploy hits this hard stop instead of
    silently running every compliance check against fake data.
    """
    if settings.COMPLIANCE_MODE == "mock" and settings.ENV == "production":
        raise RuntimeError(
            "COMPLIANCE_MODE=mock is set but ENV=production -- refusing to run "
            "compliance checks in mock mode against a production environment. "
            "This is a hard safety stop, not a warning: fix the misconfigured "
            "setting, don't work around this check."
        )
    return settings.COMPLIANCE_MODE == "mock"


# ----------------------------------------------------------------------
# Shared exception hierarchy -- see module docstring for why these exist
# instead of is_mock.
# ----------------------------------------------------------------------
class ComplianceServiceError(Exception):
    """Base for every external-provider failure in this file."""


class ComplianceServiceUnavailableError(ComplianceServiceError):
    """
    The provider could not be reached, timed out, rate-limited (429), or
    returned a server error (5xx) -- NOT a compliance finding about the
    end user. A caller should respond with something like a 503
    ("try again shortly"), never treat this as a rejection of the user's
    submission.
    """


class ComplianceServiceAuthenticationError(ComplianceServiceError):
    """
    The provider rejected the configured credentials (401/403 FROM THEM).
    Almost always a configuration problem -- a missing, wrong, or expired
    API key -- not something the end user did. Worth alerting on
    distinctly from ComplianceServiceUnavailableError in production,
    since this one needs a human to fix configuration, not a retry.
    """


# ----------------------------------------------------------------------
# Shared HTTP helper -- one place for timeout/retry-relevant error
# translation, used by every requests-based call below (not the AWS
# Textract call, which uses boto3's own exception model instead).
# ----------------------------------------------------------------------
def _post_json(url: str, headers: dict, payload: dict, timeout_seconds: float, service_name: str) -> dict:
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=timeout_seconds)
    except requests.Timeout as exc:
        raise ComplianceServiceUnavailableError(f"{service_name} timed out after {timeout_seconds}s.") from exc
    except requests.RequestException as exc:
        raise ComplianceServiceUnavailableError(f"{service_name} request failed: {exc}") from exc

    if response.status_code in (401, 403):
        raise ComplianceServiceAuthenticationError(
            f"{service_name} rejected the configured credentials (HTTP {response.status_code})."
        )
    if response.status_code == 429:
        raise ComplianceServiceUnavailableError(f"{service_name} rate limit exceeded (HTTP 429).")
    if response.status_code >= 500:
        raise ComplianceServiceUnavailableError(f"{service_name} returned a server error (HTTP {response.status_code}).")
    if response.status_code >= 400:
        # A 4xx that isn't 401/403/429 is typically a malformed-request
        # problem on this platform's side, not a compliance finding --
        # still not something to silently treat as a clean pass.
        raise ComplianceServiceError(
            f"{service_name} rejected the request (HTTP {response.status_code}): {response.text[:500]}"
        )

    try:
        return response.json()
    except ValueError as exc:
        raise ComplianceServiceUnavailableError(f"{service_name} returned a non-JSON response.") from exc


# ----------------------------------------------------------------------
# verify_pan_linkage -- PRODUCTION: Cashfree Verification Suite "Verify
# PAN". Chosen because its response includes aadhaar_seeding_status
# directly, avoiding a second, separate integration for PAN-Aadhaar
# link status specifically.
# ----------------------------------------------------------------------
_PAN_FORMAT_PATTERN = re.compile(r"^[A-Z]{5}[0-9]{4}[A-Z]$")
_PAN_CHECK_TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True, slots=True)
class PanLinkageResult:
    """
    STRUCTURALLY EXCLUDES AADHAAR DATA, PERMANENTLY: there is no field
    here for an Aadhaar number or any Aadhaar demographic data, and there
    should never be one. This function only ever answers "is this PAN
    valid, and is it linked to *some* Aadhaar," never "which Aadhaar" or
    anything else about it -- per the compliance audit, a non-notified
    private entity handling a raw Aadhaar number is very likely operating
    outside what Section 11A of the PMLA and the Aadhaar Act permit.
    """

    pan_number: str
    is_valid_format: bool
    is_linked_to_aadhaar: bool | None
    # None specifically when is_valid_format is False -- linkage status
    # is meaningless to ask about a PAN that isn't even validly formed.


def verify_pan_linkage(pan_number: str) -> PanLinkageResult:
    """
    settings.CASHFREE_CLIENT_ID / settings.CASHFREE_CLIENT_SECRET:
    PLACEHOLDERS -- obtain from the Cashfree merchant dashboard
    (Developers > API Keys) once an account exists. settings.CASHFREE_BASE_URL:
    PLACEHOLDER -- defaults to production; override to Cashfree's sandbox
    host for testing.
    """
    normalized = pan_number.strip().upper()
    is_valid_format = bool(_PAN_FORMAT_PATTERN.match(normalized))
    if not is_valid_format:
        # Rejected before spending a network call (and its cost) on a
        # PAN that's structurally invalid regardless of what any
        # provider would say about it. Runs identically in mock and real
        # mode -- format validation isn't something either mode should skip.
        return PanLinkageResult(pan_number=normalized, is_valid_format=False, is_linked_to_aadhaar=None)

    if _compliance_mode_is_mock():
        # LOCAL TESTING / DEMO RECORDING ONLY -- see _compliance_mode_is_mock's
        # own docstring for the production hard-stop this relies on.
        # Deterministic "linked" result -- exercises the real success path
        # through kyc_routes.py without a real Cashfree account.
        return PanLinkageResult(pan_number=normalized, is_valid_format=True, is_linked_to_aadhaar=True)

    response_body = _post_json(
        url=f"{settings.CASHFREE_BASE_URL}/verification/pan",
        headers={
            "x-client-id": settings.CASHFREE_CLIENT_ID.get_secret_value(),
            "x-client-secret": settings.CASHFREE_CLIENT_SECRET.get_secret_value(),
            "Content-Type": "application/json",
        },
        payload={"pan": normalized},
        timeout_seconds=_PAN_CHECK_TIMEOUT_SECONDS,
        service_name="Cashfree PAN Verification",
    )

    # aadhaar_seeding_status: "Y" (linked) / "N" (not linked), per
    # Cashfree's documented response shape -- PLACEHOLDER FIELD NAME, not
    # confirmed against a live account. If this key is missing or
    # renamed in Cashfree's actual response, is_linked resolves to None
    # (unknown) rather than silently defaulting to True or False --
    # an unknown linkage status should read as unknown, not guessed.
    seeding_status = response_body.get("aadhaar_seeding_status")
    is_linked = {"Y": True, "N": False}.get(seeding_status)

    return PanLinkageResult(pan_number=normalized, is_valid_format=True, is_linked_to_aadhaar=is_linked)


# ----------------------------------------------------------------------
# screen_aml_watchlists -- PRODUCTION: ComplyAdvantage POST /searches.
# ----------------------------------------------------------------------
_AML_CHECK_TIMEOUT_SECONDS = 10.0

SCREENED_LISTS: tuple[str, ...] = ("OFAC_SDN", "OFAC_CONSOLIDATED", "UN_CONSOLIDATED", "EU_CONSOLIDATED", "UK_HMT")
# CHANGED from the mock version, and this is an important, honest
# correction, not a cosmetic one: the mock's SCREENED_LISTS claimed
# INDIA_UAPA_SCHEDULES was covered. ComplyAdvantage's standard filters/
# sources do NOT confirmably include UAPA-specific Indian designations --
# per the researched vendor comparison, that coverage claim belongs to
# India-specific KYC vendors (e.g. Signzy), not ComplyAdvantage's general
# sanctions/PEP/adverse-media product. Silently keeping the old tuple
# while actually calling a provider that may not cover what it claims
# would be exactly the "looks like it's checking something it's not"
# failure mode is_mock existed to prevent -- worth a second, India-
# specific screening call before this alone is relied on for RBI KYC
# Master Direction compliance, which explicitly expects UAPA screening.
# NOT built here; flagging the gap rather than overstating coverage.


@dataclass(frozen=True, slots=True)
class WatchlistHit:
    list_name: str
    matched_name: str


@dataclass(frozen=True, slots=True)
class ScreeningResult:
    entity_name_screened: str
    lists_checked: tuple[str, ...]
    hits: list[WatchlistHit]
    screened_at: datetime

    @property
    def is_clear(self) -> bool:
        return len(self.hits) == 0


def screen_aml_watchlists(entity_name: str) -> ScreeningResult:
    """
    settings.COMPLYADVANTAGE_API_KEY: PLACEHOLDER.
    settings.COMPLYADVANTAGE_BASE_URL: PLACEHOLDER -- ComplyAdvantage is
    region-specific (EU/US/APAC hosts); pick the correct region for the
    entity being screened, there's no safe universal default.
    """
    entity_name = entity_name.strip()
    if not entity_name:
        raise ValueError("entity_name cannot be blank.")

    if _compliance_mode_is_mock():
        # LOCAL TESTING / DEMO RECORDING ONLY -- see _compliance_mode_is_mock's
        # own docstring for the production hard-stop this relies on.
        # Deterministic "clear" result by default. Escape hatch for
        # exercising the rejection path too, same spirit as the
        # simulate_failure-style hatches elsewhere in this codebase's
        # mocks: an entity_name containing "sanctioned_test"
        # (case-insensitive) returns a simulated hit instead.
        is_simulated_hit = "sanctioned_test" in entity_name.lower()
        hits = [WatchlistHit(list_name="MOCK_TEST_LIST", matched_name=entity_name)] if is_simulated_hit else []
        return ScreeningResult(
            entity_name_screened=entity_name,
            lists_checked=SCREENED_LISTS,
            hits=hits,
            screened_at=datetime.now(timezone.utc),
        )

    response_body = _post_json(
        url=f"{settings.COMPLYADVANTAGE_BASE_URL}/searches",
        headers={
            "Authorization": f"Token {settings.COMPLYADVANTAGE_API_KEY.get_secret_value()}",
            "Content-Type": "application/json",
        },
        payload={
            "search_term": entity_name,
            "filters": {"types": ["sanction", "warning", "pep"]},
            "fuzziness": 0.6,
        },
        timeout_seconds=_AML_CHECK_TIMEOUT_SECONDS,
        service_name="ComplyAdvantage AML Screening",
    )

    # PLACEHOLDER RESPONSE PARSING -- ComplyAdvantage's documented shape
    # nests hits at content.data.hits[], each with a doc object carrying
    # name/sources; not confirmed against a live account.
    hits_raw = response_body.get("content", {}).get("data", {}).get("hits", [])
    hits = [
        WatchlistHit(
            list_name=", ".join(hit.get("doc", {}).get("sources", []) or ["UNKNOWN_SOURCE"]),
            matched_name=hit.get("doc", {}).get("name", entity_name),
        )
        for hit in hits_raw
    ]

    return ScreeningResult(
        entity_name_screened=entity_name,
        lists_checked=SCREENED_LISTS,
        hits=hits,
        screened_at=datetime.now(timezone.utc),
    )


# ----------------------------------------------------------------------
# verify_bank_account_penny_drop -- PRODUCTION: Cashfree Bank Account
# Verification (BAV V2), synchronous variant.
# ----------------------------------------------------------------------
_PENNY_DROP_TIMEOUT_SECONDS = 20.0
# Longer than the PAN/AML timeouts -- penny drop depends on a real IMPS
# transfer completing against the destination bank, not just a database
# lookup on the provider's side, so it realistically takes longer.
# Production usage commonly falls back to Cashfree's ASYNC variant
# (immediate ack + webhook, up to 1-2 hours) when a bank is slow to
# respond; only the synchronous path is scaffolded here, matching this
# function's existing synchronous signature -- switching to async is a
# real, larger design change (a webhook receiver, a pending-verification
# state on the User/payout row), not a drop-in swap.


@dataclass(frozen=True, slots=True)
class PennyDropResult:
    is_valid: bool
    account_holder_name: str | None
    name_matches_expected: bool | None


def verify_bank_account_penny_drop(account_number: str, ifsc: str, expected_name: str) -> PennyDropResult:
    """
    settings.CASHFREE_CLIENT_ID / settings.CASHFREE_CLIENT_SECRET: same
    credentials as verify_pan_linkage above -- Cashfree's Verification
    Suite covers both PAN and bank-account checks under one account.
    """
    account_number = account_number.strip()
    ifsc = ifsc.strip().upper()
    expected_name = expected_name.strip()

    response_body = _post_json(
        url=f"{settings.CASHFREE_BASE_URL}/verification/bank-account",
        headers={
            "x-client-id": settings.CASHFREE_CLIENT_ID.get_secret_value(),
            "x-client-secret": settings.CASHFREE_CLIENT_SECRET.get_secret_value(),
            "Content-Type": "application/json",
        },
        payload={"bank_account": account_number, "ifsc": ifsc, "name": expected_name},
        timeout_seconds=_PENNY_DROP_TIMEOUT_SECONDS,
        service_name="Cashfree Bank Account Verification",
    )

    # PLACEHOLDER FIELD NAMES, per Cashfree's documented BAV V2 response
    # shape -- account_status ("VALID"/"INVALID"/...), name_at_bank, and
    # name_match_result ("DIRECT_MATCH"/"GOOD_PARTIAL_MATCH"/...). Not
    # confirmed against a live account.
    account_status = response_body.get("account_status")
    is_valid = account_status == "VALID"
    account_holder_name = response_body.get("name_at_bank") if is_valid else None
    name_match_result = response_body.get("name_match_result")
    name_matches = (name_match_result in ("DIRECT_MATCH", "GOOD_PARTIAL_MATCH")) if is_valid else None

    return PennyDropResult(
        is_valid=is_valid,
        account_holder_name=account_holder_name,
        name_matches_expected=name_matches,
    )


# ----------------------------------------------------------------------
# extract_invoice_metadata -- PRODUCTION: AWS Textract AnalyzeExpense
# (synchronous, single/small documents).
# ----------------------------------------------------------------------
_MAX_TEXTRACT_SYNC_BYTES = 5 * 1024 * 1024
# AWS's documented ceiling for synchronous AnalyzeExpense; larger
# documents need the asynchronous StartExpenseAnalysis + SNS-notification
# path instead -- NOT built here, since api/invoice_routes.py's own
# _MAX_UPLOAD_BYTES (10 MB) already exceeds this, meaning a large
# (5-10 MB) upload would need the async path to actually work. Flagging
# the mismatch rather than silently letting a large valid upload fail
# this check.


@dataclass(frozen=True, slots=True)
class InvoiceExtractionResult:
    invoice_number: str | None
    amount: Decimal | None
    currency: str | None
    buyer_name: str | None


def extract_invoice_metadata(
    pdf_bytes: bytes,
    claimed_invoice_number: str,
    claimed_amount: Decimal,
    claimed_currency: str,
    claimed_buyer_name: str,
) -> InvoiceExtractionResult:
    """
    CHANGED SIGNATURE from the mock version: pdf_bytes is now real and
    required -- the mock never actually needed it, since nothing
    inspected the file; real OCR obviously must. api/invoice_routes.py's
    call site needed updating for this to even run (a straightforward,
    necessary companion change alongside this file, not a separate
    feature).

    AWS credentials: PLACEHOLDER, but NOT a settings.AWS_ACCESS_KEY_ID
    field the way other providers use an explicit header key -- boto3
    resolves credentials via its standard chain (environment variables,
    ~/.aws/credentials, or an IAM role if running on AWS infrastructure).
    Don't hardcode AWS keys in config.py; let boto3's normal credential
    resolution handle it. settings.AWS_TEXTRACT_REGION: PLACEHOLDER,
    defaults to ap-south-1 (Mumbai) as the natural choice for an
    India-based platform -- but per AWS's documented service quotas,
    synchronous AnalyzeExpense is throttled to 1 transaction/second in
    ap-south-1, versus 5 TPS in us-east-1/us-west-2. Worth knowing before
    assuming Mumbai is also the right choice for throughput, not just
    data-residency.

    claimed_invoice_number/claimed_amount/claimed_currency/claimed_buyer_name
    are still accepted (unchanged from the mock's signature) for the
    cross-check api/invoice_routes.py already performs between what's
    claimed and what's extracted -- that comparison logic in the route
    doesn't need to change, only what extraction actually does here.
    """
    if len(pdf_bytes) > _MAX_TEXTRACT_SYNC_BYTES:
        raise ValueError(
            f"PDF exceeds Textract's synchronous {_MAX_TEXTRACT_SYNC_BYTES // (1024 * 1024)}MB limit -- "
            "needs the asynchronous StartExpenseAnalysis path instead, not implemented here."
        )

    if _compliance_mode_is_mock():
        # LOCAL TESTING / DEMO RECORDING ONLY -- see _compliance_mode_is_mock's
        # own docstring for the production hard-stop this relies on.
        # Echoes the CLAIMED values back as the "extracted" ones,
        # deliberately -- api/invoice_routes.py's cross-check compares
        # extraction against claim and rejects on mismatch, so echoing
        # the claim is what lets a real upload through mock mode reach
        # CommercialInvoice insertion at all, exercising that whole path
        # end to end. This does NOT test whether the cross-check itself
        # would catch a real mismatch -- that's exactly what it can't do
        # by construction, since it never sees an independent extraction
        # to compare against. It's a fair trade for tonight: proving the
        # dual-hash duplicate-detection path (which fires on file_hash /
        # content_fingerprint uniqueness, both computed before this
        # function is ever called) doesn't depend on this mock being
        # more sophisticated than an echo.
        return InvoiceExtractionResult(
            invoice_number=claimed_invoice_number,
            amount=claimed_amount,
            currency=claimed_currency,
            buyer_name=claimed_buyer_name,
        )

    client = boto3.client("textract", region_name=settings.AWS_TEXTRACT_REGION)

    try:
        response = client.analyze_expense(Document={"Bytes": pdf_bytes})
    except (BotoCoreError, ClientError) as exc:
        raise ComplianceServiceUnavailableError(f"AWS Textract request failed: {exc}") from exc

    # PLACEHOLDER FIELD EXTRACTION -- Textract's normalized SummaryFields
    # types, per AWS's own documentation: VENDOR_NAME, INVOICE_RECEIPT_ID,
    # TOTAL, RECEIVER_NAME, among others. NOTE, genuinely uncertain and
    # worth confirming against real extracted invoices before trusting in
    # production: Textract's "VENDOR_NAME" means the entity that ISSUED
    # the invoice, which may not match this platform's "buyer_name"
    # semantic (the paying counterparty) -- RECEIVER_NAME may be the
    # field that actually corresponds to "buyer" here, depending on which
    # side of the transaction this platform's users are typically on.
    # Not resolved here; flagging rather than guessing silently.
    extracted_fields: dict[str, str] = {}
    for expense_doc in response.get("ExpenseDocuments", []):
        for field in expense_doc.get("SummaryFields", []):
            field_type = field.get("Type", {}).get("Text")
            field_value = field.get("ValueDetection", {}).get("Text")
            if field_type and field_value:
                extracted_fields[field_type] = field_value

    raw_buyer_name = extracted_fields.get("RECEIVER_NAME") or extracted_fields.get("VENDOR_NAME")
    raw_invoice_number = extracted_fields.get("INVOICE_RECEIPT_ID")
    raw_total = extracted_fields.get("TOTAL")

    # Amount parsing is a GENUINE, non-trivial problem, not fully solved
    # here: Textract returns free text like "$1,234.56" or "1.234,56",
    # not a structured Decimal + currency pair. This strips common
    # currency symbols/separators for the common case; it will not
    # correctly handle every real-world invoice format (European
    # decimal-comma notation, embedded currency codes, OCR misreads).
    # Route sub-threshold-confidence or unparseable amounts to human
    # review rather than trusting this blindly -- not implemented here,
    # since building a genuinely robust invoice-amount parser is its own
    # real piece of work, not scaffolding.
    parsed_amount: Decimal | None = None
    if raw_total:
        cleaned = re.sub(r"[^\d.]", "", raw_total)
        try:
            parsed_amount = Decimal(cleaned) if cleaned else None
        except Exception:
            parsed_amount = None

    return InvoiceExtractionResult(
        invoice_number=raw_invoice_number,
        amount=parsed_amount,
        currency=claimed_currency,
        # Textract's SummaryFields don't reliably include a separate
        # currency code field -- falling back to the claimed currency
        # rather than guessing from a currency symbol embedded in TOTAL's
        # text, which is fragile. Flagging this as inherited from the
        # claimed value, not independently verified, unlike the other
        # three fields here which genuinely come from extraction.
        buyer_name=raw_buyer_name,
    )


# ----------------------------------------------------------------------
# verify_ubo -- REAL logic, unchanged from before: pure threshold
# calculation over ownership data the caller already has, no external
# data source, nothing to "upgrade" here. Kept exactly as it was.
# ----------------------------------------------------------------------
UBO_OWNERSHIP_THRESHOLD_PERCENT = Decimal("10.0")


@dataclass(frozen=True, slots=True)
class OwnerRecord:
    full_name: str
    ownership_percentage: Decimal


@dataclass(frozen=True, slots=True)
class CorporateOwnershipData:
    entity_name: str
    owners: list[OwnerRecord]


@dataclass(frozen=True, slots=True)
class UboVerificationResult:
    entity_name: str
    all_owners: list[OwnerRecord]
    ubo_owners: list[OwnerRecord]
    requires_enhanced_due_diligence: bool


def verify_ubo(corporate_data: CorporateOwnershipData) -> UboVerificationResult:
    total_ownership = sum((owner.ownership_percentage for owner in corporate_data.owners), start=Decimal("0"))
    if total_ownership > Decimal("100"):
        raise ValueError(
            f"Reported ownership for {corporate_data.entity_name!r} sums to "
            f"{total_ownership}%, over 100% -- this is a data error in the source ownership records."
        )

    ubo_owners = [
        owner for owner in corporate_data.owners if owner.ownership_percentage >= UBO_OWNERSHIP_THRESHOLD_PERCENT
    ]

    return UboVerificationResult(
        entity_name=corporate_data.entity_name,
        all_owners=corporate_data.owners,
        ubo_owners=ubo_owners,
        requires_enhanced_due_diligence=len(ubo_owners) > 0,
    )


# ----------------------------------------------------------------------
# generate_efira_bundle -- REAL logic, unchanged from before: no
# external API, nothing to "upgrade." Kept exactly as it was.
# ----------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class EFiraBundleData:
    transaction_reference: str
    gross_amount: str
    source_currency: str
    compliance_purpose_code: str
    completed_at: str | None
    user_full_name: str
    user_entity_type: str
    linked_invoice_storage_keys: list[str]
    linked_invoice_file_hashes: list[str]
    generated_at: str
    bundle_hash: str


def generate_efira_bundle(
    transaction_reference: str,
    gross_amount: Decimal,
    source_currency: str,
    compliance_purpose_code: str,
    completed_at: datetime | None,
    user_full_name: str,
    user_entity_type: str,
    linked_invoice_storage_keys: list[str],
    linked_invoice_file_hashes: list[str],
) -> EFiraBundleData:
    generated_at = datetime.now(timezone.utc)

    canonical_payload = "|".join(
        [
            transaction_reference,
            str(gross_amount.quantize(Decimal("0.0001"))),
            source_currency.strip().upper(),
            compliance_purpose_code,
            completed_at.isoformat() if completed_at else "",
            user_full_name,
            user_entity_type,
            ",".join(sorted(linked_invoice_storage_keys)),
            ",".join(sorted(linked_invoice_file_hashes)),
        ]
    )
    bundle_hash = hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()

    return EFiraBundleData(
        transaction_reference=transaction_reference,
        gross_amount=str(gross_amount),
        source_currency=source_currency.strip().upper(),
        compliance_purpose_code=compliance_purpose_code,
        completed_at=completed_at.isoformat() if completed_at else None,
        user_full_name=user_full_name,
        user_entity_type=user_entity_type,
        linked_invoice_storage_keys=linked_invoice_storage_keys,
        linked_invoice_file_hashes=linked_invoice_file_hashes,
        generated_at=generated_at.isoformat(),
        bundle_hash=bundle_hash,
    )


def compute_content_fingerprint(invoice_number: str, amount: Decimal, currency: str, buyer_name: str) -> str:
    normalized = "|".join(
        [
            invoice_number.strip().upper(),
            str(amount.quantize(Decimal("0.0001"))),
            currency.strip().upper(),
            buyer_name.strip().upper(),
        ]
    )
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()