"""
Services: bank_onboarding_client.py
The VirtualAccountProvider abstraction: swaps between MOCK and real
sandbox/production VAM issuance behind one config value
(settings.VAM_PROVIDER), same "dibba" pattern as core/config.py's
CLOUD_PROVIDER. Neither api/kyc_routes.py nor api/b2b_routes.py ever
import DecentroVirtualAccountProvider directly -- they call
get_virtual_account_provider() and use the interface, so adding a second
real provider later doesn't touch either route file.

CONFIDENCE LEVEL, READ BEFORE DEBUGGING: everything about
DecentroVirtualAccountProvider below is grounded in Decentro's own current
API reference (fetched directly, not recalled from memory or a search
summary) -- the endpoint URL, the request body fields, the client_id/
client_secret header auth, and the documented error_* response keys are
all confirmed. What is NOT confirmed: the exact shape of a successful
response body. Decentro's reference page renders that as an interactive
example picker rather than static text this tool can read, so the field
name used to extract the issued virtual account number below is an
educated inference from Decentro's own terminology elsewhere on the same
page, not a verified fact. This is also, structurally, the first API
integration in this whole codebase that has never been exercised against
a live call -- everything else this session was verified by running real
code against real libraries; this can only be verified by actually
calling Decentro's sandbox, which needs your real credentials and isn't
something achievable from here. Expect one debugging pass; the error
logging below is deliberately verbose specifically so that pass is fast.
"""
import hmac
import logging
import uuid
from dataclasses import dataclass
from typing import Protocol

import requests

from core.config import settings
from models.user_model import User

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class VanIssuanceResult:
    success: bool
    virtual_account_number: str | None
    routing_details: dict | None
    # Shape matches VirtualAccount.routing_details (JSONB) -- varies by
    # country, e.g. {"ifsc": "..."} for IN, {"routing_number": "...",
    # "swift": "..."} for US. None when success is False.
    provider_reference: str | None
    error_message: str | None
    raw_provider_response: dict | None
    # raw_provider_response is deliberately returned, not just logged --
    # during this first integration pass, being able to inspect exactly
    # what Decentro sent back (in a debugger, a test script, wherever) is
    # more valuable than assuming the parsed fields above are already
    # correct.


class VirtualAccountProvider(Protocol):
    def issue_virtual_account(self, user: User, country_code: str) -> VanIssuanceResult: ...
    def verify_webhook_signature(self, headers: dict[str, str], raw_body: bytes) -> bool: ...


class MockVirtualAccountProvider:
    """
    What every signup used to get by default before any real provider
    existed: nothing, until a real VAN request came in through
    api/van_routes.py. This mock is a deterministic, clearly-fake VAN and
    country-appropriate routing detail shape, so local testing with
    VAM_PROVIDER=mock (the default) can exercise any country -- unlike
    the real Decentro provider below, which genuinely can only serve one.
    """

    _MOCK_ROUTING_BY_COUNTRY: dict[str, dict] = {
        "IN": {"ifsc": "MOCK0000001"},
        "US": {"routing_number": "000000000", "swift": "MOCKUS00XXX"},
        "GB": {"sort_code": "00-00-00"},
    }

    def issue_virtual_account(self, user: User, country_code: str) -> VanIssuanceResult:
        fake_van = f"MOCK-VAN-{country_code}-{user.id:06d}"
        routing = self._MOCK_ROUTING_BY_COUNTRY.get(
            country_code,
            {"note": f"no mock routing shape defined for country_code={country_code!r}"},
        )
        return VanIssuanceResult(
            success=True,
            virtual_account_number=fake_van,
            routing_details=routing,
            provider_reference=f"mock-ref-{user.id}",
            error_message=None,
            raw_provider_response=None,
        )

    def verify_webhook_signature(self, headers: dict[str, str], raw_body: bytes) -> bool:
        # Matches the non-empty-only check api/b2b_routes.py already had
        # for the generic webhook before this file existed -- unchanged
        # behavior, just relocated behind the interface.
        return bool(headers.get("x-signature", "").strip())


class DecentroVirtualAccountProvider:
    """See this module's docstring for what's confirmed vs. best-effort here."""

    _CREATE_VA_PATH = "/v3/banking/account/virtual"

    def __init__(self) -> None:
        if (
            settings.DECENTRO_CLIENT_ID is None
            or settings.DECENTRO_CLIENT_SECRET is None
            or settings.DECENTRO_CONSUMER_URN is None
            or settings.DECENTRO_CORE_BANKING_MODULE_SECRET is None
            or settings.DECENTRO_PAYMENTS_MODULE_SECRET is None
            or settings.DECENTRO_PROVIDER_SECRET is None
        ):
            # Defensive second check -- core/config.py's own validator
            # should already have refused to start the app in this state.
            raise RuntimeError(
                "DecentroVirtualAccountProvider requires DECENTRO_CLIENT_ID, "
                "DECENTRO_CLIENT_SECRET, DECENTRO_CONSUMER_URN, "
                "DECENTRO_CORE_BANKING_MODULE_SECRET, DECENTRO_PAYMENTS_MODULE_SECRET, "
                "and DECENTRO_PROVIDER_SECRET to be set."
            )
        # .strip() on every one of these: a stray trailing space or
        # newline from copy-pasting a value out of an email/table is a
        # genuinely common, easy-to-miss cause of an authentication
        # failure that looks identical to a wrong value -- cheap
        # insurance against that regardless of which secret combination
        # turns out to be the actual fix.
        self._base_url = settings.DECENTRO_BASE_URL.strip()
        self._client_id = settings.DECENTRO_CLIENT_ID.get_secret_value().strip()
        self._client_secret = settings.DECENTRO_CLIENT_SECRET.get_secret_value().strip()
        self._consumer_urn = settings.DECENTRO_CONSUMER_URN.strip()
        self._core_banking_module_secret = settings.DECENTRO_CORE_BANKING_MODULE_SECRET.get_secret_value().strip()
        self._payments_module_secret = settings.DECENTRO_PAYMENTS_MODULE_SECRET.get_secret_value().strip()
        self._provider_secret = settings.DECENTRO_PROVIDER_SECRET.get_secret_value().strip()

    def issue_virtual_account(self, user: User, country_code: str) -> VanIssuanceResult:
        if country_code != "IN":
            # Honest rejection, not a silent wrong answer: Decentro's v3
            # stack issues Indian NEFT/RTGS/IMPS virtual accounts
            # specifically -- confirmed against their own API reference,
            # not an assumption. It cannot issue a US, GB, or any other
            # country's account. A real cross-border-capable provider
            # (Airwallex was the candidate identified when sandbox access
            # was researched) would need to be integrated separately for
            # non-IN requests -- this isn't that yet.
            return VanIssuanceResult(
                success=False,
                virtual_account_number=None,
                routing_details=None,
                provider_reference=None,
                error_message=f"Decentro does not support country_code={country_code!r} -- only 'IN' is served by this integration.",
                raw_provider_response=None,
            )

        reference_id = f"jvx-kyc-{user.id}-{uuid.uuid4().hex[:8]}"
        payload = {
            "reference_id": reference_id,
            "consumer_urn": self._consumer_urn,
            "name": user.full_name,
            "customer_va_identifier": str(user.id),
            # custom_va_number deliberately omitted: letting Decentro
            # generate the VA number rather than requesting a specific
            # suffix, since nothing in this platform's design needs one.
        }
        headers = {
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            # CURRENT HYPOTHESIS: Payments, not Core Banking -- Core
            # Banking's module_secret was tried first (matching the
            # /v3/banking/... URL path) and still returned
            # error_authentication_failed. Switched to Payments because
            # Decentro's own docs sidebar files this exact endpoint under
            # Payments -> Virtual Account Collections v3, not under a
            # Core Banking heading -- the URL naming and Decentro's own
            # categorization disagree, and this is the guess that hasn't
            # failed yet. To try Core Banking's instead, change the line
            # below to self._core_banking_module_secret.
            "module_secret": self._payments_module_secret,
            "provider_secret": self._provider_secret,
            "Content-Type": "application/json",
        }

        try:
            response = requests.post(
                f"{self._base_url}{self._CREATE_VA_PATH}",
                json=payload,
                headers=headers,
                timeout=15,
            )
        except requests.RequestException as exc:
            logger.exception("Decentro VA creation request failed (user_id=%s)", user.id)
            return VanIssuanceResult(
                success=False,
                virtual_account_number=None,
                routing_details=None,
                provider_reference=reference_id,
                error_message=f"Request to Decentro failed before a response was received: {exc}",
                raw_provider_response=None,
            )

        try:
            response_body = response.json()
        except ValueError:
            response_body = {"_unparseable_body": response.text}

        if response.status_code not in (200, 201):
            logger.error(
                "Decentro VA creation returned HTTP %s for user_id=%s: %s",
                response.status_code,
                user.id,
                response_body,
            )
            return VanIssuanceResult(
                success=False,
                virtual_account_number=None,
                routing_details=None,
                provider_reference=reference_id,
                error_message=(
                    response_body.get("message")
                    or response_body.get("response_key")
                    or f"Decentro returned HTTP {response.status_code}"
                ),
                raw_provider_response=response_body,
            )

        # BEST-EFFORT extraction -- see module docstring. Trying the most
        # likely nesting/field name, but logging the full response and
        # returning it in raw_provider_response either way, so a wrong
        # guess here is loud and immediately fixable rather than a silent
        # None slipping downstream.
        data = response_body.get("data") if isinstance(response_body.get("data"), dict) else {}
        van = data.get("virtual_account_number") or response_body.get("virtual_account_number")

        if not van:
            logger.error(
                "Decentro VA creation returned HTTP %s (success) for user_id=%s, but no "
                "virtual_account_number field was found where expected. Full response: %s",
                response.status_code,
                user.id,
                response_body,
            )
            return VanIssuanceResult(
                success=False,
                virtual_account_number=None,
                routing_details=None,
                provider_reference=reference_id,
                error_message="Decentro reported success but the VAN field wasn't where expected -- check logs and adjust the field lookup above.",
                raw_provider_response=response_body,
            )

        # routing_details extraction is EVEN LESS certain than the VAN
        # number above -- Decentro's response shape for this specific
        # field was never confirmed (same interactive-example-picker
        # limitation). Best-effort lookup for an "ifsc" key; falls back
        # to an explicitly-flagged placeholder rather than failing the
        # whole issuance over a field that's secondary to the account
        # number itself.
        ifsc = data.get("ifsc") or response_body.get("ifsc")
        routing_details = {"ifsc": ifsc} if ifsc else {"note": "ifsc not found in Decentro's response -- check raw_provider_response and adjust this extraction."}

        return VanIssuanceResult(
            success=True,
            virtual_account_number=van,
            routing_details=routing_details,
            provider_reference=reference_id,
            error_message=None,
            raw_provider_response=response_body,
        )

    def verify_webhook_signature(self, headers: dict[str, str], raw_body: bytes) -> bool:
        """
        NOT HMAC -- confirmed against Decentro's own callback documentation,
        their model is a shared custom header name/value pair the platform
        defines and registers with Decentro's team (by email, at time of
        writing -- not a self-serve dashboard/API step). raw_body is
        unused here but kept in the interface signature since a future,
        genuinely HMAC-based provider would need it.
        """
        if settings.DECENTRO_WEBHOOK_HEADER_NAME is None or settings.DECENTRO_WEBHOOK_HEADER_VALUE is None:
            logger.error("DECENTRO_WEBHOOK_HEADER_NAME/VALUE not configured -- rejecting all Decentro callbacks until set.")
            return False

        expected = settings.DECENTRO_WEBHOOK_HEADER_VALUE.get_secret_value()
        received = headers.get(settings.DECENTRO_WEBHOOK_HEADER_NAME, "")
        return hmac.compare_digest(received, expected)


def get_virtual_account_provider() -> VirtualAccountProvider:
    """The one place that reads VAM_PROVIDER -- api/van_routes.py (VAN issuance) and api/b2b_routes.py (webhook signature verification) call this, never the classes above directly."""
    if settings.VAM_PROVIDER == "decentro_sandbox":
        return DecentroVirtualAccountProvider()
    return MockVirtualAccountProvider()