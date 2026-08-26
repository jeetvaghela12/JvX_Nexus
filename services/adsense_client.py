"""
Services: adsense_client.py
Pillar 2's real, self-serve income-fetching integration -- confirmed
feasible in prior research: AdSense's `adsense.readonly` scope is
sensitive (requiring Google OAuth app verification) but NOT restricted
(so it does not trigger Google's paid CASA security audit), and is
genuinely self-serve for a solo developer, unlike Upwork/PayPal/Wise/
Fiverr, all of which are partner-gated or offer no API path at all.

RECONSTRUCTED, NOT RE-VERIFIED against your real config.py/user_model.py
-- same caveat as every file in this rebuild. Check settings field names
and User.id's type against your real files before treating this as final.
"""
import datetime
import decimal
import logging

import requests
from sqlalchemy import select
from sqlalchemy.orm import Session

from core.config import settings
from models.income_model import ConnectedIncomeSource, ForeignIncomeRecord
from services.oauth_state import create_oauth_state, verify_oauth_state, InvalidOAuthStateError  # noqa: F401 -- re-exported for routes

logger = logging.getLogger(__name__)

_GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
_GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
_ADSENSE_API_BASE = "https://adsense.googleapis.com/v2"
_ADSENSE_SCOPE = "https://www.googleapis.com/auth/adsense.readonly"
_REQUEST_TIMEOUT_SECONDS = 15


class AdSenseServiceError(Exception):
    """
    Base class for AdSense integration failures. Deliberately mirrors
    compliance_engine.py's own exception hierarchy (ServiceError /
    UnavailableError / AuthenticationError) -- same reasoning: a caller
    needs to distinguish "Google is down, retry later" from "our OAuth
    credentials are misconfigured" from "this user's consent expired and
    needs to reconnect," and a single generic exception can't carry that.
    """


class AdSenseUnavailableError(AdSenseServiceError):
    """Google's API timed out, refused the connection, or returned a 5xx/429 -- transient, worth retrying later."""


class AdSenseAuthenticationError(AdSenseServiceError):
    """A 401/403 from Google -- either our OAuth client credentials are wrong, or this user's consent/refresh token is no longer valid and they need to reconnect."""


def build_authorization_url(user_id: int) -> str:
    """
    Step 1 of the flow: called by the /consolidator/adsense/connect route.
    Returns the URL to redirect the user's browser to.
    """
    state = create_oauth_state(user_id)
    params = {
        "client_id": settings.GOOGLE_ADSENSE_CLIENT_ID,
        "redirect_uri": settings.GOOGLE_ADSENSE_REDIRECT_URI,
        "response_type": "code",
        "scope": _ADSENSE_SCOPE,
        "access_type": "offline",
        # "offline" is required to receive a refresh_token at all --
        # without it Google only issues a short-lived access_token, which
        # would mean re-prompting the user for consent every single sync.
        "prompt": "consent",
        # Forces Google to show the consent screen (and re-issue a
        # refresh_token) even if the user has connected before. Without
        # this, a reconnect after revoking access could silently fail to
        # produce a new refresh_token, since Google only guarantees
        # issuing one on the FIRST consent by default.
        "state": state,
    }
    query = "&".join(f"{key}={value}" for key, value in params.items())
    return f"{_GOOGLE_AUTH_URL}?{query}"


def _post_form(url: str, data: dict) -> dict:
    """
    Shared HTTP-failure-handling helper, parallel in spirit to
    compliance_engine.py's own _post_json -- but a separate,
    self-contained implementation here (not imported cross-module,
    since _post_json is underscore-prefixed/private to its own file)
    because this module has its own concerns: form-encoded OAuth token
    requests, not JSON compliance-provider calls.
    """
    try:
        response = requests.post(url, data=data, timeout=_REQUEST_TIMEOUT_SECONDS)
    except requests.Timeout as exc:
        raise AdSenseUnavailableError(f"Request to {url} timed out after {_REQUEST_TIMEOUT_SECONDS}s.") from exc
    except requests.RequestException as exc:
        raise AdSenseUnavailableError(f"Request to {url} failed: {exc}") from exc

    if response.status_code in (401, 403):
        raise AdSenseAuthenticationError(
            f"Google rejected the request to {url} with {response.status_code} -- "
            "check OAuth client credentials, or this user's consent may need to be renewed."
        )
    if response.status_code == 429 or response.status_code >= 500:
        raise AdSenseUnavailableError(f"Google returned {response.status_code} for {url} -- transient, retry later.")
    if response.status_code >= 400:
        raise AdSenseServiceError(f"Google returned {response.status_code} for {url}: {response.text[:500]}")

    return response.json()


def _get_json(url: str, access_token: str, params: dict | None = None) -> dict:
    """Same failure-handling discipline as _post_form, for authenticated GET calls against the AdSense API itself."""
    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        response = requests.get(url, headers=headers, params=params, timeout=_REQUEST_TIMEOUT_SECONDS)
    except requests.Timeout as exc:
        raise AdSenseUnavailableError(f"Request to {url} timed out after {_REQUEST_TIMEOUT_SECONDS}s.") from exc
    except requests.RequestException as exc:
        raise AdSenseUnavailableError(f"Request to {url} failed: {exc}") from exc

    if response.status_code in (401, 403):
        raise AdSenseAuthenticationError(
            f"Google rejected the request to {url} with {response.status_code} -- "
            "this user's AdSense connection may need to be renewed."
        )
    if response.status_code == 429 or response.status_code >= 500:
        raise AdSenseUnavailableError(f"Google returned {response.status_code} for {url} -- transient, retry later.")
    if response.status_code >= 400:
        raise AdSenseServiceError(f"Google returned {response.status_code} for {url}: {response.text[:500]}")

    return response.json()


def exchange_code_for_tokens(authorization_code: str) -> dict:
    """
    Step 2: called by the /consolidator/adsense/callback route once the
    state token has already been verified. Returns Google's raw token
    response, which includes access_token, refresh_token (only present
    on first consent or when prompt=consent forces re-issue), and
    expires_in.
    """
    return _post_form(
        _GOOGLE_TOKEN_URL,
        data={
            "code": authorization_code,
            "client_id": settings.GOOGLE_ADSENSE_CLIENT_ID,
            "client_secret": settings.GOOGLE_ADSENSE_CLIENT_SECRET.get_secret_value(),
            "redirect_uri": settings.GOOGLE_ADSENSE_REDIRECT_URI,
            "grant_type": "authorization_code",
        },
    )


def refresh_access_token(refresh_token: str) -> str:
    """
    AdSense access tokens are short-lived; every sync (beyond the very
    first, immediately-after-consent one) needs a fresh access_token
    exchanged from the long-lived refresh_token stored in
    ConnectedIncomeSource.
    """
    token_response = _post_form(
        _GOOGLE_TOKEN_URL,
        data={
            "refresh_token": refresh_token,
            "client_id": settings.GOOGLE_ADSENSE_CLIENT_ID,
            "client_secret": settings.GOOGLE_ADSENSE_CLIENT_SECRET.get_secret_value(),
            "grant_type": "refresh_token",
        },
    )
    return token_response["access_token"]


def fetch_and_store_earnings(db: Session, user_id: int, connection: ConnectedIncomeSource) -> int:
    """
    Step 3: fetches AdSense payment/earnings data and creates
    ForeignIncomeRecord rows for anything not already imported.

    Returns the count of NEW records created (not the total fetched --
    re-running this against already-synced data should report 0, not
    silently re-report the same number every time, which would make
    "did this actually do anything" impossible to tell from the response
    alone).
    """
    access_token = refresh_access_token(connection.encrypted_refresh_token)

    account_list = _get_json(f"{_ADSENSE_API_BASE}/accounts", access_token)
    accounts = account_list.get("accounts", [])
    if not accounts:
        logger.info("AdSense sync for user_id=%s found zero linked accounts.", user_id)
        return 0

    new_records_created = 0

    for account in accounts:
        account_name = account["name"]  # e.g. "accounts/pub-1234567890"
        payments_response = _get_json(f"{_ADSENSE_API_BASE}/{account_name}/payments", access_token)

        for payment in payments_response.get("payments", []):
            external_id = payment.get("name")  # AdSense's own resource identifier -- what dedup keys off
            if not external_id:
                logger.warning("AdSense payment for user_id=%s missing its own 'name' identifier -- skipping, cannot dedupe safely.", user_id)
                continue

            already_imported = db.execute(
                select(ForeignIncomeRecord.id).where(
                    ForeignIncomeRecord.user_id == user_id,
                    ForeignIncomeRecord.source == "ADSENSE",
                    ForeignIncomeRecord.external_reference_id == external_id,
                )
            ).scalar_one_or_none()
            if already_imported is not None:
                continue  # already have this one -- this is what makes re-syncing safe to run repeatedly

            amount_micros = payment.get("amount", {}).get("units")
            currency_code = payment.get("amount", {}).get("currencyCode", "USD")
            paid_date = payment.get("date")  # {"year":, "month":, "day":}

            if amount_micros is None or paid_date is None:
                logger.warning("AdSense payment %s for user_id=%s missing amount or date -- skipping.", external_id, user_id)
                continue

            record = ForeignIncomeRecord(
                user_id=user_id,
                source="ADSENSE",
                amount=decimal.Decimal(str(amount_micros)),
                currency=currency_code,
                received_date=datetime.date(paid_date["year"], paid_date["month"], paid_date["day"]),
                client_name=None,  # AdSense isn't a "client" in the same sense as a direct invoice -- there's no third party to name here
                notes="Automatically imported via AdSense OAuth sync.",
                external_reference_id=external_id,
            )
            db.add(record)
            new_records_created += 1

    connection.last_synced_at = datetime.datetime.now(datetime.timezone.utc)

    try:
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Unexpected failure committing AdSense sync results (user_id=%s)", user_id)
        raise

    return new_records_created