"""
Services: client_risk_providers.py
Pillar 3's individual signal-check functions -- each one talks to a
single external source and returns a small, honest result. Orchestration
and scoring live in clientshield_engine.py, not here; this file's only
job is "go get one fact."

RECONSTRUCTED, NOT RE-VERIFIED against your real core/config.py -- same
standing caveat as every service file in this rebuild.
"""
import datetime
import logging

import dns.resolver
import requests

from core.config import settings

logger = logging.getLogger(__name__)

_REQUEST_TIMEOUT_SECONDS = 10


class ClientRiskProviderError(Exception):
    """Base class for a single provider's failures -- mirrors compliance_engine.py's own exception hierarchy on purpose, same reasoning: a caller needs to tell a transient failure from a real error."""


class ClientRiskProviderUnavailableError(ClientRiskProviderError):
    """A provider timed out, refused the connection, or returned 5xx/429 -- transient."""


def _client_risk_mode_is_mock() -> bool:
    """
    Reuses settings.COMPLIANCE_MODE rather than introducing a new,
    parallel toggle -- same safety property (including the hard
    production stop) as the check compliance_engine.py already relies
    on, since this is the same category of problem: some of Pillar 3's
    providers (Companies House, Google Web Risk) need real, paid/
    registered credentials that don't exist yet, exactly like Cashfree
    and ComplyAdvantage didn't when that toggle was first built.
    """
    if settings.COMPLIANCE_MODE == "mock" and settings.ENV == "production":
        raise RuntimeError(
            "COMPLIANCE_MODE=mock is set but ENV=production -- refusing to run "
            "client-risk checks in mock mode against a production environment."
        )
    return settings.COMPLIANCE_MODE == "mock"


# ----------------------------------------------------------------------
# Domain age -- RDAP, free and keyless, no mock gating needed at all.
# ----------------------------------------------------------------------

class DomainAgeResult:
    __slots__ = ("domain", "found", "registration_date", "age_days")

    def __init__(self, domain: str, found: bool, registration_date: datetime.date | None, age_days: int | None):
        self.domain = domain
        self.found = found
        self.registration_date = registration_date
        self.age_days = age_days

    def __repr__(self) -> str:
        return f"DomainAgeResult(domain={self.domain!r}, found={self.found}, age_days={self.age_days})"


def check_domain_age(domain: str) -> DomainAgeResult:
    """
    Uses rdap.org's unified lookup, which resolves the correct
    authoritative RDAP server for any TLD itself -- avoids having to
    separately implement IANA's bootstrap-registry resolution here. Free,
    no API key, no mock gating: this genuinely works today for anyone.
    """
    try:
        response = requests.get(
            f"https://rdap.org/domain/{domain}",
            headers={"Accept": "application/rdap+json"},
            timeout=_REQUEST_TIMEOUT_SECONDS,
        )
    except requests.Timeout as exc:
        raise ClientRiskProviderUnavailableError(f"RDAP lookup for {domain} timed out.") from exc
    except requests.RequestException as exc:
        raise ClientRiskProviderUnavailableError(f"RDAP lookup for {domain} failed: {exc}") from exc

    if response.status_code == 404:
        return DomainAgeResult(domain=domain, found=False, registration_date=None, age_days=None)
    if response.status_code >= 500 or response.status_code == 429:
        raise ClientRiskProviderUnavailableError(f"rdap.org returned {response.status_code} for {domain}.")
    if response.status_code >= 400:
        raise ClientRiskProviderError(f"rdap.org returned {response.status_code} for {domain}.")

    data = response.json()
    registration_date_str = None
    for event in data.get("events", []):
        if event.get("eventAction") == "registration":
            registration_date_str = event.get("eventDate")
            break

    if registration_date_str is None:
        # Record found, but no registration event published -- not every
        # registry includes one. Honest partial result, not a guess.
        return DomainAgeResult(domain=domain, found=True, registration_date=None, age_days=None)

    registered_at = datetime.datetime.fromisoformat(registration_date_str.replace("Z", "+00:00"))
    age_days = (datetime.datetime.now(datetime.timezone.utc) - registered_at).days
    return DomainAgeResult(domain=domain, found=True, registration_date=registered_at.date(), age_days=age_days)


# ----------------------------------------------------------------------
# UK company registry -- free, but needs a registered (free) API key,
# so it's real regardless of mock mode -- there's no "fake Companies
# House" needed the way there is for Cashfree/ComplyAdvantage, since
# getting a real key costs nothing and takes minutes.
# ----------------------------------------------------------------------

class UkRegistryResult:
    __slots__ = ("match_found", "matched_name", "company_number", "company_status")

    def __init__(self, match_found: bool, matched_name: str | None, company_number: str | None, company_status: str | None):
        self.match_found = match_found
        self.matched_name = matched_name
        self.company_number = company_number
        self.company_status = company_status


def check_uk_company_registry(company_name: str) -> UkRegistryResult:
    """
    Companies House authenticates via HTTP Basic auth with the API key
    as the username and an EMPTY password -- an unusual pattern, but
    exactly how their own API works, not a bug in this code.
    """
    try:
        response = requests.get(
            "https://api.company-information.service.gov.uk/search/companies",
            params={"q": company_name},
            auth=(settings.COMPANIES_HOUSE_API_KEY.get_secret_value(), ""),
            timeout=_REQUEST_TIMEOUT_SECONDS,
        )
    except requests.Timeout as exc:
        raise ClientRiskProviderUnavailableError("Companies House lookup timed out.") from exc
    except requests.RequestException as exc:
        raise ClientRiskProviderUnavailableError(f"Companies House lookup failed: {exc}") from exc

    if response.status_code in (401, 403):
        raise ClientRiskProviderError("Companies House rejected the API key -- check COMPANIES_HOUSE_API_KEY.")
    if response.status_code == 429 or response.status_code >= 500:
        raise ClientRiskProviderUnavailableError(f"Companies House returned {response.status_code}.")
    if response.status_code >= 400:
        raise ClientRiskProviderError(f"Companies House returned {response.status_code}: {response.text[:300]}")

    items = response.json().get("items", [])
    if not items:
        return UkRegistryResult(match_found=False, matched_name=None, company_number=None, company_status=None)

    top = items[0]
    return UkRegistryResult(
        match_found=True,
        matched_name=top.get("title"),
        company_number=top.get("company_number"),
        company_status=top.get("company_status"),
    )


# ----------------------------------------------------------------------
# Global LEI cross-check -- GLEIF, free and keyless.
# ----------------------------------------------------------------------

class LeiCheckResult:
    __slots__ = ("match_found", "lei", "matched_name", "jurisdiction")

    def __init__(self, match_found: bool, lei: str | None, matched_name: str | None, jurisdiction: str | None):
        self.match_found = match_found
        self.lei = lei
        self.matched_name = matched_name
        self.jurisdiction = jurisdiction


def check_global_lei(entity_name: str) -> LeiCheckResult:
    try:
        response = requests.get(
            "https://api.gleif.org/api/v1/lei-records",
            params={"filter[entity.legalName]": entity_name},
            timeout=_REQUEST_TIMEOUT_SECONDS,
        )
    except requests.Timeout as exc:
        raise ClientRiskProviderUnavailableError("GLEIF lookup timed out.") from exc
    except requests.RequestException as exc:
        raise ClientRiskProviderUnavailableError(f"GLEIF lookup failed: {exc}") from exc

    if response.status_code == 429 or response.status_code >= 500:
        raise ClientRiskProviderUnavailableError(f"GLEIF returned {response.status_code}.")
    if response.status_code >= 400:
        raise ClientRiskProviderError(f"GLEIF returned {response.status_code}.")

    records = response.json().get("data", [])
    if not records:
        return LeiCheckResult(match_found=False, lei=None, matched_name=None, jurisdiction=None)

    top = records[0]
    attributes = top.get("attributes", {})
    entity = attributes.get("entity", {})
    return LeiCheckResult(
        match_found=True,
        lei=top.get("id"),
        matched_name=entity.get("legalName", {}).get("name"),
        jurisdiction=entity.get("jurisdiction"),
    )


# ----------------------------------------------------------------------
# MX record check -- plain DNS, free, keyless.
# ----------------------------------------------------------------------

def check_mx_record(email_domain: str) -> bool | None:
    """
    Returns True if the domain can plausibly receive mail (has an MX
    record, or the implicit-MX A/AAAA fallback per RFC), False if it
    genuinely cannot, or None if this couldn't be determined at all (a
    DNS resolver hiccup, not the domain's own fault) -- deliberately
    three-valued so a transient resolver error is never silently
    recorded as "this client's email domain is invalid."
    """
    try:
        dns.resolver.resolve(email_domain, "MX")
        return True
    except dns.resolver.NXDOMAIN:
        return False
    except dns.resolver.NoAnswer:
        # No MX record specifically -- check the implicit-MX fallback
        # (a resolvable A record) before concluding this domain can't
        # receive mail, since RFC rules allow that fallback and treating
        # it as invalid would be a real false positive.
        try:
            dns.resolver.resolve(email_domain, "A")
            return True
        except Exception:
            return False
    except Exception:
        logger.warning("MX lookup for %s failed with an unexpected resolver error -- treating as unknown, not invalid.", email_domain)
        return None


# ----------------------------------------------------------------------
# Disposable email check -- starter list, explicitly flagged as a
# scaffold, not the real, production-grade list this needs.
# ----------------------------------------------------------------------

_STARTER_DISPOSABLE_DOMAINS = frozenset({
    "mailinator.com", "10minutemail.com", "guerrillamail.com", "tempmail.com",
    "throwawaymail.com", "yopmail.com", "trashmail.com", "getnada.com",
    "temp-mail.org", "dispostable.com",
})
# THIS IS A STARTER SET, NOT A PRODUCTION LIST. The feasibility research
# specifically recommended a daily-updated, community-maintained list
# (e.g. github.com/amieiro/disposable-email-domains, regenerated every
# 15 minutes) precisely because disposable domains rotate constantly --
# a static, hand-picked list like this one goes stale within weeks. Swap
# this frozenset for a loaded/refreshed list before relying on this
# check for anything beyond demoing the mechanism.


def check_disposable_email(email_domain: str) -> bool:
    return email_domain.lower().strip() in _STARTER_DISPOSABLE_DOMAINS


# ----------------------------------------------------------------------
# Google Web Risk -- needs a real, paid GCP credential, so THIS one
# genuinely needs the mock gate, same reasoning as Cashfree/
# ComplyAdvantage in compliance_engine.py.
# ----------------------------------------------------------------------

def check_web_risk(url: str) -> bool | None:
    """
    Returns True if Google's Web Risk API flags the URL as malware/
    social-engineering/unwanted software, False if checked and clean,
    None if the check couldn't run at all (mock mode with nothing to
    fall back to safely -- see below).
    """
    if _client_risk_mode_is_mock():
        # Unlike compliance_engine.py's mock branches, there is no safe,
        # meaningful "fake" answer for a threat-intelligence lookup --
        # returning a fabricated True or False would be actively
        # misleading about a real security signal. None honestly means
        # "not checked," and the caller (clientshield_engine.py) must
        # treat that as a genuinely missing signal, not a clean bill of
        # health.
        return None

    try:
        response = requests.get(
            "https://webrisk.googleapis.com/v1/uris:search",
            params={
                "key": settings.GOOGLE_WEB_RISK_API_KEY.get_secret_value(),
                "uri": url,
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            },
            timeout=_REQUEST_TIMEOUT_SECONDS,
        )
    except requests.Timeout as exc:
        raise ClientRiskProviderUnavailableError("Web Risk lookup timed out.") from exc
    except requests.RequestException as exc:
        raise ClientRiskProviderUnavailableError(f"Web Risk lookup failed: {exc}") from exc

    if response.status_code in (401, 403):
        raise ClientRiskProviderError("Google rejected the Web Risk API key -- check GOOGLE_WEB_RISK_API_KEY.")
    if response.status_code == 429 or response.status_code >= 500:
        raise ClientRiskProviderUnavailableError(f"Web Risk returned {response.status_code}.")
    if response.status_code >= 400:
        raise ClientRiskProviderError(f"Web Risk returned {response.status_code}.")

    body = response.json()
    return "threat" in body and bool(body["threat"])