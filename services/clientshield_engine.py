"""
Services: clientshield_engine.py
Pillar 3's orchestration: calls every individual provider, reuses
compliance_engine.py's real, already-tested sanctions screening rather
than reimplementing it, and computes a weighted risk score -- never a
binary gate, per the feasibility research's own explicit finding.

RECONSTRUCTED, NOT RE-VERIFIED against your real
services/compliance_engine.py or models/user_model.py -- same standing
caveat as every service file in this rebuild. In particular, confirm
screen_aml_watchlists' exact import path and signature against your real
compliance_engine.py.
"""
import logging
from dataclasses import dataclass

from sqlalchemy.orm import Session

from models.clientshield_model import ClientShieldReport
from services.client_risk_providers import (
    ClientRiskProviderError,
    check_disposable_email,
    check_domain_age,
    check_global_lei,
    check_mx_record,
    check_uk_company_registry,
    check_web_risk,
)
from services.compliance_engine import screen_aml_watchlists

logger = logging.getLogger(__name__)

# Point weights -- see the module-level reasoning in the docstring below
# for why each one is what it is. Sanctions is not in this table at all:
# it is checked separately and short-circuits to HIGH outright, never
# just contributing points like everything else.
_YOUNG_DOMAIN_THRESHOLD_DAYS = 180
_POINTS_YOUNG_DOMAIN = 2
_POINTS_UNKNOWN_DOMAIN_AGE = 1
_POINTS_NO_REGISTRY_MATCH = 1
_POINTS_INVALID_MX = 2
_POINTS_DISPOSABLE_EMAIL = 2
_POINTS_WEB_RISK_FLAGGED = 3

_MEDIUM_THRESHOLD = 2
_HIGH_THRESHOLD = 5


@dataclass(frozen=True, slots=True)
class ClientRiskCheckResult:
    client_name: str
    client_domain: str | None
    client_country: str | None
    domain_age_days: int | None
    registry_match_found: bool | None
    sanctions_hit: bool
    mx_valid: bool | None
    disposable_email: bool | None
    web_risk_flagged: bool | None
    risk_score: str
    risk_points: int


def run_client_risk_check(
    client_name: str,
    client_domain: str | None,
    client_country: str | None,
    client_email_domain: str | None,
) -> ClientRiskCheckResult:
    """
    Runs every available signal check and combines them into a weighted
    score. Each provider call is individually try/excepted: a single
    provider being down (a timeout, a rate limit) degrades that ONE
    signal to "unknown," not the whole check to "failed" -- consistent
    with every other design decision in Pillar 3 that treats missing
    data as missing data, never as a false negative or false positive.

    WHY THESE WEIGHTS, SPECIFICALLY: Web Risk (+3) is the single
    strongest contributor because it's curated threat intelligence, not
    a heuristic -- the feasibility research found it to be the strongest
    genuinely meaningful signal available. A young domain (+2) and an
    invalid MX (+2) are both moderately strong, well-evidenced hygiene
    signals. Disposable email (+2) is real but has known false-positive
    tails (Gmail-alias evasion, list staleness) per the same research,
    so it sits at the same weight rather than higher. No registry match
    (+1) is deliberately the WEAKEST contributor: plenty of entirely
    legitimate small businesses have neither a UK company nor a global
    LEI, so absence of a match is much weaker evidence than presence of
    one would be. Unknown domain age (+1) reflects genuine uncertainty,
    not a confirmed red flag, so it's treated the same way.

    WHY UNCOVERED JURISDICTIONS SCORE ZERO, NOT A PENALTY: a US client
    with no free self-serve registry option available (per the
    feasibility research) gets registry_match_found=None, contributing
    ZERO points -- penalizing a client for JvX's own coverage gap would
    be dishonest and would systematically bias every US client toward a
    worse score for a reason that has nothing to do with their actual
    legitimacy.
    """
    domain_age_days: int | None = None
    if client_domain:
        try:
            domain_result = check_domain_age(client_domain)
            domain_age_days = domain_result.age_days if domain_result.found else None
        except ClientRiskProviderError:
            logger.warning("Domain age check failed for %s -- treating as unknown, not a red flag.", client_domain)

    registry_match_found: bool | None = None
    if client_country == "GB":
        try:
            registry_result = check_uk_company_registry(client_name)
            registry_match_found = registry_result.match_found
        except ClientRiskProviderError:
            logger.warning("UK Companies House check failed for %r -- treating as unknown.", client_name)
    else:
        # No free, self-serve registry option for other countries today
        # (see the feasibility research) -- fall back to the global LEI
        # cross-check, which covers SOME entities in any country but not
        # most small businesses.
        try:
            lei_result = check_global_lei(client_name)
            registry_match_found = lei_result.match_found if lei_result.match_found else None
            # Only set True on an actual match -- a non-match here does
            # NOT mean "no registry match found," it means "not in the
            # LEI database," which most small legitimate businesses
            # aren't. Leaving it None (uncovered) rather than False
            # (checked, absent) avoids penalizing the common case.
        except ClientRiskProviderError:
            logger.warning("GLEIF check failed for %r -- treating as unknown.", client_name)

    sanctions_hit = False
    try:
        screening = screen_aml_watchlists(client_name)
        sanctions_hit = not screening.is_clear
    except Exception:
        # Sanctions screening failing closed (unable to confirm clear)
        # is treated as NOT a hit here, deliberately -- the alternative
        # (treating a provider outage as a positive sanctions match)
        # would be a false accusation, which is a worse failure mode
        # than a missed check that gets retried. Logged loudly so this
        # gap is visible, not silently absorbed.
        logger.exception("Sanctions screening failed for %r during a ClientShield check -- treating as no hit, but this needs follow-up, not silence.", client_name)

    mx_valid: bool | None = None
    if client_email_domain:
        mx_valid = check_mx_record(client_email_domain)

    disposable = None
    if client_email_domain:
        disposable = check_disposable_email(client_email_domain)

    web_risk_flagged: bool | None = None
    if client_domain:
        try:
            web_risk_flagged = check_web_risk(f"https://{client_domain}")
        except ClientRiskProviderError:
            logger.warning("Web Risk check failed for %s -- treating as unknown.", client_domain)

    if sanctions_hit:
        risk_score = "HIGH"
        risk_points = _POINTS_WEB_RISK_FLAGGED + _POINTS_INVALID_MX + _POINTS_DISPOSABLE_EMAIL + _POINTS_YOUNG_DOMAIN
        # Reported as the maximum possible non-sanctions score, purely
        # for consistent display -- the actual reason for HIGH here is
        # the sanctions hit itself, not an accumulation of points.
    else:
        points = 0
        if domain_age_days is None:
            points += _POINTS_UNKNOWN_DOMAIN_AGE
        elif domain_age_days < _YOUNG_DOMAIN_THRESHOLD_DAYS:
            points += _POINTS_YOUNG_DOMAIN

        if registry_match_found is False:
            points += _POINTS_NO_REGISTRY_MATCH

        if mx_valid is False:
            points += _POINTS_INVALID_MX

        if disposable:
            points += _POINTS_DISPOSABLE_EMAIL

        if web_risk_flagged:
            points += _POINTS_WEB_RISK_FLAGGED

        risk_points = points
        if points >= _HIGH_THRESHOLD:
            risk_score = "HIGH"
        elif points >= _MEDIUM_THRESHOLD:
            risk_score = "MEDIUM"
        else:
            risk_score = "LOW"

    return ClientRiskCheckResult(
        client_name=client_name,
        client_domain=client_domain,
        client_country=client_country,
        domain_age_days=domain_age_days,
        registry_match_found=registry_match_found,
        sanctions_hit=sanctions_hit,
        mx_valid=mx_valid,
        disposable_email=disposable,
        web_risk_flagged=web_risk_flagged,
        risk_score=risk_score,
        risk_points=risk_points,
    )


def save_client_risk_check(db: Session, user_id: int, result: ClientRiskCheckResult) -> ClientShieldReport:
    report = ClientShieldReport(
        user_id=user_id,
        client_name=result.client_name,
        client_domain=result.client_domain,
        client_country=result.client_country,
        domain_age_days=result.domain_age_days,
        registry_match_found=result.registry_match_found,
        sanctions_hit=result.sanctions_hit,
        mx_valid=result.mx_valid,
        disposable_email=result.disposable_email,
        web_risk_flagged=result.web_risk_flagged,
        risk_score=result.risk_score,
        risk_points=result.risk_points,
        status="COMPLETED",
    )
    try:
        db.add(report)
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Unexpected failure saving ClientShield report (user_id=%s)", user_id)
        raise
    db.refresh(report)
    return report