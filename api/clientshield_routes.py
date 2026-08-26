"""
API: clientshield_routes.py
Pillar 3's route surface -- run a check, view past reports.

RECONSTRUCTED, NOT RE-VERIFIED -- same caveat as every route file in
this rebuild. Assumes core.dependencies.get_current_user and
core.database.get_db match the signatures used throughout the rest of
this codebase.
"""
import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from core.database import get_db
from core.dependencies import get_current_user
from models.clientshield_model import ClientShieldReport
from models.user_model import User
from services.clientshield_engine import run_client_risk_check, save_client_risk_check

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/clientshield", tags=["ClientShield"])


class ClientRiskCheckRequest(BaseModel):
    client_name: str
    client_domain: str | None = None
    client_country: str | None = None  # ISO 3166-1 alpha-2, e.g. "GB", "US"
    client_email_domain: str | None = None


@router.post("/check", status_code=201)
async def check_client(
    payload: ClientRiskCheckRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """
    Runs a full pre-engagement risk check and persists it. Synchronous --
    every provider has its own short timeout, and a failing provider
    degrades to "unknown" for that one signal rather than blocking the
    whole request (see clientshield_engine.py's own docstring).
    """
    result = run_client_risk_check(
        client_name=payload.client_name,
        client_domain=payload.client_domain,
        client_country=payload.client_country,
        client_email_domain=payload.client_email_domain,
    )
    report = save_client_risk_check(db, current_user.id, result)

    return {
        "id": report.id,
        "client_name": payload.client_name,  # echoed from the request, not re-read from the encrypted column, to avoid a redundant decrypt on the same request that just wrote it
        "client_domain": report.client_domain,
        "domain_age_days": report.domain_age_days,
        "registry_match_found": report.registry_match_found,
        "sanctions_hit": report.sanctions_hit,
        "mx_valid": report.mx_valid,
        "disposable_email": report.disposable_email,
        "web_risk_flagged": report.web_risk_flagged,
        "risk_score": report.risk_score,
        "risk_points": report.risk_points,
    }


@router.get("/reports")
async def list_reports(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict]:
    reports = db.execute(
        select(ClientShieldReport).where(ClientShieldReport.user_id == current_user.id)
    ).scalars().all()
    return [
        {
            "id": r.id,
            "client_name": r.client_name,
            "client_domain": r.client_domain,
            "risk_score": r.risk_score,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in reports
    ]


@router.get("/reports/{report_id}")
async def get_report(
    report_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """The 'see a client's profile' view -- one full report, every
    individual signal visible, not just the final score. Same uniform-404
    ownership-check pattern as every other user-owned resource in this
    codebase."""
    report = db.execute(
        select(ClientShieldReport).where(
            ClientShieldReport.id == report_id,
            ClientShieldReport.user_id == current_user.id,
        )
    ).scalar_one_or_none()
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found.")

    return {
        "id": report.id,
        "client_name": report.client_name,
        "client_domain": report.client_domain,
        "client_country": report.client_country,
        "domain_age_days": report.domain_age_days,
        "registry_match_found": report.registry_match_found,
        "sanctions_hit": report.sanctions_hit,
        "mx_valid": report.mx_valid,
        "disposable_email": report.disposable_email,
        "web_risk_flagged": report.web_risk_flagged,
        "risk_score": report.risk_score,
        "risk_points": report.risk_points,
        "created_at": report.created_at.isoformat() if report.created_at else None,
    }