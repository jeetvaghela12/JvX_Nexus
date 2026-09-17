"""
main.py
FastAPI entry point for RemitCore — the cross-border collections layer
that runs inside a partner bank's own application.

WHAT THIS SERVICE DOES NOT DO, and must never start doing: hold funds,
move funds, execute settlement, or contact the bank's customer. The bank
does all four. This service coordinates KYC and account issuance requests,
screens invoices, records what the bank reports, and returns compliance
recommendations the bank is free to ignore.
"""
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.config import settings
from core.database import Base, engine

# Imported for their side effect: each module registers its table on
# Base.metadata. Without this, create_all() silently skips any table whose
# model is not reachable from an imported router, and the first symptom is
# a confusing "relation does not exist" at runtime rather than an error at
# startup.
from models import (  # noqa: F401
    compliance_model,
    declaration_model,
    payment_model,
    user_model,
    virtual_account_model,
)

from api.auth_routes import router as auth_router
from api.b2b_routes import router as b2b_router
from api.compliance_routes import router as compliance_router
from api.declaration_routes import router as declaration_router
from api.invoice_routes import router as invoice_router
from api.kyc_routes import router as kyc_router
from api.payment_routes import router as payment_router
from api.van_routes import router as van_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
    LOCAL DEVELOPMENT ONLY.

    create_all() is additive: it issues CREATE TABLE for what is missing
    and does nothing to a table that already exists, even if the model has
    since gained columns. Against a database that already has these
    tables, a new column will simply never appear, and the failure shows
    up later as a missing-column error nobody can place.

    Real schema evolution needs Alembic. This call is appropriate only
    against a fresh, disposable database.
    """
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="RemitCore",
    description=(
        "Cross-border collections infrastructure for Indian banks. "
        "Runs inside the bank's application; never holds or moves funds."
    ),
    version="0.2.0",
    lifespan=lifespan,
)

# allow_credentials stays False deliberately. A wildcard origin combined
# with credentialed requests is rejected by browsers outright, so setting
# both would not grant broader access — it would break credentialed calls
# while appearing permissive. Auth here is a bearer token in a header, not
# a cookie, so nothing this app relies on is affected.
#
# The wildcard itself is a development setting. Before this handles a
# bank's traffic it needs a real allowlist, which is why the origins are
# read from config rather than hardcoded.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(kyc_router)
app.include_router(van_router)
app.include_router(invoice_router)
app.include_router(declaration_router)
app.include_router(payment_router)
app.include_router(compliance_router)
app.include_router(b2b_router)


@app.get("/health", tags=["Ops"])
async def health_check() -> dict[str, str]:
    return {"status": "ok", "service": "RemitCore"}