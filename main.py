"""
main.py
FastAPI application entry point -- wires CORE, MODELS, SERVICES, and API
into a single running app.
"""
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.database import Base, engine

# Import every model module so its table registers on Base.metadata BEFORE
# create_all() runs in the lifespan below. This is NOT redundant with the
# router imports further down: none of the routers below, directly or
# transitively, ever import models.compliance_model (RawWebhookLog,
# CommercialInvoice) -- only user_model, ledger_model, ticket_model, and
# virtual_account_model reach Base.metadata via the routers/services that
# use them. virtual_account_model specifically DOES have a transitive
# path today (services/bank_webhook.py imports it directly, and
# api/van_routes.py imports it too) -- it's still listed explicitly here
# rather than relying on that path staying intact, matching this block's
# own reasoning: a future refactor of either file could quietly remove
# that import without anyone noticing create_all() had started skipping
# a table. Without this explicit block, create_all() would silently
# create every table except compliance_model's two: no error at startup,
# they'd just never exist, and the first sign of trouble would be a
# confusing "relation does not exist" the moment something touches either
# table -- exactly the kind of failure mode worth catching before the
# stress test, not during it.
#
# clientshield_model added alongside the rest for the identical reason:
# ClientShieldReport is only reached transitively via api/clientshield_routes.py
# today -- fine right now, but the same "a future refactor could silently
# stop registering this table" risk applies, so it's listed explicitly
# here too, not left to rely on that one import path staying intact.
from models import cbdc_model, clientshield_model, compliance_model, income_model, ledger_model, ticket_model, user_model, virtual_account_model  # noqa: F401

from api.auth_routes import router as auth_router
from api.kyc_routes import router as kyc_router
from api.van_routes import router as van_router
from api.invoice_routes import router as invoice_router
from api.compliance_routes import router as compliance_router
from api.payout_routes import router as payout_router
from api.b2b_routes import router as b2b_router
from api.support_routes import router as support_router
from api.v1_routers import router as v1_router
from api.admin_routes import router as admin_router
from api.consolidator_routes import router as consolidator_router
from api.clientshield_routes import router as clientshield_router

# Basic logging config so the logger.exception(...) calls already in the
# API layer (b2b_routes.py, support_routes.py, v1_routers.py) actually
# produce readable, leveled output -- without this, Python's logging
# defaults still surface ERROR-level records via a bare "last resort"
# handler, but with none of the formatting that makes them useful under
# real load. Not one of the five things asked for explicitly, but a small,
# low-risk addition that matters specifically because a stress test is
# exactly when you need these lines to be legible.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
    LOCAL TESTING ONLY, per the brief: Base.metadata.create_all() is
    additive-only -- it issues CREATE TABLE for whatever doesn't exist yet
    and does nothing to a table that already does, even if that table's
    corresponding model has since gained new columns. This project's own
    history is the concrete example: source_currency, base_usd_exchange_
    rate, status, error_reason, and cbdc_reference_number were all added
    to TransactionLedger, and kyc_status/preferred_payout_route/etc. to
    User, well after either table could plausibly have already been
    created by an earlier run of exactly this call. Against any database
    that already has these tables, create_all() will NOT retroactively add
    those columns -- Alembic (or equivalent) migrations are what real
    schema evolution needs; this call is only ever appropriate against a
    fresh, disposable database, which is what "local testing" here means.
    """
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="JvX Nexus Core",
    description=(
        "Bank-grade infrastructure for cross-border B2B payments, e-Rupee "
        "settlement, and RBI/FEMA-compliant transaction processing."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

# allow_credentials=False, deliberately, even though "allow all" was asked
# for: allow_origins=["*"] combined with allow_credentials=True is
# rejected by browsers outright (the CORS spec forbids a wildcard origin
# alongside credentialed requests) -- so setting both would either be
# silently ineffective or break credentialed calls, not actually grant
# broader access. This app's auth is header-based (x_user_id today, a JWT
# Authorization header once the planned security-layer integration lands),
# not cookie-based, so allow_credentials=False doesn't limit anything this
# app actually relies on. allow_origins=["*"] is still exactly as open as
# asked -- flagging, as with every other "for now"/mock item this session,
# that this needs to become a real allowlist of known frontend origins
# before this is anywhere near production traffic.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(kyc_router)
app.include_router(van_router)
app.include_router(invoice_router)
app.include_router(compliance_router)
app.include_router(payout_router)
app.include_router(b2b_router)
app.include_router(support_router)
app.include_router(v1_router)
app.include_router(admin_router)
app.include_router(consolidator_router)
app.include_router(clientshield_router)


@app.get("/health")
async def health_check() -> dict[str, str]:
    return {"status": "ok", "system": "JvX Nexus Core"}