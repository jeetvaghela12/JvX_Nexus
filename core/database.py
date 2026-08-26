"""
Core: database.py
Database connection, pooling, and session management.

POOLING PHILOSOPHY AT THIS SCALE: pool_size/max_overflow below are
per-process values, not a global cap -- "10M+ concurrent users" is served
by many horizontally-scaled app instances, each holding a modest pool, not
one engine with an enormous pool_size. An oversized pool per instance just
races every other instance to exhaust Postgres's own max_connections (or
PgBouncer's) faster. If this app sits behind PgBouncer (recommended at
this scale), PgBouncer -- not this file -- is the actual connection
multiplexer; the settings here just need to be sane per instance and
resilient to connections being recycled underneath them.
"""
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import QueuePool

from core.config import settings

# Fetching the secure URL -- settings.DATABASE_URL is a Pydantic SecretStr
# (see core/config.py); .get_secret_value() is called exactly once, here,
# rather than at every place a connection is opened.
SQLALCHEMY_DATABASE_URL = settings.DATABASE_URL.get_secret_value()

engine: Engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    # QueuePool is the default for non-SQLite dialects; made explicit here
    # since the PgBouncer note below is specifically about this choice.
    poolclass=QueuePool,
    pool_size=20,
    # Baseline connections held open per instance. Tune against
    # (Postgres max_connections, or PgBouncer's own pool size) divided by
    # the number of running instances -- not against the 10M-user figure
    # directly; that figure is served by horizontal instance count, not by
    # one engine's pool.
    max_overflow=10,
    # Allows short bursts up to pool_size + max_overflow (30 here) under
    # load spikes. Overflow connections are discarded once no longer
    # needed rather than kept, so this doesn't raise the steady-state
    # baseline.
    pool_timeout=30,
    # Seconds a request waits for a free connection before raising a
    # timeout error, rather than hanging indefinitely when the pool is
    # exhausted -- fail fast so upstream retry/circuit-breaker logic can
    # actually act, instead of every caller queuing forever.
    pool_recycle=1800,
    # Proactively recycle connections older than 30 minutes. Protects
    # against connections silently dropped by an upstream load balancer,
    # PgBouncer, or a cloud DB proxy's idle-timeout that this app has no
    # visibility into -- without this, the first query on a connection the
    # upstream already closed fails with a stale-connection error instead
    # of transparently reconnecting.
    pool_pre_ping=True,
    # Issues a lightweight liveness check before handing out a pooled
    # connection and transparently replaces it if the check fails. Belt-
    # and-suspenders alongside pool_recycle: pre_ping also catches drops
    # that happen before the recycle window elapses.
    pool_use_lifo=True,
    # LIFO instead of QueuePool's default FIFO: under fluctuating load
    # this keeps a smaller "hot" rotation of connections in active reuse
    # and lets the remainder age out toward pool_recycle, rather than
    # cycling every connection through evenly.
    echo=(settings.ENV == "development"),
    # Never echo raw SQL -- including bound parameters, which on this
    # platform means transaction amounts and other sensitive values -- to
    # logs outside local development.
)
# NOTE on PgBouncer specifically: if it's configured in TRANSACTION
# pooling mode (typical for max throughput at this scale), be aware it can
# hand the same Postgres backend connection to a different client between
# transactions. That's transparent to plain SQL, but it breaks driver-level
# server-side prepared-statement caching for some DBAPI drivers -- asyncpg
# in particular needs connect_args={"statement_cache_size": 0} in that
# setup. psycopg2/psycopg3 are generally safer by default here, but it's
# worth confirming against whichever driver is actually in
# SQLALCHEMY_DATABASE_URL (not guessed at in this file, since passing the
# wrong driver's connect_args would break the other one). Some teams
# instead choose poolclass=NullPool here entirely -- no app-level pooling
# at all, leaving PgBouncer as the single pooling layer -- trading away
# pool_size/max_overflow tuning for one less place double-pooling can go
# wrong. Not switched to that here since pool_size/max_overflow were
# explicitly asked for; flagging it as the standard alternative.

SessionLocal: sessionmaker[Session] = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """
    SQLAlchemy 2.0 declarative base (replaces the legacy declarative_base()
    factory call). Drop-in compatible with every model already built on it
    in Stage 1 (user_model.py, ledger_model.py, ticket_model.py) --
    `class User(Base):` etc. needs no changes on their end.
    """


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency: yields one Session for the lifetime of a single
    request, then guarantees cleanup regardless of how the request ends.
    """
    db = SessionLocal()
    try:
        yield db
    except Exception:
        # Explicit rollback on any exception raised while the session was
        # in use. Session.close() below would eventually discard an
        # uncommitted transaction on its own, but being explicit here
        # makes the intent unambiguous and gives a clear place to hang
        # logging/metrics on DB-session failures later.
        db.rollback()
        raise
    finally:
        db.close()