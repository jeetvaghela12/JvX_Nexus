"""
Core: security.py
Handles password hashing and JWT token generation/verification.

Strictly cryptographic utility functions -- no user/DB models are imported
or referenced here. Callers (API-layer dependencies) own translating a
failure from this module (a raised jwt.PyJWTError, or a False from
verify_password) into the appropriate HTTP response.
"""
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

import jwt
from passlib.context import CryptContext

from core.config import settings

# ----------------------------------------------------------------------
# Security Constants
# ----------------------------------------------------------------------
# Deliberately hardcoded here rather than sourced from settings/.env,
# unlike the business-rule percentages in config.py. Those vary per bank
# partnership and are meant to be environment-configurable; token
# lifetimes are fixed security policy that should only ever change via a
# code change (and code review), not a silently-edited .env value.
ALGORITHM = "HS256"

ACCESS_TOKEN_EXPIRE_MINUTES = 15  # Bank-grade strict expiry
_MAX_ACCESS_TOKEN_LIFETIME = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

REFRESH_TOKEN_EXPIRE_DAYS = 7
# Not specified in any prior discussion -- 7 days is a common, reasonable
# default (long enough that a user isn't forced to re-enter credentials
# constantly, short enough to bound how long a stolen refresh token stays
# useful), not a figure that's been explicitly confirmed. Easy to change
# in one place if a different value is wanted.
_MAX_REFRESH_TOKEN_LIFETIME = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

_MAX_MFA_CHALLENGE_TOKEN_LIFETIME = timedelta(minutes=5)
# Deliberately short -- this token only exists to bridge the gap between
# "password verified" and "TOTP code submitted," a single-digit-minutes
# window in normal use. A 5-minute ceiling means a leaked mfa_challenge
# token is a narrow, short-lived exposure, unlike a leaked refresh token.

TokenType = Literal["access", "refresh", "mfa_challenge"]
# "mfa_challenge" was the planned extension point noted here when this
# file was first built -- now being fulfilled, not just planned. Flow:
# after password (or Google) verification succeeds in api/auth_routes.py,
# if user.mfa_enabled is set, a short-lived "mfa_challenge" token is
# issued instead of access+refresh; POST /auth/login/verify-mfa exchanges
# it (together with the submitted TOTP code) for the real tokens.
# _create_token/_decode_token below already worked generically by token
# type, so this was a small, additive change to this file, exactly as
# anticipated -- not a redesign of it.

# ----------------------------------------------------------------------
# Password Hashing (passlib / bcrypt)
# ----------------------------------------------------------------------
# Single module-level CryptContext -- constructing one per call would be
# wasteful. deprecated="auto" means a future scheme change (e.g. adding
# "argon2" ahead of "bcrypt" in the schemes list) transparently re-hashes
# existing users' passwords to the new scheme the next time they log in
# successfully, rather than requiring a big-bang migration.
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)

# bcrypt only considers the first 72 BYTES of a password -- anything
# beyond that is silently ignored by the algorithm itself, not by
# passlib. Without this guard, two different passwords that happen to
# share their first 72 bytes would hash identically. schemas/auth_schemas.py
# enforces the same 72-byte ceiling at the input layer so a request never
# even reaches here with an over-long password -- this check stays as a
# second, independent line of defense regardless.
_BCRYPT_MAX_PASSWORD_BYTES = 72


def get_password_hash(password: str) -> str:
    """Hash a plaintext password for storage. Never store the input this returns a hash of."""
    if len(password.encode("utf-8")) > _BCRYPT_MAX_PASSWORD_BYTES:
        raise ValueError(
            f"Password exceeds bcrypt's {_BCRYPT_MAX_PASSWORD_BYTES}-byte limit -- "
            "reject it at the input-validation layer instead of hashing here, since "
            "bcrypt would otherwise silently ignore everything past that point."
        )
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Check a plaintext password against a stored bcrypt hash. Constant-time under the hood via passlib."""
    return pwd_context.verify(plain_password, hashed_password)


# ----------------------------------------------------------------------
# JWT Token Generation & Verification (PyJWT)
# ----------------------------------------------------------------------
def _create_token(
    subject: str | int,
    token_type: TokenType,
    expires_delta: timedelta,
    max_lifetime: timedelta,
) -> str:
    """
    Shared claim-building logic for every token type this module issues.
    Not exported -- create_access_token / create_refresh_token are the
    public surface, each fixing its own token_type and max_lifetime so a
    caller can never request one type's token under another type's
    (longer) ceiling.
    """
    if expires_delta > max_lifetime:
        raise ValueError(
            f"expires_delta ({expires_delta}) exceeds the platform's maximum "
            f"{token_type} token lifetime of {max_lifetime}."
        )
    if expires_delta <= timedelta(0):
        raise ValueError(f"expires_delta must be positive, got {expires_delta}.")

    # timezone-aware UTC, not datetime.utcnow() -- utcnow() returns a
    # naive datetime (no tzinfo), deprecated as of Python 3.12 for
    # exactly that reason: it silently invites bugs when compared against
    # or combined with timezone-aware datetimes elsewhere in the codebase.
    now = datetime.now(timezone.utc)
    to_encode: dict[str, Any] = {
        "sub": str(subject),
        "type": token_type,
        "iat": now,
        "exp": now + expires_delta,
        # Unique per token. Not checked against a denylist anywhere yet --
        # that needs a datastore, which is out of scope for a pure crypto
        # utility file -- but every token already carries the id a future
        # revocation system (logout-everywhere, reset-password
        # invalidating old sessions, etc.) would need.
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(to_encode, settings.JWT_SECRET.get_secret_value(), algorithm=ALGORITHM)


def create_access_token(subject: str | int, expires_delta: timedelta | None = None) -> str:
    """
    Issue a signed access JWT for `subject` (typically a user id).

    expires_delta lets a caller request a SHORTER lifetime than the
    15-minute default (e.g. a step-up-auth flow issuing a short-lived
    token for one sensitive action) but can never request a longer one --
    enforced in _create_token, not left to caller discipline. A single
    careless call site elsewhere passing expires_delta=timedelta(days=30)
    would otherwise quietly undermine the platform's 15-minute expiry
    guarantee.
    """
    return _create_token(
        subject,
        token_type="access",
        expires_delta=expires_delta if expires_delta is not None else _MAX_ACCESS_TOKEN_LIFETIME,
        max_lifetime=_MAX_ACCESS_TOKEN_LIFETIME,
    )


def create_refresh_token(subject: str | int, expires_delta: timedelta | None = None) -> str:
    """
    Issue a signed refresh JWT -- long-lived, meant only to be exchanged
    for a new access token by a future /auth/refresh endpoint, never
    accepted directly by an endpoint expecting an access token.
    decode_access_token below enforces that separation via the "type"
    claim, so a leaked refresh token can't be replayed as an access token
    even though both are signed with the same secret.
    """
    return _create_token(
        subject,
        token_type="refresh",
        expires_delta=expires_delta if expires_delta is not None else _MAX_REFRESH_TOKEN_LIFETIME,
        max_lifetime=_MAX_REFRESH_TOKEN_LIFETIME,
    )


def create_mfa_challenge_token(subject: str | int, expires_delta: timedelta | None = None) -> str:
    """
    Issue a signed mfa_challenge JWT -- proves password verification
    already succeeded for `subject`, nothing more. Cannot be used to
    authenticate to any endpoint expecting an access token (the "type"
    claim blocks that the same way it blocks a refresh token from being
    used as an access token); its only valid use is being exchanged, via
    POST /auth/login/verify-mfa together with a TOTP code, for a real
    access + refresh pair.
    """
    return _create_token(
        subject,
        token_type="mfa_challenge",
        expires_delta=expires_delta if expires_delta is not None else _MAX_MFA_CHALLENGE_TOKEN_LIFETIME,
        max_lifetime=_MAX_MFA_CHALLENGE_TOKEN_LIFETIME,
    )


def _decode_token(token: str, expected_type: TokenType) -> dict[str, Any]:
    """
    Verify a JWT's signature and expiry, then confirm its "type" claim
    matches expected_type before returning its claims.

    algorithms=[ALGORITHM] is passed explicitly and is load-bearing, not
    decorative: PyJWT refuses to decode unless the token's algorithm is in
    this allowlist, which is what blocks both the classic "alg: none"
    forgery and cross-algorithm confusion attacks. Never trust the
    algorithm a token claims about itself in its own header.

    Raises jwt.PyJWTError (ExpiredSignatureError, InvalidSignatureError,
    etc.) on a bad signature/expiry, or jwt.InvalidTokenError if the type
    claim doesn't match -- both deliberately left uncaught here. Translating
    either into a 401 is the API-layer auth dependency's job, not this
    module's; catching and swallowing it here would hide *why*
    verification failed from whoever needs to decide how to respond.
    """
    claims = jwt.decode(
        token,
        settings.JWT_SECRET.get_secret_value(),
        algorithms=[ALGORITHM],
    )
    if claims.get("type") != expected_type:
        raise jwt.InvalidTokenError(f"Expected a {expected_type!r} token, got {claims.get('type')!r}.")
    return claims


def decode_access_token(token: str) -> dict[str, Any]:
    """
    Verify and decode an access token specifically. Rejects a
    structurally-valid, correctly-signed refresh token just as firmly as
    a forged one -- only the "type" claim tells them apart, and this
    checks it.
    """
    return _decode_token(token, expected_type="access")


def decode_refresh_token(token: str) -> dict[str, Any]:
    """Verify and decode a refresh token specifically -- the counterpart used by a future /auth/refresh endpoint."""
    return _decode_token(token, expected_type="refresh")


def decode_mfa_challenge_token(token: str) -> dict[str, Any]:
    """Verify and decode an mfa_challenge token specifically -- used only by POST /auth/login/verify-mfa."""
    return _decode_token(token, expected_type="mfa_challenge")