"""
Core: dependencies.py
Shared FastAPI dependencies that need to bridge security (JWT
verification) with the database (User lookup).

Deliberately NOT part of core/security.py: that file's own module
docstring scopes it to "strictly cryptographic utility functions -- no
user/DB models are imported or referenced here." get_current_user below
inherently needs to query User, so it can't live there without breaking
that boundary. This is the file that's allowed to import both security
and models -- the first thing in this codebase that actually calls
decode_access_token, which has existed since core/security.py was built
several steps ago but had no consumer until now.
"""
import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from core.database import get_db
from core.security import decode_access_token
from models.user_model import User

_bearer_scheme = HTTPBearer()
# HTTPBearer, not OAuth2PasswordBearer: this platform's /auth/login takes
# a JSON UserLogin body, not the form-encoded username/password fields
# OAuth2PasswordBearer's flow expects. Both extract the same "Authorization:
# Bearer <token>" header at runtime, but OAuth2PasswordBearer also drives
# FastAPI's auto-generated OpenAPI docs to describe an OAuth2 password
# grant this API doesn't actually implement. HTTPBearer describes what's
# really here.


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    """
    Zero-trust gate for any protected route: verifies the bearer token is
    a genuine, unexpired, correctly-typed access token, then loads and
    returns the User it names.

    decode_access_token's "type" claim check (built when core/security.py
    was refactored to add refresh tokens) is what stops a leaked refresh
    token from being usable here -- a structurally valid, correctly-signed
    refresh token is rejected by this dependency exactly as firmly as a
    forged token would be.

    Every failure mode -- missing/malformed/expired/wrong-type/forged
    token, or a token naming a user that no longer exists -- raises the
    same 401 with the same generic message. Distinguishing "expired" from
    "forged" from "user deleted" in the response would leak information
    about *why* access was denied to whoever's holding the token, which
    is exactly the kind of signal a zero-trust boundary shouldn't hand out
    -- same reasoning as login's identical "Invalid email or password" for
    every failure case in api/auth_routes.py.
    """
    unauthorized = HTTPException(
        status_code=401,
        detail="Could not validate credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        claims = decode_access_token(credentials.credentials)
    except jwt.PyJWTError:
        # Catches every PyJWT failure (expired, bad signature, alg
        # mismatch, malformed) AND decode_access_token's own
        # jwt.InvalidTokenError for a wrong-type token -- InvalidTokenError
        # is itself a PyJWTError subclass, confirmed directly against the
        # real library rather than assumed.
        raise unauthorized

    try:
        user_id = int(claims.get("sub"))
    except (TypeError, ValueError):
        # A token that verified correctly but somehow carries a
        # non-numeric subject -- shouldn't happen given create_access_token
        # always stores str(an int or str subject) and signature
        # verification already passed above, but a corrupted/crafted
        # claim shouldn't reach an int() call unguarded.
        raise unauthorized

    user = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
    if user is None:
        raise unauthorized

    return user