"""
API: auth_routes.py
Core authentication endpoints: signup, login, Google Sign-In, and TOTP-
based MFA (setup, confirm, and the login-time challenge/verify step).
"""
import logging

import jwt
import pyotp
from fastapi import APIRouter, Depends, HTTPException
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token as google_id_token
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from core.config import settings
from core.database import get_db
from core.dependencies import get_current_user
from core.security import (
    create_access_token,
    create_mfa_challenge_token,
    create_refresh_token,
    decode_mfa_challenge_token,
    get_password_hash,
    verify_password,
)
from models.user_model import User
from schemas.auth_schemas import (
    GoogleSignInRequest,
    MfaChallengeResponse,
    MfaConfirmRequest,
    MfaSetupResponse,
    MfaVerifyRequest,
    TokenResponse,
    UserLogin,
    UserSignUp,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])


class SignUpResponse(BaseModel):
    """
    Deliberately not TokenResponse -- signup doesn't auto-issue tokens
    (see signup()'s docstring for why). Defined here rather than in
    schemas/auth_schemas.py since a signup confirmation shape wasn't part
    of what was scoped there.
    """

    id: int
    email_address: str
    kyc_status: str
    message: str = "Account created. Please log in to continue."


# Computed once at import time (module load / app startup), not per
# request -- bcrypt is deliberately slow, and there's no reason to pay
# that cost again on every single login attempt against a nonexistent
# email. See the comment in login() below for what this is actually for.
_TIMING_SAFE_DUMMY_HASH = get_password_hash("not-a-real-password-used-only-for-timing-parity")


@router.post("/signup", response_model=SignUpResponse, status_code=201)
async def signup(payload: UserSignUp, db: Session = Depends(get_db)) -> SignUpResponse:
    """
    Register a new user with kyc_status="PENDING". Does NOT return tokens
    -- unlike login, signup wasn't specified to return TokenResponse, and
    keeping it that way is also the more conservative choice for a
    bank-grade system: issuing a fully-privileged access token the moment
    an account exists, before any verification, is premature trust that
    many real financial systems deliberately avoid. Log in separately
    afterward to get tokens.

    Only identity + credentials are collected here. tax_id_number,
    gst_number, iec_code, and virtual_bank_account are all correctly left
    unset (None) on the new User row -- those are KYC-stage data per the
    Zero-Touch VAM Onboarding architecture, collected later, not at
    signup. This is exactly why those columns needed to become nullable
    on User this same step; without that change this insert would fail
    outright.
    """
    existing = db.execute(select(User).where(User.email_address == payload.email_address)).scalar_one_or_none()
    if existing is not None:
        # Telling the requester an email is already registered is normal,
        # expected signup UX (unlike login's error, which stays generic
        # regardless of cause -- see login() below for why those two
        # cases are treated differently on purpose, not inconsistently).
        raise HTTPException(status_code=409, detail="An account with this email already exists.")

    user = User(
        entity_type=payload.entity_type,
        full_name=payload.full_name,
        email_address=payload.email_address,
        password_hash=get_password_hash(payload.password),
        kyc_status="PENDING",
    )

    try:
        db.add(user)
        db.commit()
    except IntegrityError:
        db.rollback()
        # Race: two concurrent signups with the same email both passed
        # the SELECT check above before either committed. Same class of
        # race bank_webhook.py's idempotency handling guards against -- a
        # check-then-insert is never airtight under concurrency; the
        # database's own unique constraint on email_address is what
        # actually guarantees this, this except just turns that guarantee
        # into a clean 409 instead of a raw 500.
        raise HTTPException(status_code=409, detail="An account with this email already exists.")
    except Exception:
        db.rollback()
        logger.exception("Unexpected failure creating user during signup (email=%s)", payload.email_address)
        raise

    db.refresh(user)
    return SignUpResponse(id=user.id, email_address=user.email_address, kyc_status=user.kyc_status)


@router.post("/login", response_model=TokenResponse | MfaChallengeResponse)
async def login(payload: UserLogin, db: Session = Depends(get_db)) -> TokenResponse | MfaChallengeResponse:
    """
    Verify credentials and issue an access + refresh token pair -- unless
    the account has MFA enabled, in which case password verification
    alone is not enough: this returns an MfaChallengeResponse instead,
    and the real tokens only come from a subsequent
    POST /auth/login/verify-mfa call with a valid TOTP code.

    "Invalid email or password" is returned for BOTH "no such account"
    and "account exists, wrong password" -- never anything that lets a
    caller distinguish which one happened. Revealing that would turn this
    endpoint into an account-enumeration oracle: an attacker could submit
    a list of email addresses and learn, purely from which error came
    back, which ones are registered on this platform. That's a different
    call than signup's (where confirming an email is already registered
    is normal, expected UX) specifically because this is the endpoint an
    attacker would actually use that signal against.
    """
    user = db.execute(select(User).where(User.email_address == payload.email_address)).scalar_one_or_none()

    if user is not None and user.password_hash is not None:
        password_valid = verify_password(payload.password, user.password_hash)
    else:
        # Covers BOTH "no such account" and "account exists but has no
        # password because it was created via Google Sign-In" -- treated
        # identically on purpose. Telling a Google-only user "this
        # account has no password, use Google Sign-In instead" would leak
        # exactly the kind of information the enumeration-prevention
        # design above is trying to avoid revealing through this endpoint
        # specifically.
        verify_password(payload.password, _TIMING_SAFE_DUMMY_HASH)
        password_valid = False

    if user is None or not password_valid:
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if user.mfa_enabled:
        # MFA is a SECOND factor checked after the first (password)
        # succeeds, not instead of it -- password verification above
        # already happened, which is exactly the correct place for this
        # check to sit. Real tokens are deliberately NOT issued here; see
        # MfaChallengeResponse's own docstring for why this is a
        # different response shape, not an optional-field variant of
        # TokenResponse.
        challenge_token = create_mfa_challenge_token(subject=user.id)
        return MfaChallengeResponse(mfa_challenge_token=challenge_token)

    access_token = create_access_token(subject=user.id)
    refresh_token = create_refresh_token(subject=user.id)

    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@router.post("/login/verify-mfa", response_model=TokenResponse)
async def login_verify_mfa(payload: MfaVerifyRequest, db: Session = Depends(get_db)) -> TokenResponse:
    """
    Second step of login for an MFA-enabled account: exchanges a valid
    mfa_challenge_token (from login() above) plus a correct TOTP code for
    real access + refresh tokens.

    Every failure path here returns the identical generic 401, same
    enumeration-prevention reasoning as login() itself: an expired/
    forged challenge token, a challenge token naming a user who somehow
    no longer has MFA enabled, and a wrong TOTP code all look the same to
    the caller. Distinguishing them would hand an attacker probing this
    endpoint a signal about exactly which part of their guess was wrong.
    """
    unauthorized = HTTPException(status_code=401, detail="Invalid or expired MFA verification.")

    try:
        claims = decode_mfa_challenge_token(payload.mfa_challenge_token)
    except jwt.PyJWTError:
        raise unauthorized

    try:
        user_id = int(claims.get("sub"))
    except (TypeError, ValueError):
        raise unauthorized

    user = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
    if user is None or not user.mfa_enabled or user.mfa_secret is None:
        raise unauthorized

    totp = pyotp.TOTP(user.mfa_secret)
    if not totp.verify(payload.totp_code, valid_window=1):
        # valid_window=1: accepts the current 30-second code plus one
        # window on either side, standard practice to absorb ordinary
        # clock drift between the user's device and this server without
        # meaningfully widening the guessable window.
        raise unauthorized

    access_token = create_access_token(subject=user.id)
    refresh_token = create_refresh_token(subject=user.id)

    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@router.post("/mfa/setup", response_model=MfaSetupResponse)
async def setup_mfa(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> MfaSetupResponse:
    """
    Generates a new TOTP secret and stores it -- but does NOT enable MFA
    yet. mfa_enabled only flips to True once /auth/mfa/confirm verifies
    the caller can actually produce a valid code from it, so a failed or
    incomplete setup (QR scanned wrong, app never actually configured)
    can't lock the account out of its own login.
    """
    if current_user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is already enabled for this account.")

    secret = pyotp.random_base32()
    current_user.mfa_secret = secret

    try:
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Unexpected failure saving MFA secret during setup (user_id=%s)", current_user.id)
        raise

    provisioning_uri = pyotp.TOTP(secret).provisioning_uri(name=current_user.email_address, issuer_name="JvX Nexus")
    return MfaSetupResponse(secret=secret, provisioning_uri=provisioning_uri)


@router.post("/mfa/confirm", response_model=MfaSetupResponse)
async def confirm_mfa(
    payload: MfaConfirmRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> MfaSetupResponse:
    """
    Verifies the first real code from the caller's newly-configured
    authenticator app, and only on success flips mfa_enabled to True.
    Reusing MfaSetupResponse's shape here (rather than a new schema) since
    there's genuinely nothing more to say than the same secret/URI already
    returned, plus a message confirming activation -- not concealing
    anything by returning them again.
    """
    if current_user.mfa_secret is None:
        raise HTTPException(status_code=400, detail="No MFA setup in progress -- call /auth/mfa/setup first.")
    if current_user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is already enabled for this account.")

    totp = pyotp.TOTP(current_user.mfa_secret)
    if not totp.verify(payload.totp_code, valid_window=1):
        raise HTTPException(status_code=400, detail="Invalid code -- MFA was not enabled. Try again with the current code from your app.")

    current_user.mfa_enabled = True

    try:
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Unexpected failure enabling MFA (user_id=%s)", current_user.id)
        raise

    provisioning_uri = pyotp.TOTP(current_user.mfa_secret).provisioning_uri(name=current_user.email_address, issuer_name="JvX Nexus")
    return MfaSetupResponse(secret=current_user.mfa_secret, provisioning_uri=provisioning_uri, message="MFA successfully enabled.")


@router.post("/google", response_model=TokenResponse)
async def google_signin(payload: GoogleSignInRequest, db: Session = Depends(get_db)) -> TokenResponse:
    """
    Verifies a Google-issued ID token (obtained client-side via Google
    Identity Services -- this endpoint only ever verifies, it never
    issues or redirects) and either logs in an existing user or creates a
    new one, then returns this platform's own access + refresh token pair
    exactly like login() does above. Past this point, a Google-
    authenticated and a password-authenticated user are indistinguishable
    to every other route in this codebase -- same TokenResponse, same
    downstream JWT handling, same get_current_user dependency.

    AUTO-LINKING BY VERIFIED EMAIL: if no User is found by google_id but
    one IS found by email_address, that existing account gets linked
    (google_id set on it) rather than rejected or duplicated -- and
    duplication isn't even possible given email_address's existing unique
    constraint. This only happens when Google's own email_verified claim
    is true. Relying on Google's verification of email ownership here is
    standard, widely-used practice, but it is a real, security-relevant
    design choice, not an incidental implementation detail.
    """
    try:
        claims = google_id_token.verify_oauth2_token(
            payload.id_token,
            google_requests.Request(),
            settings.GOOGLE_OAUTH_CLIENT_ID,
        )
    except ValueError as exc:
        # google-auth's verify_oauth2_token is documented to raise
        # ValueError for verification failures -- expired token, bad
        # signature, wrong audience, malformed token. This is the primary
        # expected failure path, per google-auth's own documentation (not
        # verified against the actual installed library in this
        # environment, since it isn't installed here).
        logger.info("Google ID token verification failed: %s", exc)
        raise HTTPException(status_code=401, detail="Invalid or expired Google token.")
    except Exception:
        # Defensive fallback: if google-auth's real exception hierarchy
        # turns out to differ from what's documented, this still fails
        # safely with a 401 instead of an unhandled 500.
        logger.exception("Unexpected error verifying a Google ID token.")
        raise HTTPException(status_code=401, detail="Invalid or expired Google token.")

    google_id = claims.get("sub")
    email = claims.get("email")
    if not google_id or not email:
        raise HTTPException(status_code=401, detail="Google token did not include the required identity claims.")
    if not claims.get("email_verified", False):
        raise HTTPException(status_code=401, detail="Google account email is not verified.")

    full_name = claims.get("name") or email

    user = db.execute(select(User).where(User.google_id == google_id)).scalar_one_or_none()

    if user is None:
        # Not linked yet under this google_id -- check whether an
        # existing password-based account already owns this (Google-
        # verified) email, and link rather than reject or duplicate.
        user = db.execute(select(User).where(User.email_address == email)).scalar_one_or_none()

        if user is not None:
            user.google_id = google_id
        else:
            # Genuinely new user, never seen by either method before.
            if payload.entity_type is None:
                raise HTTPException(
                    status_code=400,
                    detail="entity_type is required to create a new account via Google Sign-In.",
                )
            user = User(
                entity_type=payload.entity_type,
                full_name=full_name,
                email_address=email,
                password_hash=None,
                google_id=google_id,
                kyc_status="PENDING",
            )
            db.add(user)

    try:
        db.commit()
    except IntegrityError:
        # Race: two concurrent Google Sign-In attempts for the same new
        # google_id, or a Google Sign-In racing a password-based signup
        # for the same email -- same class of race signup()'s own
        # IntegrityError handling guards against, same resolution.
        db.rollback()
        raise HTTPException(status_code=409, detail="Could not complete Google Sign-In due to a conflicting account.")
    except Exception:
        db.rollback()
        logger.exception("Unexpected failure during Google Sign-In (google_id=%s)", google_id)
        raise

    db.refresh(user)

    access_token = create_access_token(subject=user.id)
    refresh_token = create_refresh_token(subject=user.id)

    return TokenResponse(access_token=access_token, refresh_token=refresh_token)