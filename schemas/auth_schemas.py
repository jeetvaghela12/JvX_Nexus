"""
Schemas: auth_schemas.py
Pydantic request/response schemas for the authentication API.

NEW FOLDER: schemas/ wasn't part of the folder structure established
earlier this session (models/, core/, services/, api/) -- same kind of
deliberate expansion as compliance_model.py and auth_model.py were,
flagging it the same way rather than adding it silently.
"""
import string
from typing import Literal

from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator

# Mirrors core/security.py's own bcrypt limit exactly -- catching an
# over-length password here gives a clear 422 at the schema boundary
# instead of a less obvious ValueError surfacing later inside
# get_password_hash.
_BCRYPT_MAX_PASSWORD_BYTES = 72
_MIN_PASSWORD_LENGTH = 12
_SPECIAL_CHARACTERS = string.punctuation


def validate_password_strength(password: str) -> str:
    """
    Shared strength check -- exported (not underscored) since a future
    password-reset schema will need the exact same rules applied to a
    new password there too, not just at signup.

    NIST SP 800-63B's current guidance actually favors length over
    composition rules (a long passphrase over "must contain a symbol"),
    on the grounds that composition requirements often just push people
    toward predictable patterns like "Password1!". Not followed here --
    composition rules are still what's specified and what's expected of a
    bank-grade system by most auditors/users in practice, so this
    enforces both length AND composition rather than picking one. Worth
    knowing this is a deliberate choice, not an oversight of the more
    current guidance -- swap to a pure length-based check if you'd rather
    follow NIST's current position.
    """
    encoded_length = len(password.encode("utf-8"))
    if encoded_length > _BCRYPT_MAX_PASSWORD_BYTES:
        raise ValueError(
            f"Password must be at most {_BCRYPT_MAX_PASSWORD_BYTES} bytes "
            f"(bcrypt's hard limit) -- got {encoded_length}."
        )
    if len(password) < _MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {_MIN_PASSWORD_LENGTH} characters long.")
    if not any(c.isupper() for c in password):
        raise ValueError("Password must contain at least one uppercase letter.")
    if not any(c.islower() for c in password):
        raise ValueError("Password must contain at least one lowercase letter.")
    if not any(c.isdigit() for c in password):
        raise ValueError("Password must contain at least one digit.")
    if not any(c in _SPECIAL_CHARACTERS for c in password):
        raise ValueError("Password must contain at least one special character.")
    return password


class UserSignUp(BaseModel):
    """
    Registration input. password/confirm_password are compared in
    _passwords_match below; only password is ever used past validation
    (get_password_hash(payload.password) in the route) -- confirm_password
    exists purely to catch a typo at input time, never touches the
    database.

    SCHEMA/MODEL MISMATCH, FLAGGED NOW SINCE IT WILL BLOCK THE NEXT STEP:
    this deliberately does NOT collect tax_id_number or virtual_bank_account,
    even though both are currently NOT NULL columns on User. Those are
    KYC-stage data -- per this project's own "sign up, log in, then start
    KYC" flow, neither exists yet at initial signup. As things stand,
    api/auth_routes.py's /signup literally cannot INSERT a User row
    without a value for both. Most likely fix: make those two columns
    nullable on User, populated later once KYC actually collects them --
    a real schema change, and worth confirming before the routes step,
    not something to silently work around with placeholder values in the
    insert logic once that route gets built.
    """

    email_address: EmailStr
    password: str = Field(min_length=_MIN_PASSWORD_LENGTH, max_length=_BCRYPT_MAX_PASSWORD_BYTES)
    confirm_password: str
    full_name: str = Field(min_length=1, max_length=255)
    # entity_type's canonical value set was never confirmed elsewhere in
    # this project (see user_model.py's own comment on that column) --
    # "freelancer"/"agency" match the placeholder already used when a
    # local test user was seeded earlier. Adjust this Literal if the real
    # onboarding flow uses different values.
    entity_type: Literal["freelancer", "agency"]

    @field_validator("password")
    @classmethod
    def _password_meets_strength_requirements(cls, value: str) -> str:
        return validate_password_strength(value)

    @model_validator(mode="after")
    def _passwords_match(self) -> "UserSignUp":
        if self.password != self.confirm_password:
            raise ValueError("password and confirm_password do not match.")
        return self


class UserLogin(BaseModel):
    """
    Login input. Deliberately NO strength rules on password here, unlike
    UserSignUp -- this validates an attempt against an EXISTING password,
    not a new one being set. Rejecting a legitimately weak password some
    already-registered user signed up with (before this rule existed, or
    via a different onboarding path) would lock them out at login, which
    is a bug in login, not a feature of it.
    """

    email_address: EmailStr
    password: str = Field(min_length=1)


class TokenResponse(BaseModel):
    """
    Shape returned by /login (and, once built, /auth/refresh). Both
    access_token and refresh_token are always present together here --
    if MFA readiness later means login can also return an intermediate
    "mfa_challenge" state instead of full tokens, that's a different
    response shape, not an optional-field variant of this one; keeping
    TokenResponse meaning "here are your real, usable tokens" rather than
    overloading it avoids a client having to check which fields are
    populated to know what it actually got.
    """

    access_token: str
    refresh_token: str
    token_type: Literal["bearer"] = "bearer"


class GoogleSignInRequest(BaseModel):
    """
    Input for POST /auth/google. id_token is the signed JWT Google's
    Identity Services client library hands the frontend after the user
    completes "Sign in with Google" -- this backend verifies it, it
    doesn't issue it.

    entity_type is optional here on purpose: it's only actually required
    when this call results in creating a brand-new User (no existing
    account found by google_id or email) -- an existing user logging back
    in doesn't need it, and this schema has no way to know in advance
    which case a given request is. api/auth_routes.py's google_signin()
    is where that distinction, and the resulting validation, actually
    happens.
    """

    id_token: str = Field(min_length=1)
    entity_type: Literal["freelancer", "agency"] | None = None


class MfaSetupResponse(BaseModel):
    """
    Output for POST /auth/mfa/setup. secret is returned raw (not
    SecretStr-wrapped, unlike password/confirm_password on UserSignUp) --
    unlike a password, this value is MEANT to leave the server and be
    entered into an authenticator app; wrapping it wouldn't protect
    anything here since the whole point is handing it to the caller.
    provisioning_uri is the otpauth:// URI a QR-code library can render
    directly -- this backend returns the URI string, not a QR image;
    rendering that into a scannable code is a frontend concern with
    established libraries for exactly this.
    """

    secret: str
    provisioning_uri: str
    message: str = "Scan this with an authenticator app, then confirm with a generated code via /auth/mfa/confirm."


class MfaConfirmRequest(BaseModel):
    """Input for POST /auth/mfa/confirm -- proves the user can actually generate a valid code before mfa_enabled flips to True."""

    totp_code: str = Field(min_length=6, max_length=6)


class MfaVerifyRequest(BaseModel):
    """
    Input for POST /auth/login/verify-mfa -- the second step of a login
    for an MFA-enabled account. mfa_challenge_token is what /auth/login
    returned instead of real tokens; totp_code is read off the user's
    authenticator app at the moment of this call.
    """

    mfa_challenge_token: str = Field(min_length=1)
    totp_code: str = Field(min_length=6, max_length=6)


class MfaChallengeResponse(BaseModel):
    """
    What POST /auth/login returns INSTEAD of TokenResponse when
    user.mfa_enabled is True -- a deliberately separate shape, not an
    optional-field variant of TokenResponse, matching the design note
    already on TokenResponse itself: this means "here is a challenge to
    complete," not "here are your real, usable tokens," and a client
    checking which fields are populated to figure out what it got would
    be exactly the ambiguity keeping these as two distinct shapes avoids.
    """

    mfa_challenge_token: str
    message: str = "Password verified. Submit your authenticator code to /auth/login/verify-mfa to complete login."