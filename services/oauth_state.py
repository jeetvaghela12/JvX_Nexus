"""
Services: oauth_state.py
A reusable, self-contained OAuth CSRF-state token: HMAC-signed,
timestamped, tied to a specific user_id.

WHY THIS EXISTS: an OAuth callback endpoint is hit by the user's browser
being redirected by the THIRD-PARTY provider (Google), not by an
authenticated API call from JvX's own frontend -- there is no
Authorization header on that request, so Depends(get_current_user)
cannot run there. This token is how the callback endpoint knows which
user initiated the flow, and is the CSRF protection the OAuth `state`
parameter exists for.

Deliberately self-contained: does not touch core/security.py's JWT
machinery, and does not need a new database table or cache -- the token
carries and verifies its own integrity. Written generically enough that
any future OAuth integration (PayPal, Wise -- see the Pillar 2 roadmap)
can reuse this module unchanged, rather than each needing its own
CSRF-state mechanism.
"""
import base64
import binascii
import hmac
import hashlib
import time

from core.config import settings

_STATE_MAX_AGE_SECONDS = 600  # 10 minutes -- an OAuth consent flow should complete well within this


class InvalidOAuthStateError(Exception):
    """
    Raised when a state token fails signature verification, is malformed,
    or has expired. Treated as a hard rejection everywhere it's used,
    never downgraded to a warning -- this token IS the CSRF protection
    for the entire OAuth flow, so a failure here means either an attack
    or a genuinely stale/replayed link, and both should be refused.
    """


def create_oauth_state(user_id: int) -> str:
    """Called when the user clicks "Connect AdSense" -- embeds their
    user_id and an issued-at timestamp, signed so the callback endpoint
    can trust it came from this server and hasn't been tampered with."""
    payload = f"{user_id}:{int(time.time())}"
    signature = hmac.new(
        settings.OAUTH_STATE_SECRET.get_secret_value().encode(),
        payload.encode(),
        hashlib.sha256,
    ).hexdigest()
    raw = f"{payload}:{signature}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


def verify_oauth_state(state: str) -> int:
    """
    Returns the verified user_id if the state token is valid and fresh;
    raises InvalidOAuthStateError otherwise. Every failure mode -- bad
    encoding, wrong shape, signature mismatch, expiry -- is folded into
    the same exception type, deliberately: giving an attacker a different
    error for "malformed" versus "wrong signature" versus "expired" leaks
    information that makes forging a valid token incrementally easier.
    """
    try:
        raw = base64.urlsafe_b64decode(state.encode()).decode()
        user_id_str, issued_at_str, signature = raw.split(":")
    except (ValueError, UnicodeDecodeError, binascii.Error) as exc:
        raise InvalidOAuthStateError("Malformed state token.") from exc

    payload = f"{user_id_str}:{issued_at_str}"
    expected_signature = hmac.new(
        settings.OAUTH_STATE_SECRET.get_secret_value().encode(),
        payload.encode(),
        hashlib.sha256,
    ).hexdigest()

    # Constant-time comparison, same reasoning as the bank-webhook HMAC
    # check in b2b_routes.py -- a naive == comparison leaks timing
    # information an attacker could use to forge a valid signature
    # byte-by-byte.
    if not hmac.compare_digest(signature, expected_signature):
        raise InvalidOAuthStateError("State token signature mismatch -- possible CSRF attempt.")

    try:
        issued_at = int(issued_at_str)
        user_id = int(user_id_str)
    except ValueError as exc:
        raise InvalidOAuthStateError("Malformed state token payload.") from exc

    if time.time() - issued_at > _STATE_MAX_AGE_SECONDS:
        raise InvalidOAuthStateError("State token expired -- start the connection again.")

    return user_id