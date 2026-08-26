"""
core/encryption.py

Field-Level Encryption (FLE) for regulated PII -- government tax IDs, PAN
numbers, and similar identifiers that must never touch disk in plaintext.

Algorithm: AES-256-GCM.
    - AEAD (Authenticated Encryption with Associated Data): protects both
      confidentiality AND integrity. A tampered ciphertext raises
      cryptography.exceptions.InvalidTag on decrypt instead of silently
      returning corrupted PII.
    - Nonce is 96 bits (the size AES-GCM is designed for) and is generated
      fresh with os.urandom() on every encryption call -- never reused.
      Reusing a nonce with the same key catastrophically breaks GCM's
      confidentiality guarantees.

Storage format: base64(nonce[12 bytes] + ciphertext_with_tag), stored in a
single String column -- no schema change beyond widening the column (see
models/user_model.py) to fit the extra bytes.

KEY MANAGEMENT (placeholder -- read before wiring to production):
    settings.FIELD_ENCRYPTION_KEY (core/config.py) holds a base64-encoded
    32-byte key, sourced from .env. It's typed as Pydantic's SecretStr so
    it never appears in a repr()/log/traceback -- _decoded_key() below is
    the one place in this module that calls .get_secret_value() to reach
    the underlying string; nothing else in this file needs to. This is a
    placeholder suitable for local dev and CI. In production, the key
    should be issued and rotated by a
    managed KMS (AWS KMS, GCP Cloud KMS, HashiCorp Vault) via envelope
    encryption -- the app holds a short-lived data key unwrapped from the
    KMS, not a static secret sitting in .env indefinitely. Swap out
    _decoded_key() below for a KMS call when moving off placeholder status.

KEY ROTATION: this placeholder assumes one active key. Rotating keys
without a big-bang re-encryption migration typically means prefixing the
stored value with a key-version tag (e.g. "v2:<base64>") so old rows keep
decrypting under their original key while new writes use the current one.
Not implemented here -- flagging so it isn't forgotten later.
"""
from __future__ import annotations

import base64
import os
from functools import lru_cache

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy.engine import Dialect
from sqlalchemy.types import String, TypeDecorator

from core.config import settings  # adjust import path if config.py ends up elsewhere

_NONCE_LENGTH_BYTES = 12  # 96-bit nonce, the size AES-GCM is designed for


@lru_cache(maxsize=1)
def _decoded_key() -> bytes:
    """
    Decode the base64 key once per process instead of on every row.

    At 10M+ concurrent users this runs on every encrypt/decrypt call, so a
    redundant base64 decode per row is wasted CPU at scale. settings is
    immutable after app startup, so caching the decode is safe.
    """
    # .get_secret_value() -- FIELD_ENCRYPTION_KEY is a SecretStr (see
    # core/config.py), so the plain string has to be unwrapped explicitly;
    # base64.b64decode() can't operate on the SecretStr wrapper directly.
    return base64.b64decode(settings.FIELD_ENCRYPTION_KEY.get_secret_value())


class EncryptedString(TypeDecorator):
    """
    Transparent AES-256-GCM encryption for a single string column.

    The ORM and application code only ever see plaintext `str` -- encryption
    happens on the way into the DB, decryption on the way out.

    IMPORTANT: do not put a plain equality index on a column using this
    type. Ciphertext differs on every write (random nonce), so a B-tree
    index over it can never satisfy "find row where column == X" lookups.
    If a column needs to be searchable later, pair it with a separate
    deterministic blind-index column (e.g. HMAC-SHA256(value, index_key))
    rather than indexing the ciphertext itself.
    """

    impl = String
    cache_ok = True  # no per-instance state affects the encrypted output, so compiled-statement caching is safe

    def process_bind_param(self, value: str | None, dialect: Dialect) -> str | None:
        """Encrypt on the way INTO the database (INSERT / UPDATE)."""
        if value is None:
            return None
        aesgcm = AESGCM(_decoded_key())
        nonce = os.urandom(_NONCE_LENGTH_BYTES)
        ciphertext = aesgcm.encrypt(nonce, value.encode("utf-8"), associated_data=None)
        return base64.b64encode(nonce + ciphertext).decode("ascii")

    def process_result_value(self, value: str | None, dialect: Dialect) -> str | None:
        """Decrypt on the way OUT of the database (SELECT)."""
        if value is None:
            return None
        raw = base64.b64decode(value)
        nonce, ciphertext = raw[:_NONCE_LENGTH_BYTES], raw[_NONCE_LENGTH_BYTES:]
        aesgcm = AESGCM(_decoded_key())
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
        except InvalidTag as exc:
            # Ciphertext was tampered with, truncated, or encrypted under a
            # different key. Fail loudly -- never return corrupted PII.
            raise ValueError("Failed to decrypt field: ciphertext integrity check failed") from exc
        return plaintext.decode("utf-8")