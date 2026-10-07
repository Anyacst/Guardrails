"""Cryptographic utilities for GuardX.

Guarantees:
- INV-006: Keyed HMAC-SHA256 for sensitive entity fingerprinting (anti-rainbow table)
- Ephemeral session key generation
"""

import hashlib
import hmac
import secrets


def generate_session_key(nbytes: int = 32) -> str:
    """Generates an unguessable hexadecimal session key for HMAC derivation."""
    return secrets.token_hex(nbytes)


def compute_keyed_fingerprint(value: str, key: str | bytes) -> str:
    """Computes a keyed HMAC-SHA256 fingerprint for identity/equality matching.
    
    Guarantees:
    - Never stores raw sensitive value.
    - Prevents offline dictionary and rainbow-table attacks.
    """
    if isinstance(key, str):
        key_bytes = key.encode("utf-8")
    else:
        key_bytes = key

    val_bytes = value.encode("utf-8")
    h = hmac.new(key_bytes, val_bytes, hashlib.sha256)
    return h.hexdigest()
