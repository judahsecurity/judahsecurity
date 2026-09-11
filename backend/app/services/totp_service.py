"""Small RFC 6238 TOTP helper used by authenticated browser scans."""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time
from urllib.parse import parse_qs, urlparse


def normalize_totp_secret(value: str) -> str:
    """Return a validated, padding-free Base32 TOTP secret.

    Authenticator setup URIs are accepted so operators can paste either the
    raw secret or the ``otpauth://`` value encoded in a QR code.
    """
    secret = (value or "").strip()
    if secret.lower().startswith("otpauth://"):
        query = parse_qs(urlparse(secret).query)
        secret = (query.get("secret") or [""])[0]

    secret = "".join(secret.split()).replace("-", "").upper().rstrip("=")
    if not secret:
        raise ValueError("TOTP secret is empty")

    padded = secret + "=" * ((8 - len(secret) % 8) % 8)
    try:
        base64.b32decode(padded, casefold=True)
    except Exception as exc:
        raise ValueError("TOTP secret must be valid Base32 or an otpauth URI") from exc
    return secret


def generate_totp(
    secret: str,
    *,
    at_time: float | None = None,
    digits: int = 6,
    period: int = 30,
) -> str:
    """Generate a standard SHA-1 time-based one-time password."""
    if digits not in (6, 7, 8):
        raise ValueError("TOTP digits must be 6, 7, or 8")
    if period <= 0:
        raise ValueError("TOTP period must be positive")

    normalized = normalize_totp_secret(secret)
    padded = normalized + "=" * ((8 - len(normalized) % 8) % 8)
    key = base64.b32decode(padded, casefold=True)
    timestamp = time.time() if at_time is None else at_time
    counter = struct.pack(">Q", int(timestamp) // period)
    digest = hmac.new(key, counter, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10 ** digits)).zfill(digits)
