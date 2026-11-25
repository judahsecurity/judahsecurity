"""Signed intake for the isolated stealer-log collector.

The collector runs in a separate, disposable environment: it joins the
channels, triages and sandbox-parses archives there, filters to in-scope
records, and POSTs normalized JSON to the platform. The platform never receives
an archive, only vetted records.

Each request is authenticated with an HMAC-SHA256 signature over the raw body
using a shared secret, plus a timestamp to bound replay. The signature proves
the sender holds the secret; it is not a user credential.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
from typing import Optional

logger = logging.getLogger(__name__)

SIGNATURE_HEADER = "x-collector-signature"
TIMESTAMP_HEADER = "x-collector-timestamp"


def sign_payload(secret: str, timestamp: str, body: bytes) -> str:
    """Return the hex HMAC-SHA256 of ``timestamp.body`` — used by both sides."""
    mac = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256)
    return mac.hexdigest()


def verify_signature(
    *,
    secret: Optional[str],
    signature: Optional[str],
    timestamp: Optional[str],
    body: bytes,
    max_skew_seconds: int,
    now: Optional[float] = None,
) -> tuple[bool, str]:
    """Return (ok, reason). Constant-time compare; bounded clock skew."""
    if not secret:
        return False, "Collector intake is not configured (no shared secret)."
    if not signature or not timestamp:
        return False, "Missing collector signature or timestamp header."
    try:
        ts = float(timestamp)
    except (TypeError, ValueError):
        return False, "Invalid timestamp header."
    now = time.time() if now is None else now
    if abs(now - ts) > max_skew_seconds:
        return False, "Timestamp outside the accepted window (possible replay)."
    expected = sign_payload(secret, timestamp, body)
    if not hmac.compare_digest(expected, signature):
        return False, "Signature mismatch."
    return True, "ok"
