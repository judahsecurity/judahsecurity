"""Bounded path traversal proof reading an out-of-root operator sentinel.

A request that returns the contents of a file outside the intended directory is
directory traversal / local file inclusion. The probe reads a benign control
resource inside the served tree and a traversal URL that resolves, via ``../``
segments, to an operator-nominated file *outside* it whose ``sentinel_marker``
is known not to appear in a normal response. Confirmation requires the marker
only in the traversal response, with 2xx non-truncated bodies.

Nothing here is model generated: the control resource, the traversal template,
and the sentinel marker are operator policy, the read is non-destructive, and
the cache-busting token is nonce bound. A separate actor must repeat the recipe
against the same sentinel with a different nonce before a finding is published.
Only booleans and the marker's hash are retained, never the file contents.
"""

from __future__ import annotations

import hashlib
import re

from .browser import assert_in_scope
from .http_observe import observe_get

MIN_MARKER = 8


def path_canary_proof_valid(result: dict) -> bool:
    """Structural gate: the sentinel marker appears only through traversal."""
    if (not isinstance(result, dict)
            or result.get("operation") != "scoped_path_canary"
            or result.get("test_type") != "path_traversal"):
        return False
    nonce = str(result.get("nonce", ""))
    if (not nonce or len(nonce) > 40 or not nonce.isalnum()
            or not re.fullmatch(r"[0-9a-f]{64}", str(result.get("marker_sha256", "")))):
        return False
    control = result.get("control") or {}
    probe = result.get("probe") or {}
    if (control.get("marker_present") is not False
            or probe.get("marker_present") is not True):
        return False
    for row in (control, probe):
        status = row.get("status")
        if (not isinstance(status, int) or not 200 <= status < 300
                or row.get("truncated") is not False):
            return False
    return result.get("proof_confirmed") is True


def probe_path_canary(control_url: str, traversal_url: str, *,
                      sentinel_marker: str, allowed_origin: str,
                      state: dict | None, nonce: str) -> dict:
    """Prove directory traversal by reading an out-of-root operator sentinel.

    ``control_url`` is a benign in-tree resource; ``traversal_url`` resolves via
    ``../`` segments to an operator-nominated file outside the served root whose
    ``sentinel_marker`` is known not to appear in normal responses. Confirmed
    only when the marker is present solely in the traversal response.
    """
    if not nonce or len(nonce) > 40 or not nonce.isalnum():
        raise ValueError("A bounded alphanumeric nonce is required")
    if not isinstance(sentinel_marker, str) or len(sentinel_marker) < MIN_MARKER:
        raise ValueError("A substantial out-of-root sentinel marker is required")
    for url in (control_url, traversal_url):
        assert_in_scope(url, [allowed_origin])

    def _read(url: str) -> dict:
        observed = observe_get(url, [allowed_origin], state,
                               reflection_marker=sentinel_marker)
        return {
            "status": observed.get("status"),
            "truncated": observed.get("truncated"),
            "marker_present": bool(observed.get("reflection_detected")),
        }

    control = _read(control_url)
    probe = _read(traversal_url)
    confirmed = bool(
        probe["marker_present"] and not control["marker_present"]
        and isinstance(control["status"], int) and 200 <= control["status"] < 300
        and isinstance(probe["status"], int) and 200 <= probe["status"] < 300
        and control["truncated"] is False and probe["truncated"] is False
    )
    return {
        "operation": "scoped_path_canary", "test_type": "path_traversal",
        "nonce": nonce, "requests_sent": 2,
        "marker_sha256": hashlib.sha256(sentinel_marker.encode()).hexdigest(),
        "traversal_template": traversal_url, "control_template": control_url,
        "control": control, "probe": probe,
        "proof_confirmed": confirmed, "finding": False,
    }
