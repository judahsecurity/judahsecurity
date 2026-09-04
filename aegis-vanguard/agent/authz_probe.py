"""
Authorization probe — multi-identity differential testing for IDOR / BOLA.

Broken object-level authorization is the class scanners miss because proving it
needs *two identities and a diff*: request an object as its owner, then request
the same object as a different user (and unauthenticated), and see whether the
other principal gets the owner's data. The authz_hunter's prompt already told it
to "compare_requests baseline vs one mutation" and that "two accounts are needed
for real proof" — but that primitive was platform-only; Vanguard had no way to
actually run the diff. This module is it.

Two tools:
  * ``compare_requests`` — the general baseline-vs-mutation primitive: send the
    same request under two header sets (identity/tenant/role swap) and report a
    status + body-similarity diff with a verdict hint.
  * ``authz_diff`` — the BOLA/IDOR harness: owner vs other-identity vs
    unauthenticated, with a verdict that flags cross-identity data access.

Detection is conservative (owner must return a real 200 object; the other
principal must get a near-identical body) to keep false positives low. The HTTP
fetch is injectable so the verdict logic is unit-tested without a network.
"""
from __future__ import annotations

import json
import logging
from difflib import SequenceMatcher
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("agent.authz_probe")

# Injectable HTTP: (method, url, headers, body) -> {status, headers, body, error}.
HttpFetch = Callable[[str, str, Dict[str, str], str], Dict[str, Any]]

# An owner response must look like a real object before a "leak" means anything.
_MIN_OBJECT_LEN = 48
# Bodies at/above this similarity are treated as "the same object".
_SAME_OBJECT_RATIO = 0.90
# Statuses that indicate the other principal was correctly denied.
_DENIED_STATUS = {401, 403, 404, 405}


def _default_http(method: str, url: str, headers: Dict[str, str], body: str) -> Dict[str, Any]:
    import scanners
    return scanners.run_send_http_request(
        method=method, url=url, headers_json=json.dumps(headers or {}),
        body=body, follow_redirects=False, bridge=None,
    )


def _similarity(a: str, b: str) -> float:
    a, b = (a or "")[:6000], (b or "")[:6000]
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()


def _brief(resp: Dict[str, Any]) -> Dict[str, Any]:
    body = resp.get("body") or ""
    return {"status": resp.get("status"), "length": len(body),
            "error": resp.get("error")}


# ---------------------------------------------------------------------------
# Pure verdict (unit-tested)
# ---------------------------------------------------------------------------

def _authz_verdict(
    owner: Dict[str, Any],
    other: Optional[Dict[str, Any]],
    unauth: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Classify a multi-identity result set. Returns {finding, reason, similarity}."""
    o_status = owner.get("status")
    o_body = owner.get("body") or ""
    # Owner must have retrieved a real object for a "leak" to mean anything.
    if o_status != 200 or len(o_body) < _MIN_OBJECT_LEN:
        return {"finding": None,
                "reason": "owner did not return a substantive 200 object; "
                          "inconclusive baseline"}

    # Unauthenticated access to the owner's object → missing auth entirely.
    if unauth is not None and unauth.get("status") == 200:
        sim = _similarity(o_body, unauth.get("body") or "")
        if sim >= _SAME_OBJECT_RATIO:
            return {"finding": "broken_access_control",
                    "reason": f"unauthenticated request returned the same object "
                              f"(similarity {sim:.2f})", "similarity": round(sim, 3)}

    # Cross-identity access → BOLA / IDOR.
    if other is not None:
        if other.get("status") in _DENIED_STATUS:
            return {"finding": None,
                    "reason": f"other identity correctly denied "
                              f"(HTTP {other.get('status')})"}
        if other.get("status") == 200:
            sim = _similarity(o_body, other.get("body") or "")
            if sim >= _SAME_OBJECT_RATIO:
                return {"finding": "idor",
                        "reason": f"a different identity retrieved the same object "
                                  f"(similarity {sim:.2f})", "similarity": round(sim, 3)}
            return {"finding": None,
                    "reason": f"other identity got 200 but a different body "
                              f"(similarity {sim:.2f}) — likely its own object",
                    "similarity": round(sim, 3)}
    return {"finding": None, "reason": "no cross-identity access observed"}


# ---------------------------------------------------------------------------
# Drivers
# ---------------------------------------------------------------------------

def _parse_headers(headers_json: str) -> Dict[str, str]:
    try:
        h = json.loads(headers_json) if headers_json and headers_json.strip() else {}
        return h if isinstance(h, dict) else {}
    except json.JSONDecodeError:
        return {}


def run_compare_requests(
    url: str,
    method: str = "GET",
    body: str = "",
    headers_a_json: str = "{}",
    headers_b_json: str = "{}",
    fetch: Optional[HttpFetch] = None,
) -> Dict[str, Any]:
    """Baseline-vs-mutation primitive: same request under two header sets."""
    http = fetch or _default_http
    a = http(method, url, _parse_headers(headers_a_json), body)
    b = http(method, url, _parse_headers(headers_b_json), body)
    sim = _similarity(a.get("body") or "", b.get("body") or "")
    same_status = a.get("status") == b.get("status")
    hint = "identical response — mutation had no effect"
    if not same_status:
        hint = f"status changed {a.get('status')} → {b.get('status')} — mutation mattered"
    elif sim < _SAME_OBJECT_RATIO:
        hint = f"same status but body differs (similarity {sim:.2f})"
    return {
        "url": url, "method": method,
        "a": _brief(a), "b": _brief(b),
        "similarity": round(sim, 3), "same_status": same_status,
        "verdict_hint": hint,
    }


def run_authz_diff(
    target_url: str,
    method: str = "GET",
    body: str = "",
    owner_headers_json: str = "{}",
    other_headers_json: str = "{}",
    test_unauth: bool = True,
    fetch: Optional[HttpFetch] = None,
) -> Dict[str, Any]:
    """IDOR/BOLA harness: owner vs other-identity vs unauthenticated.

    Provide the owner's session in owner_headers_json (Cookie/Authorization) and
    a *second* user's session in other_headers_json. A near-identical object
    returned to the other identity (or unauthenticated) is broken authorization.
    """
    http = fetch or _default_http
    owner = http(method, target_url, _parse_headers(owner_headers_json), body)
    if owner.get("error"):
        return {"probe": "authz_diff", "target": target_url, "candidates": [],
                "error": f"owner request failed: {owner['error']}"}

    other = None
    if other_headers_json and other_headers_json.strip() not in ("", "{}"):
        other = http(method, target_url, _parse_headers(other_headers_json), body)
    unauth = http(method, target_url, {}, body) if test_unauth else None

    verdict = _authz_verdict(owner, other, unauth)
    candidates: List[Dict[str, Any]] = []
    if verdict.get("finding"):
        vt = verdict["finding"]
        candidates.append({
            "title": ("Insecure Direct Object Reference (BOLA)" if vt == "idor"
                      else "Broken Access Control — unauthenticated object access"),
            "vuln_type": vt,
            "severity": "high",
            "url": target_url,
            "evidence": verdict["reason"],
            "similarity": verdict.get("similarity"),
            "confirmed": True,
        })
    return {
        "probe": "authz_diff", "target": target_url,
        "owner": _brief(owner),
        "other": _brief(other) if other else None,
        "unauth": _brief(unauth) if unauth else None,
        "verdict": verdict,
        "candidates": candidates,
    }


__all__ = [
    "run_compare_requests",
    "run_authz_diff",
    "_authz_verdict",
    "_similarity",
]
