"""Cross-identity write-authorization proof (write-style IDOR / BOLA).

The read proof (``authz_proof``) shows a second identity can *read* an owner's
object. This proof shows a second identity can *modify* it, using a bounded
canary write and an owner-side readback:

  0. owner readback          -> neither fresh canary is present (baseline)
  1. owner writes canary A    (authorized self-write)
  2. owner readback          -> canary A present  (field is writable + reflected)
  3. other identity writes canary B to the *owner's* object
  4. owner readback          -> canary B present  => the other identity mutated
                                the owner's object (cross-account write)
  5. owner restores the field (cleanup)
  6. owner readback          -> neither test canary present (cleanup confirmed)

Only step 4 confirms the finding. Every write targets one operator-declared,
bounded field with short random nonces, and the owner restores the field at the
end. The confirmation is deterministic and independent of model prose. This
module performs no IO itself: the caller injects a ``write_fn`` and a
``readback_fn`` so the recipe is exercised directly in tests and so all scope,
identity, budget, and transport rules stay in the scoped-assessment layer.
"""

from __future__ import annotations

import re
from collections.abc import Callable

WRITE_METHODS = ("POST", "PUT", "PATCH")
_RECIPE = "owner_only_write_cross_identity_v1"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")

# WriteFn: (identity, canary) -> {"status": int}
WriteFn = Callable[[str, str], dict]
# ReadbackFn: (markers) -> {"status","content_type","body_sha256","truncated",
#                           "redirected","markers": {marker: bool}}
ReadbackFn = Callable[[list[str]], dict]


def _readback_row(response: dict, markers: list[str]) -> dict:
    found = response.get("markers") or {}
    return {
        "status": response.get("status"),
        "content_type": response.get("content_type"),
        "body_sha256": response.get("body_sha256"),
        "truncated": response.get("truncated"),
        "redirected": response.get("redirected"),
        "markers": {marker: bool(found.get(marker)) for marker in markers},
    }


def owner_only_write_proof_valid(result: dict) -> bool:
    """Strict, prose-independent validity check for a write-authz proof."""
    if (result.get("operation") != "authz_owner_only_write"
            or result.get("proof_recipe") != _RECIPE
            or result.get("policy") != "owner_only"
            or result.get("method") not in WRITE_METHODS
            or not isinstance(result.get("target"), str) or not result["target"]
            or not isinstance(result.get("readback_target"), str) or not result["readback_target"]
            or not isinstance(result.get("field"), str) or not result["field"]
            or not isinstance(result.get("owner_identity"), str) or not result["owner_identity"]
            or not isinstance(result.get("other_identity"), str) or not result["other_identity"]
            or result["owner_identity"] == result["other_identity"]):
        return False
    owner_canary = result.get("owner_canary")
    other_canary = result.get("other_canary")
    if (not isinstance(owner_canary, str) or not isinstance(other_canary, str)
            or not owner_canary or owner_canary == other_canary):
        return False
    checks = result.get("checks")
    if not isinstance(checks, dict):
        return False
    required = ("owner_readback_baseline", "owner_write_canary",
                "owner_readback_after_owner_write", "other_write_canary",
                "owner_readback_after_other_write")
    if not all(isinstance(checks.get(key), dict) for key in required):
        return False
    baseline = checks["owner_readback_baseline"]
    after_owner = checks["owner_readback_after_owner_write"]
    after_other = checks["owner_readback_after_other_write"]
    owner_write = checks["owner_write_canary"]
    other_write = checks["other_write_canary"]
    # Readbacks must be clean, untruncated, non-redirected observations.
    for row in (baseline, after_owner, after_other):
        if (row.get("truncated") is not False or row.get("redirected") is not False
                or not _DIGEST.fullmatch(str(row.get("body_sha256", "")))
                or row.get("status") != 200 or not isinstance(row.get("markers"), dict)):
            return False
    # Fresh canaries: neither appears before we write it.
    if baseline["markers"].get(owner_canary) is not False or baseline["markers"].get(other_canary) is not False:
        return False
    # The owner's self-write must succeed and be reflected (field is writable).
    if not (isinstance(owner_write.get("status"), int) and 200 <= owner_write["status"] < 300):
        return False
    if after_owner["markers"].get(owner_canary) is not True:
        return False
    # The other identity's write must land on the owner's object: its canary is
    # visible on the owner's readback. A rejected write (4xx) or a write that is
    # not reflected does not confirm.
    if not (isinstance(other_write.get("status"), int) and 200 <= other_write["status"] < 300):
        return False
    if after_other["markers"].get(other_canary) is not True:
        return False
    return True


def probe_owner_only_write(
    target: str, readback_target: str, *, method: str, field: str,
    owner_identity: str, other_identity: str,
    owner_canary: str, other_canary: str, restore_canary: str,
    write_fn: WriteFn, readback_fn: ReadbackFn,
    before_request: Callable[[], object],
) -> dict:
    """Run the canary-write + readback recipe and return a structured result."""
    if method not in WRITE_METHODS:
        raise ValueError("Write authorization proof needs POST, PUT, or PATCH")
    if owner_identity == other_identity:
        raise ValueError("Write authorization proof needs two distinct identities")
    if len({owner_canary, other_canary, restore_canary}) != 3 or not all(
            (owner_canary, other_canary, restore_canary)):
        raise ValueError("Three distinct bounded canaries are required")

    markers = [owner_canary, other_canary]
    checks: dict[str, dict] = {}

    before_request()
    checks["owner_readback_baseline"] = _readback_row(readback_fn(markers), markers)

    before_request()
    checks["owner_write_canary"] = {"status": write_fn(owner_identity, owner_canary).get("status")}

    before_request()
    checks["owner_readback_after_owner_write"] = _readback_row(readback_fn(markers), markers)

    before_request()
    checks["other_write_canary"] = {"status": write_fn(other_identity, other_canary).get("status")}

    before_request()
    checks["owner_readback_after_other_write"] = _readback_row(readback_fn(markers), markers)

    # Cleanup: the owner restores the field to a neutral value and we confirm
    # neither test canary remains. Cleanup never affects proof_confirmed.
    before_request()
    cleanup_write = write_fn(owner_identity, restore_canary)
    before_request()
    cleanup_readback = _readback_row(readback_fn(markers), markers)
    cleanup_confirmed = bool(
        isinstance(cleanup_write.get("status"), int) and 200 <= cleanup_write["status"] < 300
        and cleanup_readback["status"] == 200
        and cleanup_readback["markers"].get(owner_canary) is False
        and cleanup_readback["markers"].get(other_canary) is False)
    checks["cleanup"] = {"status": cleanup_write.get("status"),
                         "restored": cleanup_confirmed,
                         "readback_status": cleanup_readback["status"]}

    result = {
        "operation": "authz_owner_only_write",
        "proof_recipe": _RECIPE,
        "policy": "owner_only",
        "target": target,
        "readback_target": readback_target,
        "method": method,
        "field": field,
        "owner_identity": owner_identity,
        "other_identity": other_identity,
        "owner_canary": owner_canary,
        "other_canary": other_canary,
        "requests_sent": 7,
        "identity_transport": "named_identity_cookies_only",
        "checks": checks,
        "cleanup_confirmed": cleanup_confirmed,
    }
    result["proof_confirmed"] = owner_only_write_proof_valid(result)
    return result
