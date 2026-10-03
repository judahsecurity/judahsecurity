"""Owner-only authorization proof for operator-declared, browser-observed GET resources."""

from __future__ import annotations

import json
import re
from collections.abc import Callable

from .http_observe import observe_get


CHECK_ORDER = ("owner_first", "other_first", "anonymous_first",
               "owner_second", "other_second", "anonymous_second")


def observed_owner_resource(private_exchange: bytes) -> str:
    try:
        sample = json.loads(private_exchange)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("Invalid private browser exchange") from exc
    if (not isinstance(sample, dict) or not isinstance(sample.get("url"), str)
            or sample.get("method") != "GET" or sample.get("resource_type") not in ("xhr", "fetch")):
        raise ValueError("Authorization proof requires this owner's exact browser-observed GET resource")
    return sample["url"]


def owner_only_proof_valid(result: dict) -> bool:
    if (result.get("operation") != "authz_owner_only"
            or result.get("proof_recipe") != "owner_only_cross_identity_v1"
            or result.get("policy") != "owner_only"
            or result.get("method") != "GET"
            or not isinstance(result.get("target"), str) or not result["target"]
            or not isinstance(result.get("owner_identity"), str) or not result["owner_identity"]
            or not isinstance(result.get("other_identity"), str) or not result["other_identity"]
            or result["owner_identity"] == result["other_identity"]):
        return False
    checks = result.get("checks")
    if not isinstance(checks, dict) or not all(isinstance(checks.get(key), dict) for key in CHECK_ORDER):
        return False
    rows = [checks[key] for key in CHECK_ORDER]
    if any(row.get("truncated") is not False or row.get("redirected") is not False
           or not re.fullmatch(r"[0-9a-f]{64}", str(row.get("body_sha256", ""))) for row in rows):
        return False
    owner, other, anon, owner_again, other_again, anon_again = rows
    if (owner.get("status") != other.get("status") or owner.get("status") != 200
            or owner_again.get("status") != other_again.get("status") or owner_again.get("status") != 200
            or anon.get("status") not in (401, 403, 404)
            or anon_again.get("status") != anon.get("status")):
        return False
    if (not owner.get("content_type") or owner.get("content_type") != other.get("content_type")
            or owner.get("content_type") != owner_again.get("content_type")
            or owner.get("content_type") != other_again.get("content_type")):
        return False
    owned_hash = owner["body_sha256"]
    return (owned_hash == other["body_sha256"] == owner_again["body_sha256"] == other_again["body_sha256"]
            and anon["body_sha256"] == anon_again["body_sha256"] != owned_hash)


def probe_owner_only(target: str, *, owner_identity: str, other_identity: str,
                     owner_state: dict, other_state: dict, allowed_origins: list[str],
                     before_request: Callable[[], object]) -> dict:
    states = (owner_state, other_state, None, owner_state, other_state, None)
    checks = {}
    for key, state in zip(CHECK_ORDER, states, strict=True):
        before_request()
        response = observe_get(target, allowed_origins, state)
        checks[key] = {name: response[name] for name in (
            "status", "content_type", "bytes_captured", "truncated", "body_sha256", "redirected",
        )}
    result = {
        "operation": "authz_owner_only", "proof_recipe": "owner_only_cross_identity_v1",
        "policy": "owner_only", "target": target, "method": "GET",
        "owner_identity": owner_identity, "other_identity": other_identity,
        "requests_sent": 6, "identity_transport": "named_identity_cookies_only", "checks": checks,
    }
    result["proof_confirmed"] = owner_only_proof_valid(result)
    return result
