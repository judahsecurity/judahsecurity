"""A bounded GET query probe from a browser-observed request sample.

This is exploratory evidence. A changed response is never SQLi proof.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from urllib.parse import quote, unquote_plus, urlsplit, urlunsplit

from .browser import assert_in_scope, origin
from .browser_actions import allowed_discovery_path
from .http_observe import observe_get


def plan_observed_query(private_exchange: bytes, *, parameter: str,
                        allowed_origins: list[str]) -> tuple[str, str]:
    """Validate the browser sample and mutation before reserving the request budget."""
    try:
        captured = json.loads(private_exchange)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("Invalid captured exchange") from exc
    if not isinstance(captured, dict):
        raise ValueError("Invalid captured exchange")
    url = captured.get("url")
    if captured.get("method") != "GET" or captured.get("resource_type") not in ("document", "xhr", "fetch"):
        raise ValueError("Query probe requires an observed GET browser exchange")
    if not isinstance(url, str) or not isinstance(parameter, str) or not 0 < len(parameter) <= 80:
        raise ValueError("Observed URL and parameter name are required")
    try:
        body = base64.b64decode(captured.get("request_body_base64", ""), validate=True)
    except (binascii.Error, TypeError, ValueError) as exc:
        raise ValueError("Invalid captured request body") from exc
    if body:
        raise ValueError("GET query probe does not replay request bodies")
    assert_in_scope(url, allowed_origins)
    parts = urlsplit(url)
    if parts.fragment:
        raise ValueError("Fragment-bearing samples are not replayed")
    if not allowed_discovery_path(parts.path or "/"):
        raise ValueError("State-changing path is not eligible for query probing")
    if len(parts.query) > 2_048:
        raise ValueError("Observed query exceeds probe limit")
    fields = parts.query.split("&")
    if len(fields) > 40:
        raise ValueError("Observed query has too many fields")
    matches = [index for index, field in enumerate(fields)
               if field and unquote_plus(field.split("=", 1)[0]) == parameter]
    if len(matches) != 1:
        raise ValueError("Parameter must occur exactly once in the observed query")
    index = matches[0]
    # Append to the encoded value. Preserve every other query byte, including
    # its encoding and order, so the probe changes exactly one field.
    name, separator, value = fields[index].partition("=")
    fields[index] = name + "=" + value + "%27" if separator else name + "=%27"
    mutated = urlunsplit(parts._replace(query="&".join(fields)))
    assert_in_scope(mutated, allowed_origins)
    return url, mutated


def probe_observed_query(url: str, mutated: str, *, parameter: str,
                         allowed_origins: list[str], storage_state: dict | None) -> dict:
    """Make one baseline and one one-field probe request, without publishing a finding."""
    parts = urlsplit(url)

    baseline = observe_get(url, allowed_origins, storage_state)
    probe = observe_get(mutated, allowed_origins, storage_state)

    def summary(result: dict) -> dict:
        return {key: result[key] for key in (
            "status", "content_type", "bytes_captured", "truncated",
            "body_sha256", "redirected",
        )}

    changed = baseline["status"] != probe["status"] or baseline["body_sha256"] != probe["body_sha256"]
    return {
        "operation": "query_probe",
        "target": origin(url) + (parts.path or "/"),
        "method": "GET", "location": "query", "parameter": parameter,
        "technique": "append_single_quote", "requests_sent": 2,
        "identity_transport": "named_identity_cookies_only",
        "baseline": summary(baseline), "probe": summary(probe),
        "changed": changed,
        "inconclusive": baseline["truncated"] or probe["truncated"]
        or baseline["redirected"] or probe["redirected"]
        or baseline["status"] in (401, 403) or probe["status"] in (401, 403),
        "finding": False,
    }


def plan_adaptive_query(private_exchange: bytes, *, parameter: str,
                        control: str, probe: str,
                        allowed_origins: list[str]) -> tuple[str, str, str]:
    """Bind two agent-chosen values to one browser-observed, safe GET field."""
    baseline, _ = plan_observed_query(
        private_exchange, parameter=parameter, allowed_origins=allowed_origins,
    )
    for label, value in (("control", control), ("probe", probe)):
        if not isinstance(value, str) or not value or len(value) > 120:
            raise ValueError(f"{label} must contain 1-120 characters")
        lowered = value.lower()
        if any(char in value for char in "\r\n\x00") or "http://" in lowered or "https://" in lowered or "//" in value:
            raise ValueError(f"{label} contains an ineligible URL or control character")
    if control == probe:
        raise ValueError("Control and probe must differ")
    parts = urlsplit(baseline)
    fields = parts.query.split("&")
    index = next(index for index, field in enumerate(fields)
                 if field and unquote_plus(field.split("=", 1)[0]) == parameter)
    name = fields[index].split("=", 1)[0]

    def with_value(value: str) -> str:
        changed = fields.copy()
        changed[index] = name + "=" + quote(value, safe="")
        url = urlunsplit(parts._replace(query="&".join(changed)))
        if len(url) > 2_048:
            raise ValueError("Mutated URL exceeds probe limit")
        assert_in_scope(url, allowed_origins)
        return url

    return baseline, with_value(control), with_value(probe)


def probe_adaptive_query(baseline: str, control_url: str, probe_url: str, *,
                         parameter: str, hypothesis: str,
                         allowed_origins: list[str],
                         storage_state: dict | None) -> dict:
    """Run repeated baseline/control/probe GETs; differential signals stay leads."""
    parts = urlsplit(baseline)
    result = {
        "operation": "adaptive_query_experiment",
        "target": origin(baseline) + (parts.path or "/"),
        "method": "GET", "location": "query", "parameter": parameter,
        "hypothesis": hypothesis,
        "baseline_url_sha256": hashlib.sha256(baseline.encode()).hexdigest(),
        "identity_transport": "named_identity_cookies_only",
        "sequence": ["baseline", "control", "probe", "probe", "control", "baseline"],
        "observations": [], "requests_sent": 0, "finding": False,
    }
    urls = {"baseline": baseline, "control": control_url, "probe": probe_url}
    for label in result["sequence"]:
        result["requests_sent"] += 1
        try:
            observed = observe_get(urls[label], allowed_origins, storage_state)
        except Exception as exc:
            result.update(inconclusive=True, error_type=type(exc).__name__)
            return result
        result["observations"].append({
            "case": label,
            **{key: observed[key] for key in (
                "status", "content_type", "bytes_captured", "truncated",
                "body_sha256", "redirected", "sql_error_family",
            )},
        })
    grouped = {label: [row for row in result["observations"] if row["case"] == label]
               for label in urls}
    def stable(rows: list[dict]) -> bool:
        return all((row["status"], row["body_sha256"]) ==
                   (rows[0]["status"], rows[0]["body_sha256"]) for row in rows[1:])

    result["stable"] = all(stable(rows) for rows in grouped.values())
    result["inconclusive"] = not result["stable"] or any(
        row["truncated"] or row["redirected"] or row["status"] in (401, 403)
        for row in result["observations"]
    )
    control_row, probe_row = grouped["control"][0], grouped["probe"][0]
    result["response_differs"] = (
        control_row["status"], control_row["body_sha256"]
    ) != (
        probe_row["status"], probe_row["body_sha256"]
    )
    result["diagnostic_lead"] = bool(
        not result["inconclusive"] and (
            control_row["status"] != probe_row["status"] or
            control_row["content_type"] != probe_row["content_type"] or
            (probe_row["sql_error_family"] and
             probe_row["sql_error_family"] != control_row["sql_error_family"])
        )
    )
    return result
