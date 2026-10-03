"""A bounded GET query probe from a browser-observed request sample.

This is exploratory evidence. A changed response is never SQLi proof.
"""

from __future__ import annotations

import base64
import binascii
import json
from urllib.parse import unquote_plus, urlsplit, urlunsplit

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
    if captured.get("method") != "GET" or captured.get("resource_type") not in ("xhr", "fetch"):
        raise ValueError("Query probe requires an observed GET XHR/fetch exchange")
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
