"""Authentication consistency invariant (CWE-306 / CWE-650 / CWE-863).

Invariant: authentication is a property of the *resource*, not of the HTTP
method, the path spelling, or an override header. When an anonymous request
to a path is denied (401/403), every other way of reaching the same handler
must be denied too.

This module is deliberately product-agnostic. It does not know about any
vendor, route, or prior finding. It covers, among others:

* Express/Koa routers that attach auth middleware with ``router.get`` only,
  so ``POST`` reaches the handler (e.g. ML/ICS analytics "calculate" APIs).
* ASP.NET controllers missing ``[Authorize]`` on one action verb.
* Flask/Django views where the decorator wraps only one method branch.
* Frameworks honouring ``X-HTTP-Method-Override`` after the auth check.

It also turns values leaked by one response (model names, IDs, slugs) into
inputs for templated routes, so a disclosure finding automatically feeds the
next probe instead of relying on the model to remember to chain it.

Everything here is pure: planning, classification, identifier harvesting and
template expansion. The network-facing tool lives in ``tools.py``
(``test_auth_consistency``) and goes through the scoped ``_http_exchange``.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, urlsplit

DENY_STATUSES = frozenset({401, 403})
# Never sent: DELETE is destructive by definition and cannot be made safe with
# an empty body. HEAD returns no body, so it cannot demonstrate data exposure.
ALT_METHODS = ("POST", "PUT", "PATCH")
OVERRIDE_HEADERS = ("X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method")
EMPTY_JSON_BODY = "{}"

# Paths whose name says the handler changes state. A body-less POST to
# ``/calculate`` is a read in practice; a body-less POST to ``/delete`` is not.
_STATE_CHANGING_PATH = re.compile(
    r"(?i)(?:^|[/_.-])(?:delete|remove|destroy|drop|purge|wipe|truncate|reset|"
    r"shutdown|reboot|restart|stop|kill|logout|signout|pay|purchase|checkout|"
    r"transfer|withdraw|refund|deactivate|disable|revoke|unsubscribe|write|"
    r"setpoint|actuate|command|cmd|exec|run|start|deploy|publish|approve)"
    r"(?:$|[/_.-])"
)

_DENY_BODY = re.compile(
    r"(?i)(?:invalid[\s_-]*(?:auth|token|session|credential)|unauthori[sz]ed|"
    r"forbidden|access[\s_-]*denied|not[\s_-]*authori[sz]ed|not[\s_-]*authenticated|"
    r"authentication[\s_-]*(?:required|failed)|login[\s_-]*required|"
    r"please[\s_-]*(?:log|sign)[\s_-]*in|missing[\s_-]*(?:auth|token|credentials)|"
    r"jwt[\s_-]*(?:expired|malformed|missing)|permission[\s_-]*denied)"
)
_HTML = re.compile(r"(?is)^\s*(?:<!doctype\s+html|<html|<head|<body)")
_LOGIN_FORM = re.compile(r"(?is)<form[^>]*>.*?type=[\"']?password")

# Template slots as they appear in captured routes, OpenAPI paths, framework
# route tables, and our JS extractor (which normalizes ``${expr}`` to EXPR).
_SLOT = re.compile(
    r"\{[A-Za-z_][\w.-]{0,63}\}"       # {model_name}   (OpenAPI / ASP.NET)
    r"|\$\{[^}]{1,80}\}"               # ${modelName}   (JS template literal)
    r"|(?<=/):[A-Za-z_]\w{0,63}"       # :model         (Express / Rails)
    r"|<(?:\w+:)?[A-Za-z_]\w{0,63}>"   # <int:id>       (Flask / Django)
    r"|(?<=/)EXPR(?=/|$|\?)"           # EXPR           (js_endpoints normalize)
)

_IDENT_KEY = re.compile(
    r"(?i)^(?:id|uuid|guid|name|slug|key|code|handle|"
    r".*(?:_id|Id|ID|_name|Name|_slug|_key|_uuid|_code))$"
)
_SAFE_IDENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~:-]{0,127}$")
_SECRETISH_KEY = re.compile(r"(?i)(?:secret|password|passwd|token|api[_-]?key|private|salt|hash|session)")
_HEX_BLOB = re.compile(r"^[A-Fa-f0-9]{40,}$")

MAX_IDENTIFIERS = 50
MAX_EXPANSIONS = 25
BODY_PREVIEW_CHARS = 300


@dataclass
class Variant:
    """One alternate way of reaching the same handler."""

    label: str
    method: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"label": self.label, "method": self.method, "headers": dict(self.headers),
                "has_body": self.body is not None}


def is_state_changing_path(path: str) -> bool:
    return bool(_STATE_CHANGING_PATH.search(urlsplit(path or "").path or path or ""))


def plan_variants(
    path: str,
    *,
    baseline_method: str = "GET",
    methods: Iterable[str] | None = None,
    include_override_headers: bool = True,
    allow_state_changing: bool = False,
) -> tuple[list[Variant], list[str]]:
    """Return (variants, skipped_reasons) for one denied path.

    Variants carry an empty JSON object so frameworks that require a parsed
    body still route the request, without supplying any attacker data.
    """
    baseline_method = (baseline_method or "GET").upper()
    wanted = [m.upper() for m in (methods or ALT_METHODS)]
    skipped: list[str] = []
    if "DELETE" in wanted:
        skipped.append("DELETE is never sent by this probe")
    wanted = [m for m in dict.fromkeys(wanted) if m in ALT_METHODS and m != baseline_method]
    if is_state_changing_path(path) and not allow_state_changing:
        skipped.append(
            "Path name indicates a state-changing action; alternate write methods "
            "were not sent. Re-run with allow_state_changing=true only when the "
            "operator approved writes to this exact path."
        )
        return [], skipped
    json_headers = {"Content-Type": "application/json", "Accept": "application/json"}
    variants = [
        Variant(label=f"verb:{m}", method=m, headers=dict(json_headers), body=EMPTY_JSON_BODY)
        for m in wanted
    ]
    if include_override_headers and baseline_method in {"GET", "HEAD"}:
        for header in OVERRIDE_HEADERS:
            variants.append(Variant(
                label=f"override:{header}",
                method="POST",
                headers={**json_headers, header: baseline_method},
                body=EMPTY_JSON_BODY,
            ))
    return variants, skipped


def body_fingerprint(text: str) -> str:
    """Stable hash that ignores whitespace and cache-busting asset hashes."""
    normalized = re.sub(r"\s+", " ", text or "").strip()
    normalized = re.sub(r"(?i)([?&](?:v|ver|t|hash|_)=)[\w.-]+", r"\1", normalized)
    normalized = re.sub(r"\.[a-f0-9]{8,}\.(js|css)", r".\1", normalized)
    return hashlib.sha256(normalized.encode("utf-8", "ignore")).hexdigest()[:32]


def _content_type(headers: dict[str, Any] | None) -> str:
    for key, value in (headers or {}).items():
        if str(key).lower() == "content-type":
            return str(value or "").lower()
    return ""


def data_shape(text: str, content_type: str = "") -> dict[str, Any]:
    """Describe what a response exposes without echoing the data itself."""
    text = text or ""
    shape: dict[str, Any] = {"bytes": len(text.encode("utf-8", "ignore"))}
    parsed: Any = None
    if "json" in content_type or text.lstrip()[:1] in ("{", "["):
        try:
            parsed = json.loads(text)
        except Exception:
            parsed = None
    if isinstance(parsed, dict):
        shape["kind"] = "json_object"
        shape["keys"] = sorted(str(k) for k in parsed.keys())[:20]
        non_empty = [k for k, v in parsed.items() if v not in (None, "", [], {})]
        shape["non_empty_keys"] = sorted(str(k) for k in non_empty)[:20]
        for value in parsed.values():
            if isinstance(value, str) and value.count("\n") >= 2 and "," in value.split("\n", 1)[0]:
                rows = [r for r in value.split("\n") if r.strip()]
                shape["embedded_csv"] = {
                    "rows": max(0, len(rows) - 1),
                    "columns": len(rows[0].split(",")) if rows else 0,
                }
                break
    elif isinstance(parsed, list):
        shape["kind"] = "json_array"
        shape["items"] = len(parsed)
    elif _HTML.search(text):
        shape["kind"] = "html"
    elif text.count("\n") >= 2 and "," in text.split("\n", 1)[0]:
        rows = [r for r in text.split("\n") if r.strip()]
        shape["kind"] = "csv"
        shape["rows"] = max(0, len(rows) - 1)
    else:
        shape["kind"] = "text" if text else "empty"
    return shape


_ENVELOPE_KEYS = frozenset({
    "error", "errors", "message", "msg", "detail", "details", "status", "code",
    "success", "ok", "statuscode", "status_code", "timestamp", "path", "title", "type",
})


def _meaningful(shape: dict[str, Any]) -> bool:
    kind = shape.get("kind")
    if kind == "json_object":
        return any(k.lower() not in _ENVELOPE_KEYS for k in shape.get("non_empty_keys") or [])
    if kind == "json_array":
        return int(shape.get("items") or 0) > 0
    if kind in {"csv", "text"}:
        return int(shape.get("bytes") or 0) > 0
    return False


def classify_variant(
    *,
    baseline_status: int,
    baseline_body: str,
    variant_status: int,
    variant_body: str,
    variant_headers: dict[str, Any] | None = None,
    shell_fingerprints: Iterable[str] = (),
) -> dict[str, Any]:
    """Decide whether one variant broke the invariant.

    Outcomes:
      bypass           – denied baseline, variant returned application data
      handler_reached  – denied baseline, variant got past auth into the handler
                         (2xx with an empty/trivial body, or 400/422 validation)
      consistent       – variant was denied as well, or redirected to login
      not_routed       – 404/405/501: no handler for that method
      spa_fallback     – 2xx HTML equal to the app shell / a login page
      soft_deny        – 2xx whose body is itself an auth error
      not_applicable   – the baseline was not denied, so there is no invariant
    """
    baseline_status = int(baseline_status or 0)
    variant_status = int(variant_status or 0)
    ctype = _content_type(variant_headers)
    shape = data_shape(variant_body, ctype)
    result: dict[str, Any] = {"status": variant_status, "data_shape": shape}

    if baseline_status not in DENY_STATUSES:
        return {**result, "outcome": "not_applicable",
                "why": f"baseline was {baseline_status}, not a 401/403 deny"}
    if variant_status in DENY_STATUSES:
        return {**result, "outcome": "consistent", "why": "variant also denied"}
    if 300 <= variant_status < 400:
        return {**result, "outcome": "consistent", "why": "variant redirected (typically to login)"}
    if variant_status in (404, 405, 501):
        return {**result, "outcome": "not_routed", "why": "no handler for this method"}
    body = variant_body or ""
    if 200 <= variant_status < 300:
        fp = body_fingerprint(body)
        if body and (fp in set(shell_fingerprints) or (_HTML.search(body) and _LOGIN_FORM.search(body))):
            return {**result, "outcome": "spa_fallback",
                    "why": "body is the application shell or a login page, not handler output"}
        if body and fp == body_fingerprint(baseline_body):
            return {**result, "outcome": "soft_deny", "why": "variant body identical to the denied baseline"}
        if _DENY_BODY.search(body[:2000]) and not _meaningful(shape):
            return {**result, "outcome": "soft_deny", "why": "2xx wrapper around an auth error"}
        if _meaningful(shape) and shape.get("kind") != "html":
            return {**result, "outcome": "bypass",
                    "why": "anonymous variant returned handler data while the baseline was denied"}
        if shape.get("kind") == "html":
            return {**result, "outcome": "handler_reached",
                    "why": "2xx HTML that differs from the shell; inspect manually"}
        return {**result, "outcome": "handler_reached",
                "why": "2xx with an empty body: auth did not run, but no data shown yet"}
    if variant_status in (400, 422):
        if _DENY_BODY.search(body[:2000]):
            return {**result, "outcome": "consistent", "why": "validation error mentions auth"}
        return {**result, "outcome": "handler_reached",
                "why": f"{variant_status} validation error: the handler ran without auth"}
    return {**result, "outcome": "inconclusive", "why": f"unexpected status {variant_status}"}


SEVERITY_BY_OUTCOME = {"bypass": "high", "handler_reached": "medium"}


def summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Collapse per-variant outcomes into one verdict for the target URL."""
    outcomes = [r.get("outcome") for r in results]
    if "bypass" in outcomes:
        verdict, signal = "MUTANT_BYPASS_CANDIDATE", "auth_consistency_bypass"
    elif "handler_reached" in outcomes:
        verdict, signal = "MUTANT_BYPASS_CANDIDATE", "auth_consistency_handler_reached"
    elif outcomes and all(o == "not_applicable" for o in outcomes):
        verdict, signal = "NOT_APPLICABLE", ""
    elif outcomes and all(o in {"consistent", "not_routed", "spa_fallback", "soft_deny"} for o in outcomes):
        verdict, signal = "CONSISTENT", ""
    else:
        verdict, signal = "INCONCLUSIVE", ""
    severity = None
    for outcome in ("bypass", "handler_reached"):
        if outcome in outcomes:
            severity = SEVERITY_BY_OUTCOME[outcome]
            break
    return {"verdict": verdict, "signal": signal, "severity_hint": severity}


def preview(text: str, limit: int = BODY_PREVIEW_CHARS) -> str:
    """A short excerpt for the operator. Never the whole dataset."""
    text = (text or "").replace("\r", "")
    return text[:limit] + ("…" if len(text) > limit else "")


# ---------------------------------------------------------------------------
# Leaked identifiers → templated routes
# ---------------------------------------------------------------------------

def _usable_identifier(value: Any) -> str | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        value = str(int(value)) if float(value).is_integer() else None
        if value is None:
            return None
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not _SAFE_IDENT.match(value) or _HEX_BLOB.match(value):
        return None
    if value.lower() in {"true", "false", "null", "none", "undefined"}:
        return None
    return value


def harvest_identifiers(payload: Any, *, limit: int = MAX_IDENTIFIERS) -> list[str]:
    """Collect identifier-looking values from a disclosed JSON document.

    Takes values under id/name/slug-style keys, and plain arrays of short
    strings (``["Dryer", "Sim2"]``). Skips anything under secret-looking keys.
    Order is preserved so the first entries of a listing are tried first.
    """
    if isinstance(payload, (str, bytes)):
        try:
            payload = json.loads(payload)
        except Exception:
            return []
    found: list[str] = []
    seen: set[str] = set()

    def add(value: Any) -> None:
        ident = _usable_identifier(value)
        if ident and ident not in seen and len(found) < limit:
            seen.add(ident)
            found.append(ident)

    def walk(node: Any, key: str = "", depth: int = 0) -> None:
        if depth > 6 or len(found) >= limit:
            return
        if key and _SECRETISH_KEY.search(key):
            return
        if isinstance(node, dict):
            for k, v in node.items():
                k = str(k)
                if _SECRETISH_KEY.search(k):
                    continue
                if _IDENT_KEY.match(k) and not isinstance(v, (dict, list)):
                    add(v)
            for k, v in node.items():
                if isinstance(v, (dict, list)):
                    walk(v, str(k), depth + 1)
        elif isinstance(node, list):
            scalars = [v for v in node if isinstance(v, (str, int, float, bool))]
            if scalars and len(scalars) == len(node):
                for v in scalars:
                    add(v)
            else:
                for v in node:
                    walk(v, key, depth + 1)

    walk(payload)
    return found


def template_slots(path: str) -> list[str]:
    return [m.group(0) for m in _SLOT.finditer(path or "")]


def is_templated(url_or_path: str) -> bool:
    return bool(template_slots(urlsplit(url_or_path).path if "://" in (url_or_path or "") else url_or_path))


def expand_template(
    url_or_path: str,
    identifiers: Iterable[str],
    *,
    limit: int = MAX_EXPANSIONS,
) -> list[str]:
    """Fill the single slot of a templated route with each identifier.

    Routes with more than one slot are returned unexpanded (empty list): we do
    not guess how two leaked lists pair up.
    """
    slots = template_slots(url_or_path)
    if len(slots) != 1:
        return []
    slot = slots[0]
    out: list[str] = []
    for ident in identifiers:
        ident = _usable_identifier(ident)
        if not ident:
            continue
        concrete = url_or_path.replace(slot, quote(ident, safe="._~-"), 1)
        if concrete not in out:
            out.append(concrete)
        if len(out) >= limit:
            break
    return out


# ---------------------------------------------------------------------------
# Coverage cells
# ---------------------------------------------------------------------------

TEST_TYPE = "auth_consistency"
MAX_DENY_OBSERVATIONS = 400


def deny_observation(method: str, url: str, status: int) -> dict[str, Any] | None:
    """Value-free record of one anonymous read deny, for later cell seeding.

    Only GET/HEAD denies start the invariant. Write-verb denies are usually the
    probe's own consistent results; seeding from them would cascade.
    """
    if int(status or 0) not in DENY_STATUSES:
        return None
    if (method or "GET").upper() not in {"GET", "HEAD"}:
        return None
    parts = urlsplit(url or "")
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        return None
    return {
        "method": (method or "GET").upper(),
        "host": parts.netloc.lower(),
        "path": parts.path or "/",
        "status": int(status),
    }


def record_deny_observation(store: list[dict[str, Any]], observation: dict[str, Any] | None) -> bool:
    if not observation:
        return False
    key = (observation["method"], observation["host"], observation["path"])
    for row in store:
        if (row.get("method"), row.get("host"), row.get("path")) == key:
            return False
    if len(store) >= MAX_DENY_OBSERVATIONS:
        return False
    store.append(observation)
    return True


def seed_auth_consistency_cells(brain: Any, observations: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Open one coverage cell per (denied path × alternate method).

    The cells make the invariant part of the run's denominator: a run cannot
    report full coverage while a denied API path has untested verbs.
    """
    from app.services.agent.coverage_cells import (
        MAX_COVERAGE_CELLS,
        _new_cell,
        migrate_coverage_cells,
    )

    if not hasattr(brain, "coverage_cells") or brain.coverage_cells is None:
        return []
    existing = {row.get("id") for row in brain.coverage_cells if isinstance(row, dict)}
    for obs in observations or []:
        if not isinstance(obs, dict) or int(obs.get("status") or 0) not in DENY_STATUSES:
            continue
        path = str(obs.get("path") or "/")
        method = str(obs.get("method") or "GET").upper()
        variants, skipped = plan_variants(path, baseline_method=method, include_override_headers=False)
        targets = [v.method for v in variants] or (["review"] if skipped else [])
        for alt in targets:
            cell = _new_cell(
                brain,
                method=method,
                path=path,
                host=str(obs.get("host") or ""),
                identity="anonymous",
                parameter=f"method:{alt}",
                test_type=TEST_TYPE,
                source="auth_deny_observation",
                reason=(
                    f"Anonymous {method} was {obs.get('status')}; the same handler must also "
                    f"deny {alt}. Run test_auth_consistency(url=...)."
                    if alt != "review" else
                    "Denied state-changing path; alternate verbs need operator approval"
                ),
            )
            api_like = bool(re.search(r"(?i)/(?:api|v\d+|graphql|rest|rpc)(?:/|$)", path))
            cell["priority_rank"] = 0 if api_like else 2
            if alt == "review":
                cell["status"] = "blocked"
            if cell["id"] not in existing and len(existing) < MAX_COVERAGE_CELLS:
                brain.coverage_cells.append(cell)
                existing.add(cell["id"])
    return migrate_coverage_cells(brain)


# ---------------------------------------------------------------------------
# Agent-facing guidance (product-agnostic)
# ---------------------------------------------------------------------------

HUNTER_RULES = (
    "Deny differential loop (any product): every anonymous 401/403 is a question, "
    "not an answer. Ask which part of the request caused the deny, then change ONE "
    "thing at a time — HTTP method, method-override header, path spelling, identity. "
    "Run test_auth_consistency(url=<denied url>) on each denied API path; it sends "
    "POST/PUT/PATCH with {} and override headers, never DELETE. If a route is "
    "templated (/x/{id}, /x/:id, /x/EXPR), pass identifiers leaked elsewhere in the "
    "run, or identifier_source_url=<listing that leaked them>. bypass → "
    "submit_finding_candidate High (Critical only with sensitive data or writes "
    "proven). Do not page through or bulk-download exposed data: one excerpt, the "
    "row count, and the column names are the proof."
)

VERIFIER_ADDENDUM = (
    "Auth-consistency candidate. Re-derive ONLY: anonymous baseline method on the "
    "same URL is 401/403; the cited alternate method or override header with body "
    "{} returns 2xx with handler data (not the SPA shell, not a login page, not an "
    "auth error inside a 200). confirmed if both hold now. refuted if the "
    "alternate method is also 401/403/3xx-to-login/404/405."
)

WRITEUP_RULES = (
    "Method-specific authentication bypass (CWE-650 / CWE-306): cite the anonymous "
    "denied baseline and the anonymous alternate-method request with status, size "
    "and data shape. Remediation: enforce authentication on every method — apply "
    "auth middleware at the router/namespace level (default deny) rather than per "
    "verb, ignore method-override headers after auth, and add a regression test "
    "that iterates all methods per route."
)
