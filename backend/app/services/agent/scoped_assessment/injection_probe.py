"""Bounded server-side injection proofs on one observed GET query input.

Each proof compares an inert, nonce-bound control with a short list of probes and
confirms only on a signal the payload itself cannot produce by reflection:

* ``ssti``: an arithmetic expression over two fresh random factors. The product
  never appears in the request, so seeing it means the server evaluated the
  template expression.
* ``command_injection``: the same computed-output idea through shell arithmetic
  (``expr``/``$(( ))``). Only arithmetic is ever sent; nothing writes, deletes,
  or opens a network connection.
* ``path_traversal``: a read of a world-readable, fixed-content system file
  (``/etc/passwd`` or ``win.ini``) whose signature is absent from a control that
  traverses to a nonexistent, nonce-named file.
* ``nosql``: an operator differential. ``param[$ne]=<nonce>`` (always true)
  must return a stable body that differs from ``param=<nonce>``, while
  ``param[$eq]=<nonce>`` (same meaning as the control) must match the control.
  A server that ignores the bracket syntax returns the same body for both
  operators and is not confirmed.

The model never chooses payloads, factors, or URLs. Only fixed labels and digests
leave this module; response bodies are not returned to the agent.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from urllib.error import HTTPError
from urllib.request import Request, build_opener

from app.services.agent.assessment_proxy import assessment_urllib_handlers

from .browser import assert_in_scope
from .http_observe import _NoRedirect, _cookie_header

MAX_BODY = 256 * 1024
TEST_TYPES = ("ssti", "command_injection", "path_traversal", "nosql")
NOSQL_SEQUENCE = ("control_first", "true_first", "false_first", "true_second", "control_last")
MIN_MARKER_LENGTH = 8

# Fixed probe recipes. ``{a}``/``{b}`` are fresh random factors per run.
SSTI_RECIPES = (
    ("jinja_twig", "{{{{{a}*{b}}}}}"),
    ("dollar_brace", "${{{a}*{b}}}"),
    ("erb", "<%= {a}*{b} %>"),
    ("hash_brace", "#{{{a}*{b}}}"),
)
CMDI_RECIPES = (
    ("semicolon_expr", ";expr {a} \\* {b}"),
    ("pipe_expr", "|expr {a} \\* {b}"),
    ("subshell_arith", "$(echo $(({a}*{b})))"),
    ("backtick_expr", "`expr {a} \\* {b}`"),
)
TRAVERSAL_RECIPES = (
    ("dotdot_passwd", "../../../../../../../../etc/passwd", "passwd"),
    ("absolute_passwd", "/etc/passwd", "passwd"),
    ("nested_dotdot_passwd", "....//....//....//....//....//....//etc/passwd", "passwd"),
    ("dotdot_win_ini", "..\\..\\..\\..\\..\\..\\windows\\win.ini", "win_ini"),
)
_FILE_SIGNATURES = {
    "passwd": re.compile(rb"(?m)^root:[^:\r\n]*:0:0:[^\r\n]*:/[^\r\n]*$"),
    "win_ini": re.compile(rb"(?is)\[fonts\].{0,2000}\[extensions\]|\[extensions\].{0,2000}\[fonts\]"),
}


def recipes_for(test_type: str) -> tuple[str, ...]:
    if test_type == "ssti":
        return tuple(name for name, _ in SSTI_RECIPES)
    if test_type == "command_injection":
        return tuple(name for name, _ in CMDI_RECIPES)
    if test_type == "path_traversal":
        return tuple(name for name, *_ in TRAVERSAL_RECIPES)
    if test_type == "nosql":
        return ("operator_ne",)
    raise ValueError("Unsupported injection probe")


def nosql_field_name(parameter: str, step: str) -> str:
    """The query field name for one NoSQL step; controls keep the original name."""
    if step.startswith("true"):
        return f"{parameter}[$ne]"
    if step.startswith("false"):
        return f"{parameter}[$eq]"
    return parameter


def rename_query_field(url: str, parameter: str, new_name: str) -> str:
    """Rename exactly one query field, keeping its value and every other field."""
    from urllib.parse import quote, unquote_plus, urlsplit, urlunsplit

    parts = urlsplit(url)
    fields = parts.query.split("&")
    matches = [i for i, f in enumerate(fields) if f and unquote_plus(f.split("=", 1)[0]) == parameter]
    if len(matches) != 1:
        raise ValueError("observed_query_baseline_missing")
    name, _, value = fields[matches[0]].partition("=")
    fields[matches[0]] = quote(new_name, safe="") + "=" + value
    return urlunsplit(parts._replace(query="&".join(fields)))


def new_factors() -> tuple[int, int]:
    """Two five-digit primes-ish factors whose product is a 9-10 digit marker."""
    a = 10007 + secrets.randbelow(89000)
    b = 10007 + secrets.randbelow(89000)
    return a, b


def control_value(test_type: str, nonce: str) -> str:
    if test_type == "nosql":
        return f"prowl{nonce}"
    if test_type == "path_traversal":
        return f"../../../../../../../../etc/prowl-absent-{nonce}"
    return f"prowl{nonce}"


def probe_value(test_type: str, recipe: str, a: int = 0, b: int = 0) -> str:
    if test_type == "ssti":
        return dict(SSTI_RECIPES)[recipe].format(a=a, b=b)
    if test_type == "command_injection":
        return dict(CMDI_RECIPES)[recipe].format(a=a, b=b)
    if test_type == "path_traversal":
        return next(value for name, value, _ in TRAVERSAL_RECIPES if name == recipe)
    raise ValueError("Unsupported injection probe")


def _signature_for(recipe: str) -> str:
    return next((sig for name, _, sig in TRAVERSAL_RECIPES if name == recipe), "")


def _fetch(url: str, *, allowed_origin: str, state: dict | None) -> tuple[int, bytes]:
    assert_in_scope(url, [allowed_origin])
    headers = {"Accept": "text/html, application/json, */*;q=0.8"}
    cookie = _cookie_header(state, url)
    if cookie:
        headers["Cookie"] = cookie
    opener = build_opener(*assessment_urllib_handlers(), _NoRedirect())
    try:
        response = opener.open(Request(url, headers=headers, method="GET"), timeout=20)
    except HTTPError as error:
        response = error
    with response:
        return int(response.status or 0), response.read(MAX_BODY)


def _observation(status: int, body: bytes, *, test_type: str, marker: str,
                 signature: str) -> dict:
    if test_type == "path_traversal":
        # An empty signature means "any known file signature" (used for controls).
        patterns = [_FILE_SIGNATURES[signature]] if signature else list(_FILE_SIGNATURES.values())
        signal = any(pattern.search(body) for pattern in patterns)
    else:
        signal = bool(marker) and marker.encode() in body
    return {"status": status, "length": len(body),
            "sha256": hashlib.sha256(body).hexdigest()[:16], "signal": signal}


def probe_injection(urls: dict, *, test_type: str, allowed_origin: str,
                    state: dict | None, nonce: str, factors: tuple[int, int] = (0, 0),
                    fetch=_fetch) -> dict:
    """Run control first, then fixed probes until one shows the signal.

    ``urls`` maps ``"control"`` and each recipe name to an already-built,
    in-scope URL. The caller charges the request budget.
    """
    if test_type not in TEST_TYPES:
        raise ValueError("Unsupported injection probe")
    if not nonce or len(nonce) < MIN_MARKER_LENGTH or len(nonce) > 40 or not nonce.isalnum():
        raise ValueError("A random alphanumeric nonce of at least 8 characters is required")
    a, b = factors
    marker = ""
    if test_type != "path_traversal":
        if a < 10007 or b < 10007:
            raise ValueError("Fresh random factors are required")
        marker = str(a * b)
        if len(marker) < MIN_MARKER_LENGTH:
            raise ValueError("Computed marker is too short to be unique")
    order = [name for name in recipes_for(test_type) if name in urls]
    if "control" not in urls or not order:
        raise ValueError("Control and at least one probe URL are required")
    status, body = fetch(urls["control"], allowed_origin=allowed_origin, state=state)
    # Marker discipline: the control must not already show the signal.
    control = _observation(status, body, test_type=test_type, marker=marker, signature="")
    requests_sent = 1
    probes = []
    hit = ""
    if not control["signal"]:
        for name in order:
            status, body = fetch(urls[name], allowed_origin=allowed_origin, state=state)
            requests_sent += 1
            row = _observation(status, body, test_type=test_type, marker=marker,
                               signature=_signature_for(name))
            row["recipe"] = name
            probes.append(row)
            if row["signal"]:
                hit = name
                break
    probe = next((row for row in probes if row["recipe"] == hit), {})
    confirmed = bool(hit and not control["signal"] and probe.get("signal")
                     # Body-diff rule: a status change alone is never the signal.
                     and probe.get("sha256") != control.get("sha256"))
    return {
        "operation": "scoped_injection_probe", "test_type": test_type,
        "requests_sent": requests_sent, "control": control, "probes": probes,
        "recipe": hit, "marker_length": len(marker),
        "signature": _signature_for(hit) if test_type == "path_traversal" else "computed_product",
        "proof_confirmed": confirmed,
        "finding": False,
    }


_VOLATILE = re.compile(rb"[A-Za-z0-9+/=_-]{16,}")
_DIGITS = re.compile(rb"\d+")


def _stable_digest(body: bytes) -> str:
    """Digest with long tokens and numbers removed so CSRF tokens and clocks don't vary it."""
    return hashlib.sha256(_DIGITS.sub(b"0", _VOLATILE.sub(b"", body))).hexdigest()[:16]


def probe_nosql(urls: dict, *, allowed_origin: str, state: dict | None, nonce: str,
                fetch=_fetch) -> dict:
    """Interleaved operator differential; ``urls`` maps each NOSQL_SEQUENCE step."""
    if not nonce or len(nonce) < MIN_MARKER_LENGTH or len(nonce) > 40 or not nonce.isalnum():
        raise ValueError("A random alphanumeric nonce of at least 8 characters is required")
    if set(urls) != set(NOSQL_SEQUENCE):
        raise ValueError("Every NoSQL differential step needs a URL")
    checks = {}
    for step in NOSQL_SEQUENCE:
        status, body = fetch(urls[step], allowed_origin=allowed_origin, state=state)
        checks[step] = {"status": status, "length": len(body),
                        "sha256": _stable_digest(body)}
    digest = {step: row["sha256"] for step, row in checks.items()}
    stable_control = digest["control_first"] == digest["control_last"] == digest["false_first"]
    stable_true = digest["true_first"] == digest["true_second"]
    differs = digest["true_first"] != digest["control_first"]
    ok_status = all(200 <= row["status"] < 300 for row in checks.values())
    confirmed = bool(stable_control and stable_true and differs and ok_status)
    return {
        "operation": "scoped_injection_probe", "test_type": "nosql",
        "requests_sent": len(NOSQL_SEQUENCE), "checks": checks,
        "recipe": "operator_ne" if confirmed else "",
        "control": {"signal": False, "sha256": digest["control_first"]},
        "probes": [{"recipe": "operator_ne", "signal": confirmed,
                    "sha256": digest["true_first"]}],
        "signature": "operator_differential", "marker_length": len(nonce),
        "proof_confirmed": confirmed,
        "finding": False,
    }


def injection_proof_valid(row: dict) -> bool:
    """Structural check used by proof policy on stored hunter/verifier receipts."""
    if not isinstance(row, dict) or row.get("operation") != "scoped_injection_probe":
        return False
    test_type = row.get("test_type")
    if test_type not in TEST_TYPES or row.get("proof_confirmed") is not True:
        return False
    control = row.get("control") or {}
    probes = row.get("probes") or []
    hit = next((p for p in probes if isinstance(p, dict) and p.get("recipe") == row.get("recipe")), None)
    if not hit or hit.get("signal") is not True or control.get("signal") is not False:
        return False
    if hit.get("sha256") == control.get("sha256"):
        return False
    if test_type == "nosql":
        checks = row.get("checks") or {}
        if set(checks) != set(NOSQL_SEQUENCE):
            return False
        d = {step: (checks[step] or {}).get("sha256") for step in NOSQL_SEQUENCE}
        if not (d["control_first"] == d["control_last"] == d["false_first"]
                and d["true_first"] == d["true_second"] != d["control_first"]):
            return False
    elif test_type != "path_traversal" and int(row.get("marker_length") or 0) < MIN_MARKER_LENGTH:
        return False
    nonce = str(row.get("nonce") or "")
    if len(nonce) < MIN_MARKER_LENGTH:
        return False
    return int(row.get("requests_sent") or 0) >= 2
