"""Probe and recon logic ported from the Aegis Vanguard harness.

Sources (kept in Vanguard unchanged): ``agent/probes.py`` (server-side
prototype pollution), ``agent/api_probes.py`` (GraphQL), ``agent/vcs_dump.py``
(exposed ``.git``/``.svn``), the grpc/websocket hunter playbooks, and
``scanners.py`` (GitLab asset-hash fingerprint, mail intel, third-party vendor
intel).

Everything here is transport-free: drivers take an async ``send`` callable
(and, for mail intel, an async ``resolve`` callable) so the request plans and
verdicts are unit-tested without a network. The agent mixin binds ``send`` to
the scope-checked, evidence-recording ``_http_exchange``.

Every driver returns leads, never findings. A lead names the observed signal,
the evidence ids that back it, and what would have to be shown next.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import struct
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from app.services.secret_safety import secret_descriptor

logger = logging.getLogger(__name__)

# send(method, url, headers, body) -> {"status", "headers", "body", "body_bytes",
#   "evidence_id", "error", "skipped", "cookie_sent"}
Send = Callable[..., Awaitable[Dict[str, Any]]]
Resolve = Callable[[str, str], Awaitable[List[str]]]

LEAD_NOTE = (
    "Leads only: this tool never creates findings. Reproduce the signal with a "
    "bounded follow-up, then submit_finding_candidate with the evidence ids so the "
    "independent verifier can decide."
)


def _status(resp: Dict[str, Any]) -> Optional[int]:
    status = resp.get("status")
    return int(status) if isinstance(status, int) else None


def _body(resp: Dict[str, Any]) -> str:
    return str(resp.get("body") or "")


def _evidence(*responses: Dict[str, Any]) -> List[str]:
    return [str(r["evidence_id"]) for r in responses if r and r.get("evidence_id")]


def _lead(signal: str, strength: str, detail: str, evidence_ids: List[str],
          next_step: str, **extra: Any) -> Dict[str, Any]:
    return {"signal": signal, "strength": strength, "detail": detail,
            "evidence_ids": evidence_ids, "next_step": next_step, **extra}


def summarize(tool: str, target: str, leads: List[Dict[str, Any]],
              responses: Iterable[Dict[str, Any]], *, skipped: Optional[List[str]] = None,
              inconclusive: str = "", **extra: Any) -> Dict[str, Any]:
    """Common result envelope for every ported probe."""
    responses = [r for r in responses if r]
    if leads:
        verdict = "LEAD"
    elif inconclusive or (skipped and not any(_status(r) is not None for r in responses)):
        verdict = "INCONCLUSIVE"
    else:
        verdict = "NO_SIGNAL"
    out: Dict[str, Any] = {
        "tool": tool,
        "target": target,
        "verdict": verdict,
        "leads": leads,
        "evidence_ids": sorted({e for r in responses for e in _evidence(r)}),
        "requests_sent": sum(1 for r in responses if _status(r) is not None),
        "note": LEAD_NOTE,
    }
    if skipped:
        out["skipped"] = skipped
    if inconclusive:
        out["inconclusive_reason"] = inconclusive
    out.update(extra)
    return out


def _with_params(url: str, params: List[Tuple[str, str]]) -> str:
    parts = urlsplit(url)
    query = parse_qsl(parts.query, keep_blank_values=True) + list(params)
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", urlencode(query), ""))


def origin_of(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


# ---------------------------------------------------------------------------
# Server-side prototype pollution (Vanguard agent/probes.py)
# ---------------------------------------------------------------------------

def pp_marker(nonce: str) -> Tuple[str, str]:
    """Inert property name/value pair unique to this probe run."""
    clean = re.sub(r"[^a-z0-9]", "", str(nonce).lower())[:12] or "0"
    return f"aegpp{clean}", f"polluted{clean}"


def pp_hit(base: Dict[str, Any], polluted: Dict[str, Any], marker_val: str) -> Optional[str]:
    """Vanguard ``_pp_hit``: reflected marker, or a 200 -> 5xx flip."""
    if polluted.get("error") or polluted.get("skipped"):
        return None
    if marker_val in _body(polluted) and marker_val not in _body(base):
        return "polluted property reflected in response"
    if _status(base) == 200 and _status(polluted) in (500, 502):
        return f"pollution caused a server error (HTTP {_status(polluted)})"
    return None


def pp_vectors(target_url: str, key: str, val: str) -> List[Dict[str, Any]]:
    """Pollution vectors, each paired with a plain-property control."""
    json_hdr = {"Content-Type": "application/json"}
    return [
        {
            "name": "query_proto",
            "method": "GET",
            "url": _with_params(target_url, [(f"__proto__[{key}]", val),
                                             (f"constructor[prototype][{key}]", val)]),
            "headers": {}, "body": "",
            "control": {"method": "GET", "url": _with_params(target_url, [(key, val)]),
                        "headers": {}, "body": ""},
        },
        {
            "name": "json_proto",
            "method": "POST", "url": target_url, "headers": json_hdr,
            "body": json.dumps({"__proto__": {key: val}}),
            "control": {"method": "POST", "url": target_url, "headers": json_hdr,
                        "body": json.dumps({key: val})},
        },
        {
            "name": "json_constructor",
            "method": "POST", "url": target_url, "headers": json_hdr,
            "body": json.dumps({"constructor": {"prototype": {key: val}}}),
            "control": {"method": "POST", "url": target_url, "headers": json_hdr,
                        "body": json.dumps({key: val})},
        },
    ]


def classify_pp(base: Dict[str, Any], polluted: Dict[str, Any], control: Dict[str, Any],
                marker_val: str) -> Optional[Tuple[str, str]]:
    """(strength, reason) when a vector differs from both baseline and control.

    An endpoint that echoes any input reflects the marker for the plain-property
    control too; that is an echo, not pollution.
    """
    why = pp_hit(base, polluted, marker_val)
    if not why:
        return None
    control_echo = marker_val in _body(control)
    control_error = _status(control) in (500, 502)
    if "reflected" in why:
        if control_echo:
            return None
        return "medium", why + " (plain-property control did not echo it)"
    if control_error:
        return None
    return "weak", why + " (plain-property control did not error)"


async def run_prototype_pollution(target_url: str, send: Send, nonce: str) -> Dict[str, Any]:
    key, val = pp_marker(nonce)
    base = await send("GET", target_url, {}, "")
    responses = [base]
    leads: List[Dict[str, Any]] = []
    skipped: List[str] = []
    if _status(base) is None:
        return summarize("probe_server_prototype_pollution", target_url, [], responses,
                         inconclusive=f"baseline failed: {base.get('error') or base.get('skipped')}")
    for vector in pp_vectors(target_url, key, val):
        polluted = await send(vector["method"], vector["url"], vector["headers"], vector["body"])
        responses.append(polluted)
        if polluted.get("skipped"):
            skipped.append(f"{vector['name']}: {polluted['skipped']}")
            continue
        ctl = vector["control"]
        control = await send(ctl["method"], ctl["url"], ctl["headers"], ctl["body"])
        responses.append(control)
        verdict = classify_pp(base, polluted, control, val)
        if verdict:
            strength, why = verdict
            leads.append(_lead(
                "server_prototype_pollution", strength, f"{vector['name']}: {why}",
                _evidence(base, polluted, control),
                "Re-fetch an unrelated endpoint for the marker property, or test a "
                "gadget with a measurable non-destructive effect, before submitting.",
                vector=vector["name"], marker_property=key,
            ))
            break
    # A property that shows up on a fresh baseline after pollution persisted on
    # the server-wide prototype: the strongest signal this probe can produce.
    if leads or any(not r.get("skipped") for r in responses[1:]):
        followup = await send("GET", target_url, {}, "")
        responses.append(followup)
        if val in _body(followup) and val not in _body(base):
            leads.insert(0, _lead(
                "server_prototype_pollution", "strong",
                "marker property appears on a fresh unpolluted request after the vectors ran",
                _evidence(base, followup),
                "The prototype stays polluted until the process restarts; tell the operator, "
                "then submit_finding_candidate with these evidence ids.",
                marker_property=key,
            ))
    return summarize("probe_server_prototype_pollution", target_url, leads, responses,
                     skipped=skipped, marker_property=key,
                     caution=("A vulnerable server keeps the inert marker property on its "
                              "global prototype until restart."))


# ---------------------------------------------------------------------------
# GraphQL (Vanguard agent/api_probes.py; shares heuristics with
# app.services.graphql_scanner_service)
# ---------------------------------------------------------------------------

GQL_INTROSPECTION_QUERY = "query{__schema{types{name}}}"
GQL_TYPENAME_QUERY = "{__typename}"


def _json(body: str) -> Any:
    try:
        return json.loads(body)
    except (ValueError, TypeError):
        return None


def introspection_enabled(resp_body: str) -> bool:
    data = _json(resp_body)
    if not isinstance(data, dict):
        return False
    return bool(((data.get("data") or {}).get("__schema") or {}).get("types"))


def suggestions_leak(resp_body: str) -> bool:
    return "did you mean" in (resp_body or "").lower()


def batching_enabled(resp_body: str) -> bool:
    data = _json(resp_body)
    return isinstance(data, list) and len(data) >= 2


def typename_answered(resp_body: str) -> bool:
    data = _json(resp_body)
    return isinstance(data, dict) and isinstance(data.get("data"), dict) and "__typename" in data["data"]


def schema_type_names(resp_body: str, limit: int = 40) -> List[str]:
    data = _json(resp_body)
    if not isinstance(data, dict):
        return []
    types = ((data.get("data") or {}).get("__schema") or {}).get("types") or []
    names = [str(t.get("name")) for t in types if isinstance(t, dict) and t.get("name")]
    return [n for n in names if not n.startswith("__")][:limit]


async def run_graphql(endpoint_url: str, send: Send) -> Dict[str, Any]:
    from app.services.graphql_scanner_service import FIELD_SUGGESTION_QUERY, _looks_like_graphql

    hdrs = {"Content-Type": "application/json"}
    leads: List[Dict[str, Any]] = []
    skipped: List[str] = []
    responses: List[Dict[str, Any]] = []
    extra: Dict[str, Any] = {}

    intro = await send("POST", endpoint_url, hdrs, json.dumps({"query": GQL_INTROSPECTION_QUERY}))
    responses.append(intro)
    if intro.get("skipped"):
        skipped.append(f"POST introspection: {intro['skipped']}")
        intro = await send("GET", _with_params(endpoint_url, [("query", GQL_INTROSPECTION_QUERY)]),
                           {}, "")
        responses.append(intro)
    if introspection_enabled(_body(intro)):
        names = schema_type_names(_body(intro))
        extra["schema_types_sample"] = names
        leads.append(_lead(
            "graphql_introspection", "medium",
            f"__schema returned {len(names)} non-meta type names",
            _evidence(intro),
            "Introspection alone is informational; map mutations/queries over users, "
            "files or payments and test their authorization before submitting.",
        ))

    batch = await send("POST", endpoint_url, hdrs,
                       json.dumps([{"query": GQL_TYPENAME_QUERY}, {"query": GQL_TYPENAME_QUERY}]))
    responses.append(batch)
    if batch.get("skipped"):
        skipped.append(f"POST batching: {batch['skipped']}")
    elif batching_enabled(_body(batch)):
        leads.append(_lead(
            "graphql_batching", "weak", "an array of two queries returned an array of results",
            _evidence(batch),
            "Batching matters only with a rate-limited operation (login, OTP, coupon); "
            "show the limit is bypassed before submitting.",
        ))

    typo = await send("POST", endpoint_url, hdrs, json.dumps({"query": FIELD_SUGGESTION_QUERY}))
    responses.append(typo)
    if typo.get("skipped"):
        skipped.append(f"POST suggestions: {typo['skipped']}")
    elif suggestions_leak(_body(typo)):
        leads.append(_lead(
            "graphql_suggestions", "weak", "'Did you mean' suggestions leak schema field names",
            _evidence(typo),
            "Use suggestions to recover hidden fields when introspection is off; "
            "report only together with an impactful hidden operation.",
        ))

    get_q = await send("GET", _with_params(endpoint_url, [("query", GQL_TYPENAME_QUERY)]), {}, "")
    responses.append(get_q)
    if typename_answered(_body(get_q)) or (
        _status(get_q) == 200 and _looks_like_graphql(_body(get_q)) and '"data"' in _body(get_q)
    ):
        leads.append(_lead(
            "graphql_get_queries", "weak", "queries are executed over GET",
            _evidence(get_q),
            "Relevant to CSRF only with cookie authentication and a state-changing "
            "mutation reachable over GET.",
        ))

    is_graphql = any(_looks_like_graphql(_body(r)) or typename_answered(_body(r))
                     or batching_enabled(_body(r)) for r in responses)
    return summarize("probe_graphql", endpoint_url, leads, responses, skipped=skipped,
                     inconclusive="" if (is_graphql or leads) else "no GraphQL response shape observed",
                     looks_like_graphql=is_graphql, **extra)


# ---------------------------------------------------------------------------
# Exposed VCS directories (Vanguard agent/vcs_dump.py) with redaction
# ---------------------------------------------------------------------------

GIT_PATHS = ["/.git/HEAD", "/.git/config", "/.git/index", "/.git/logs/HEAD",
             "/.git/packed-refs"]
SVN_PATHS = ["/.svn/wc.db", "/.svn/entries"]

# Signatures that confirm a path is a real VCS artifact, not a soft-404 page.
VCS_SIGNATURES = {
    "/.git/HEAD": re.compile(r"\A\s*(ref:\s+refs/|[0-9a-f]{40}\s*\Z)"),
    "/.git/config": re.compile(r"^\s*\[(core|remote |branch )", re.IGNORECASE | re.MULTILINE),
    "/.git/logs/HEAD": re.compile(r"^[0-9a-f]{40} [0-9a-f]{40} ", re.MULTILINE),
    "/.git/index": re.compile(r"\ADIRC"),
    "/.git/packed-refs": re.compile(r"^[0-9a-f]{40} refs/", re.MULTILINE),
    "/.svn/wc.db": re.compile(r"\ASQLite format 3"),
    "/.svn/entries": re.compile(r"\A\s*\d+\s*\n"),
}

_HTMLISH = re.compile(r"<\s*(!doctype|html|head|body)\b", re.IGNORECASE)
_URL_WITH_USERINFO = re.compile(r"(?P<scheme>[a-z][a-z0-9+.\-]*://)(?P<userinfo>[^/\s@]+)@(?P<rest>[^\s]*)",
                                re.IGNORECASE)
_EXTRAHEADER = re.compile(r"^\s*extraheader\s*=\s*(?P<value>.+?)\s*$", re.IGNORECASE | re.MULTILINE)
_AUTH_VALUE = re.compile(r"(?i)^(?:authorization\s*:\s*)?(?P<scheme>basic|bearer|token)\s+(?P<secret>\S+)")
_PASSWORDISH = re.compile(r"^\s*(?P<key>password|passwd|token|secret|accesstoken)\s*=\s*(?P<value>.+?)\s*$",
                          re.IGNORECASE | re.MULTILINE)
_BENIGN_USERNAMES = {"git", "oauth2", "x-access-token", "gitlab-ci-token", "x-token-auth",
                     "token", "pat", "bitbucket", "azure", "anonymous"}


def vcs_confirms(path: str, body: str) -> bool:
    """True when ``body`` carries the signature for that VCS artifact."""
    body = body or ""
    sig = VCS_SIGNATURES.get(path)
    if sig is None:
        return bool(body) and not _HTMLISH.search(body[:2048])
    return bool(sig.search(body))


def _section_at(config_body: str, offset: int) -> str:
    sections = list(re.finditer(r"^\s*\[([^\]]+)\]", config_body[:offset], re.MULTILINE))
    return sections[-1].group(1).strip() if sections else ""


def redact_url_userinfo(url: str) -> Tuple[str, Optional[Dict[str, Any]]]:
    """Replace any URL userinfo with a fingerprint; return (safe_url, credential)."""
    match = _URL_WITH_USERINFO.search(url or "")
    if not match:
        return url, None
    userinfo = match.group("userinfo")
    user, _, password = userinfo.partition(":")
    host = urlsplit(match.group("scheme") + match.group("rest")).hostname or ""
    descriptor = secret_descriptor(userinfo)
    safe = url[: match.start("userinfo")] + descriptor["redacted"] + url[match.end("userinfo"):]
    credential = {
        "kind": "url_userinfo",
        "host": host,
        "username": user if user.lower() in _BENIGN_USERNAMES else ("[redacted]" if user else ""),
        "has_password": bool(password),
        **descriptor,
    }
    return safe, credential


def extract_git_config(config_body: str) -> Dict[str, Any]:
    """Remote URLs and credentials from a ``.git/config``; secrets never raw.

    Vanguard returned remote URLs verbatim (credentials included). Here every
    credential is replaced by a ``secret_safety`` fingerprint.
    """
    body = config_body or ""
    remotes: List[Dict[str, Any]] = []
    credentials: List[Dict[str, Any]] = []
    for match in re.finditer(r"^\s*(?:push)?url\s*=\s*(?P<url>\S+)", body, re.IGNORECASE | re.MULTILINE):
        safe, cred = redact_url_userinfo(match.group("url"))
        section = _section_at(body, match.start())
        remotes.append({"section": section, "url": safe, "has_credentials": cred is not None})
        if cred:
            credentials.append({**cred, "section": section})
    for match in _EXTRAHEADER.finditer(body):
        value = match.group("value")
        auth = _AUTH_VALUE.match(value)
        secret = auth.group("secret") if auth else value
        credentials.append({
            "kind": "http_extraheader",
            "scheme": (auth.group("scheme").lower() if auth else "unknown"),
            "section": _section_at(body, match.start()),
            **secret_descriptor(secret),
        })
    for match in _PASSWORDISH.finditer(body):
        credentials.append({
            "kind": f"config_{match.group('key').lower()}",
            "section": _section_at(body, match.start()),
            **secret_descriptor(match.group("value")),
        })
    return {"remotes": remotes, "credentials": credentials,
            "credential_count": len(credentials)}


def git_refs(packed_refs: str = "", head: str = "") -> Dict[str, Any]:
    branches = sorted({m.group(1) for m in re.finditer(r"^[0-9a-f]{40} refs/heads/(\S+)",
                                                       packed_refs or "", re.MULTILINE)})
    tags = sorted({m.group(1) for m in re.finditer(r"^[0-9a-f]{40} refs/tags/(\S+)",
                                                   packed_refs or "", re.MULTILINE)})
    head_ref = ""
    match = re.match(r"\s*ref:\s+(\S+)", head or "")
    if match:
        head_ref = match.group(1)
    return {"head": head_ref, "branches": branches[:50], "tags": tags[:50]}


def git_index_summary(data: bytes) -> Dict[str, Any]:
    """Version and entry count from a ``.git/index`` header (no file names)."""
    if not data or len(data) < 12 or data[:4] != b"DIRC":
        return {}
    version, entries = struct.unpack(">II", data[4:12])
    return {"version": version, "tracked_files": entries}


def git_log_summary(logs_head: str) -> Dict[str, Any]:
    lines = [ln for ln in (logs_head or "").splitlines() if re.match(r"^[0-9a-f]{40} ", ln)]
    return {"reflog_entries": len(lines)}


async def run_vcs_dump(base_url: str, send: Send) -> Dict[str, Any]:
    base = base_url.rstrip("/")
    accessible: List[str] = []
    artifacts: Dict[str, Any] = {}
    responses: List[Dict[str, Any]] = []
    bodies: Dict[str, Dict[str, Any]] = {}
    skipped: List[str] = []
    for path in GIT_PATHS + SVN_PATHS:
        resp = await send("GET", base + path, {}, "")
        responses.append(resp)
        if resp.get("skipped") or resp.get("error"):
            skipped.append(f"{path}: {resp.get('skipped') or resp.get('error')}")
            continue
        if _status(resp) == 200 and vcs_confirms(path, _body(resp)):
            accessible.append(path)
            bodies[path] = resp
    if "/.git/config" in bodies:
        artifacts["git_config"] = extract_git_config(_body(bodies["/.git/config"]))
    if "/.git/HEAD" in bodies or "/.git/packed-refs" in bodies:
        artifacts["refs"] = git_refs(_body(bodies.get("/.git/packed-refs", {})),
                                     _body(bodies.get("/.git/HEAD", {})))
    if "/.git/index" in bodies:
        artifacts["index"] = git_index_summary(bodies["/.git/index"].get("body_bytes") or b"")
    if "/.git/logs/HEAD" in bodies:
        artifacts["reflog"] = git_log_summary(_body(bodies["/.git/logs/HEAD"]))

    leads: List[Dict[str, Any]] = []
    if accessible:
        creds = (artifacts.get("git_config") or {}).get("credentials") or []
        detail = "accessible VCS artifacts: " + ", ".join(accessible)
        if creds:
            detail += f"; {len(creds)} credential(s) in .git/config (fingerprinted, values withheld)"
        leads.append(_lead(
            "vcs_exposure", "strong" if creds else "medium", detail,
            _evidence(*bodies.values()),
            ("Credentials are reported as fingerprints only; do not try them. "
             "Submit with these evidence ids; a full tree reconstruction needs "
             "explicit operator authorization."),
            severity_hint="critical" if creds else "high",
        ))
    return summarize("probe_vcs_exposure", base, leads, responses, skipped=skipped,
                     accessible=accessible, artifacts=artifacts)


# ---------------------------------------------------------------------------
# gRPC server reflection (Vanguard grpc_hunter methodology step 3)
# ---------------------------------------------------------------------------

GRPC_REFLECTION_PATHS = [
    "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
    "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
]
GRPC_STATUS_NAMES = {
    0: "OK", 1: "CANCELLED", 2: "UNKNOWN", 3: "INVALID_ARGUMENT", 5: "NOT_FOUND",
    7: "PERMISSION_DENIED", 12: "UNIMPLEMENTED", 13: "INTERNAL", 14: "UNAVAILABLE",
    16: "UNAUTHENTICATED",
}


def grpc_frame(message: bytes, flags: int = 0) -> bytes:
    return bytes([flags]) + struct.pack(">I", len(message)) + message


def reflection_list_services_request() -> bytes:
    """ServerReflectionRequest{list_services: ""} (field 7, length-delimited)."""
    return b"\x3a\x00"


def parse_grpc_frames(data: bytes) -> Tuple[List[bytes], Dict[str, str]]:
    """Split a gRPC / gRPC-Web body into messages and (gRPC-Web) trailers."""
    messages: List[bytes] = []
    trailers: Dict[str, str] = {}
    pos = 0
    while pos + 5 <= len(data or b""):
        flags = data[pos]
        length = struct.unpack(">I", data[pos + 1:pos + 5])[0]
        chunk = data[pos + 5:pos + 5 + length]
        pos += 5 + length
        if flags & 0x80:
            for line in chunk.decode("utf-8", "replace").splitlines():
                name, _, value = line.partition(":")
                if name.strip():
                    trailers[name.strip().lower()] = value.strip()
        else:
            messages.append(chunk)
    return messages, trailers


def _varint(data: bytes, pos: int) -> Tuple[int, int]:
    result = shift = 0
    while pos < len(data):
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift > 63:
            break
    raise ValueError("malformed varint")


def protobuf_fields(data: bytes) -> List[Tuple[int, Any]]:
    """Minimal protobuf decoder: [(field_number, int|bytes)]."""
    fields: List[Tuple[int, Any]] = []
    pos = 0
    while pos < len(data):
        key, pos = _varint(data, pos)
        field, wire = key >> 3, key & 7
        if wire == 0:
            value, pos = _varint(data, pos)
        elif wire == 2:
            length, pos = _varint(data, pos)
            value = data[pos:pos + length]
            pos += length
        elif wire == 1:
            value, pos = data[pos:pos + 8], pos + 8
        elif wire == 5:
            value, pos = data[pos:pos + 4], pos + 4
        else:
            raise ValueError(f"unsupported wire type {wire}")
        fields.append((field, value))
    return fields


def parse_list_services(message: bytes) -> Dict[str, Any]:
    """Decode ServerReflectionResponse -> services or an error response."""
    services: List[str] = []
    error: Dict[str, Any] = {}
    for field, value in protobuf_fields(message):
        if field == 6 and isinstance(value, bytes):  # list_services_response
            for sub_field, service in protobuf_fields(value):
                if sub_field == 1 and isinstance(service, bytes):
                    for name_field, name in protobuf_fields(service):
                        if name_field == 1 and isinstance(name, bytes):
                            services.append(name.decode("utf-8", "replace"))
        elif field == 7 and isinstance(value, bytes):  # error_response
            for err_field, err_value in protobuf_fields(value):
                if err_field == 1 and isinstance(err_value, int):
                    error["code"] = err_value
                elif err_field == 2 and isinstance(err_value, bytes):
                    error["message"] = err_value.decode("utf-8", "replace")[:200]
    return {"services": services, "error": error}


def grpc_status(resp: Dict[str, Any], trailers: Dict[str, str]) -> Optional[int]:
    headers = {str(k).lower(): str(v) for k, v in (resp.get("headers") or {}).items()}
    raw = trailers.get("grpc-status", headers.get("grpc-status"))
    try:
        return int(raw) if raw is not None else None
    except ValueError:
        return None


def grpc_attempts(base_url: str) -> List[Dict[str, Any]]:
    base = base_url.rstrip("/")
    frame = grpc_frame(reflection_list_services_request())
    # The frame is pure ASCII, so it travels unchanged through the text-body
    # HTTP path (UTF-8 encoding of these code points is byte-identical).
    assert all(b < 0x80 for b in frame)
    request = frame.decode("ascii")
    attempts = []
    for path in GRPC_REFLECTION_PATHS:
        attempts.append({"mode": "grpc_h2", "url": base + path, "http2": True,
                         "headers": {"Content-Type": "application/grpc", "TE": "trailers"},
                         "body": request})
    for path in GRPC_REFLECTION_PATHS:
        attempts.append({"mode": "grpc_web", "url": base + path, "http2": False,
                         "headers": {"Content-Type": "application/grpc-web+proto",
                                     "X-Grpc-Web": "1", "Accept": "application/grpc-web+proto"},
                         "body": request})
    return attempts


async def run_grpc_reflection(base_url: str, send: Send) -> Dict[str, Any]:
    leads: List[Dict[str, Any]] = []
    responses: List[Dict[str, Any]] = []
    skipped: List[str] = []
    observations: List[Dict[str, Any]] = []
    for attempt in grpc_attempts(base_url):
        resp = await send("POST", attempt["url"], attempt["headers"], attempt["body"],
                          http2=attempt["http2"])
        responses.append(resp)
        if resp.get("skipped") or resp.get("error"):
            skipped.append(f"{attempt['mode']} {urlsplit(attempt['url']).path}: "
                           f"{resp.get('skipped') or resp.get('error')}")
            continue
        try:
            messages, trailers = parse_grpc_frames(resp.get("body_bytes") or b"")
            parsed = [parse_list_services(m) for m in messages]
        except (ValueError, struct.error):
            messages, trailers, parsed = [], {}, []
        status = grpc_status(resp, trailers)
        services = sorted({s for p in parsed for s in p["services"]})
        observations.append({
            "mode": attempt["mode"], "path": urlsplit(attempt["url"]).path,
            "http_status": _status(resp), "grpc_status": status,
            "grpc_status_name": GRPC_STATUS_NAMES.get(status, "") if status is not None else "",
            "service_count": len(services),
        })
        if services:
            leads.append(_lead(
                "grpc_reflection_unauthenticated", "medium",
                f"server reflection listed {len(services)} service(s) without credentials",
                _evidence(resp),
                "Reflection is a disclosure lead; pick a non-reflection method that returns "
                "data and show it answers without credentials before submitting.",
                mode=attempt["mode"], services=services[:50],
            ))
            break
    reached = any(o.get("grpc_status") is not None or o.get("service_count") for o in observations)
    return summarize("probe_grpc_reflection", base_url, leads, responses, skipped=skipped,
                     inconclusive="" if (leads or reached) else "no gRPC response observed",
                     observations=observations,
                     limitation=("Lists services only; it never calls application methods. "
                                 "grpcurl is not used."))


# ---------------------------------------------------------------------------
# WebSocket Origin check / CSWSH (Vanguard websocket_hunter methodology step 3)
# ---------------------------------------------------------------------------

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def ws_accept_value(key: str) -> str:
    return base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()


def ws_http_url(url: str) -> str:
    parts = urlsplit(url)
    scheme = {"ws": "http", "wss": "https"}.get(parts.scheme.lower(), parts.scheme.lower())
    return urlunsplit((scheme, parts.netloc, parts.path or "/", parts.query, ""))


def ws_handshake_headers(key: str, origin: Optional[str], subprotocol: str = "") -> Dict[str, str]:
    headers = {
        "Connection": "Upgrade", "Upgrade": "websocket",
        "Sec-WebSocket-Version": "13", "Sec-WebSocket-Key": key,
    }
    if origin is not None:
        headers["Origin"] = origin
    if subprotocol:
        headers["Sec-WebSocket-Protocol"] = subprotocol
    return headers


def ws_accepted(resp: Dict[str, Any], key: str) -> bool:
    headers = {str(k).lower(): str(v) for k, v in (resp.get("headers") or {}).items()}
    return _status(resp) == 101 and headers.get("sec-websocket-accept") == ws_accept_value(key)


def classify_ws_origin(control_ok: bool, results: Dict[str, bool], cookie_sent: bool) -> Tuple[str, str]:
    """(verdict, reason) from the same-origin control and foreign-origin attempts."""
    if not control_ok:
        return "inconclusive", "same-origin handshake was not accepted (wrong path, auth or subprotocol)"
    accepted = sorted(name for name, ok in results.items() if ok)
    if not accepted:
        return "enforced", "foreign origins were rejected while the same-origin handshake succeeded"
    if cookie_sent:
        return "lead", f"handshake accepted with foreign Origin ({', '.join(accepted)}) on a cookie-bearing request"
    return "weak", (f"handshake accepted with foreign Origin ({', '.join(accepted)}) but no session cookie "
                    "was sent; CSWSH needs ambient cookie auth")


async def run_websocket_origin(ws_url: str, send: Send, nonce: str, subprotocol: str = "") -> Dict[str, Any]:
    url = ws_http_url(ws_url)
    own = origin_of(url)
    canary = f"https://{re.sub(r'[^a-z0-9]', '', nonce.lower())[:12] or 'x'}.cswsh-check.invalid"

    def key() -> str:
        return base64.b64encode(hashlib.sha256(f"{nonce}:{os.urandom(8).hex()}".encode()).digest()[:16]).decode()

    responses: List[Dict[str, Any]] = []
    ctl_key = key()
    control = await send("GET", url, ws_handshake_headers(ctl_key, own, subprotocol), "")
    responses.append(control)
    control_ok = ws_accepted(control, ctl_key)
    results: Dict[str, bool] = {}
    cookie_sent = bool(control.get("cookie_sent"))
    if control_ok:
        for label, origin in (("foreign", canary), ("null", "null"), ("absent", None)):
            k = key()
            resp = await send("GET", url, ws_handshake_headers(k, origin, subprotocol), "")
            responses.append(resp)
            if label != "absent":
                results[label] = ws_accepted(resp, k)
            cookie_sent = cookie_sent or bool(resp.get("cookie_sent"))
    verdict, reason = classify_ws_origin(control_ok, results, cookie_sent)
    leads = []
    if verdict in ("lead", "weak"):
        leads.append(_lead(
            "websocket_origin_not_validated", "medium" if verdict == "lead" else "weak", reason,
            _evidence(*responses),
            "Show a cross-site page can read or send user data over the socket (subscribe "
            "to the user's channel) before submitting as CSWSH.",
            foreign_origin=canary,
        ))
    return summarize("probe_websocket_origin", ws_url, leads, responses,
                     inconclusive=reason if verdict == "inconclusive" else "",
                     origin_policy=verdict, cookie_sent=cookie_sent)


# ---------------------------------------------------------------------------
# GitLab asset-hash fingerprint (Vanguard scanners.run_gitlab_fingerprint)
# ---------------------------------------------------------------------------

KNOWN_GITLAB_ASSET_HASHES: Dict[str, Dict[str, Any]] = {
    # Seen in public reporting as useful for GitLab CE version correlation.
    # Keep version empty unless a local hash DB confirms the exact release.
    "4a081f9e3a60a0e580cad484d66fbf5a1505ad313280e96728729069f87f856e": {
        "product": "GitLab CE",
        "notes": "Known GitLab /help stylesheet hash; provide GITLAB_HASH_DB_PATH for exact version mapping.",
        "cve_candidates": ["CVE-2021-22205"],
    },
}


def load_gitlab_hash_db(db_path: str = "") -> Dict[str, Dict[str, Any]]:
    path = db_path or os.environ.get("GITLAB_HASH_DB_PATH", "")
    db = dict(KNOWN_GITLAB_ASSET_HASHES)
    if not path:
        return db
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except Exception as exc:
        logger.warning("failed to load GitLab hash DB %s: %s", path, exc)
        return db
    if isinstance(data, dict):
        for asset_hash, record in data.items():
            if isinstance(record, str):
                db[asset_hash.lower()] = {"version": record}
            elif isinstance(record, dict):
                db[asset_hash.lower()] = record
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                asset_hash = str(item.get("hash") or item.get("sha256") or "").lower()
                if asset_hash:
                    db[asset_hash] = item
    return db


def parse_version_tuple(version: str) -> tuple:
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", version or "")
    return tuple(int(part) for part in match.groups()) if match else ()


def gitlab_cve_2021_22205_risk(version: str) -> str:
    """vulnerable/patched/unknown for CVE-2021-22205 (11.9 - 13.8.7, 13.9.0 - 13.9.5,
    13.10.0 - 13.10.2)."""
    v = parse_version_tuple(version)
    if not v:
        return "unknown"
    major, minor, patch = v
    if major < 11 or (major == 11 and minor < 9):
        return "unknown"
    if major < 13:
        return "vulnerable"
    if major > 13:
        return "patched"
    if minor < 8:
        return "vulnerable"
    if minor == 8:
        return "patched" if patch >= 8 else "vulnerable"
    if minor == 9:
        return "patched" if patch >= 6 else "vulnerable"
    if minor == 10:
        return "patched" if patch >= 3 else "vulnerable"
    return "patched"


_STYLESHEET = re.compile(r"""<link[^>]+href=["']([^"']+\.css(?:\?[^"']*)?)["']""", re.IGNORECASE)


def gitlab_stylesheets(help_body: str, help_url: str, limit: int = 20) -> List[str]:
    hrefs = _STYLESHEET.findall(help_body or "")
    urls = list(dict.fromkeys(urljoin(help_url, h) for h in hrefs))
    return urls[: max(1, min(int(limit or 20), 50))]


def is_probable_gitlab(body: str, headers: Dict[str, Any]) -> bool:
    return ("gitlab" in (body or "")[:20000].lower()
            or "gitlab" in json.dumps(headers or {}, default=str).lower()
            or "/assets/application-" in (body or ""))


def gitlab_overall_risk(matches: List[Dict[str, Any]]) -> str:
    if any(m.get("cve_2021_22205_risk") == "vulnerable" for m in matches):
        return "vulnerable"
    versioned = [m for m in matches if m.get("version")]
    if versioned and all(m.get("cve_2021_22205_risk") == "patched" for m in versioned):
        return "patched"
    return "unknown"


async def run_gitlab_fingerprint(target_url: str, send: Send, hash_db: Dict[str, Dict[str, Any]],
                                 max_assets: int = 20) -> Dict[str, Any]:
    base = target_url.rstrip("/")
    if not urlsplit(base).scheme:
        base = f"https://{base}"
    help_url = urljoin(base + "/", "help")
    page = await send("GET", help_url, {}, "")
    responses = [page]
    if _status(page) is None:
        return summarize("fingerprint_gitlab", target_url, [], responses,
                         inconclusive=f"/help fetch failed: {page.get('error') or page.get('skipped')}")
    body = _body(page)
    assets: List[Dict[str, Any]] = []
    matches: List[Dict[str, Any]] = []
    skipped: List[str] = []
    for asset_url in gitlab_stylesheets(body, help_url, max_assets):
        resp = await send("GET", asset_url, {}, "")
        responses.append(resp)
        if resp.get("skipped") or resp.get("error"):
            skipped.append(f"{asset_url}: {resp.get('skipped') or resp.get('error')}")
            continue
        content = resp.get("body_bytes")
        if content is None:
            content = _body(resp).encode()
        sha256 = hashlib.sha256(content).hexdigest()
        asset = {"url": asset_url, "status_code": _status(resp), "sha256": sha256, "bytes": len(content)}
        record = hash_db.get(sha256)
        if record:
            version = str(record.get("version") or "")
            asset["hash_db_match"] = True
            matches.append({"asset_url": asset_url, "sha256": sha256, "version": version or None,
                            "record": record,
                            "cve_2021_22205_risk": gitlab_cve_2021_22205_risk(version),
                            "evidence_id": resp.get("evidence_id", "")})
        assets.append(asset)
    probable = is_probable_gitlab(body, page.get("headers") or {}) or bool(matches)
    risk = gitlab_overall_risk(matches)
    versions = sorted({m["version"] for m in matches if m.get("version")})
    leads = []
    if risk == "vulnerable":
        leads.append(_lead(
            "gitlab_version_in_cve_2021_22205_range", "medium",
            f"stylesheet hash maps to GitLab {', '.join(versions) or '?'} in the vulnerable range",
            _evidence(page) + [m["evidence_id"] for m in matches if m.get("evidence_id")],
            "Version-in-range is a lead; confirm the version from a second source (e.g. "
            "/api/v4/version with a token, or /help text) before submitting. Exploit "
            "validation needs explicit authorization and an approved OOB collaborator.",
            cve_id="CVE-2021-22205",
        ))
    return summarize("fingerprint_gitlab", target_url, leads, responses, skipped=skipped,
                     help_url=help_url, is_probable_gitlab=probable, versions=versions,
                     cve_2021_22205_risk=risk, asset_count=len(assets),
                     matches=[{k: v for k, v in m.items() if k != "record"} for m in matches],
                     assets=assets[:20],
                     hash_db_entries=len(hash_db))


# ---------------------------------------------------------------------------
# Mail security intel (Vanguard scanners.run_mail_intel), DNS only
# ---------------------------------------------------------------------------

DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "s1", "s2", "dkim", "mail")

_MAIL_PROVIDERS = {
    "google": "Google Workspace", "googlemail": "Google Workspace",
    "outlook": "Microsoft 365", "protection.outlook": "Microsoft 365",
    "pphosted": "Proofpoint", "mimecast": "Mimecast",
    "barracuda": "Barracuda", "messagelabs": "Symantec",
    "zoho": "Zoho Mail", "secureserver": "GoDaddy",
    "emailsrvr": "Rackspace", "postmarkapp": "Postmark",
    "mailgun": "Mailgun", "sendgrid": "SendGrid",
    "amazonaws": "Amazon SES", "forcepoint": "Forcepoint",
}


def detect_mail_provider(mx_records: List[str]) -> str:
    for mx in mx_records:
        for pattern, name in _MAIL_PROVIDERS.items():
            if pattern in mx.lower():
                return name
    return "Unknown"


def email_risk_score(records: Dict[str, Any]) -> int:
    """0-100: 0 = fully secured, 100 = no mail security at all (Vanguard scoring)."""
    score = 100
    for key, weight in (("spf", 25), ("dkim", 25), ("dmarc", 25), ("bimi", 5),
                        ("mta_sts", 10), ("dane", 10)):
        if records.get(key):
            score -= weight
    return max(0, score)


def _unquote_txt(value: str) -> str:
    value = value.strip()
    if '"' in value:
        return "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', value))
    return value


def parse_spf(txt_records: List[str]) -> Dict[str, Any]:
    spf = [_unquote_txt(t) for t in txt_records if _unquote_txt(t).lower().startswith("v=spf1")]
    if not spf:
        return {"present": False}
    record = spf[0]
    match = re.search(r"(?:^|\s)([+\-~?]?)all\b", record, re.IGNORECASE)
    qualifier = (match.group(1) or "+") if match else ""
    return {
        "present": True, "record": record[:400], "count": len(spf),
        "all": {"-": "fail", "~": "softfail", "?": "neutral", "+": "pass"}.get(qualifier, "missing"),
        "lookups": len(re.findall(r"\b(include:|a\b|a:|mx\b|mx:|ptr\b|ptr:|exists:|redirect=)",
                                  record, re.IGNORECASE)),
    }


def parse_dmarc(txt_records: List[str]) -> Dict[str, Any]:
    dmarc = [_unquote_txt(t) for t in txt_records if _unquote_txt(t).lower().startswith("v=dmarc1")]
    if not dmarc:
        return {"present": False}
    tags = {}
    for part in dmarc[0].split(";"):
        name, _, value = part.strip().partition("=")
        if name:
            tags[name.strip().lower()] = value.strip()
    return {"present": True, "record": dmarc[0][:400], "count": len(dmarc),
            "policy": tags.get("p", "").lower(), "subdomain_policy": tags.get("sp", "").lower(),
            "pct": tags.get("pct", "100"), "reporting": bool(tags.get("rua") or tags.get("ruf"))}


def mail_weaknesses(records: Dict[str, Any]) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    spf, dmarc = records.get("spf_detail") or {}, records.get("dmarc_detail") or {}
    has_mx = bool(records.get("mx"))
    if not spf.get("present"):
        out.append({"issue": "spf_missing", "detail": "no v=spf1 TXT record"})
    else:
        if spf.get("count", 1) > 1:
            out.append({"issue": "spf_multiple", "detail": "multiple SPF records (permerror)"})
        if spf.get("all") in ("pass", "neutral"):
            out.append({"issue": "spf_permissive_all", "detail": f"SPF ends with {spf.get('all')} all"})
        if spf.get("all") == "missing":
            out.append({"issue": "spf_no_all", "detail": "SPF has no all mechanism"})
        if spf.get("lookups", 0) > 10:
            out.append({"issue": "spf_lookup_limit", "detail": "more than 10 DNS-lookup mechanisms"})
    if not dmarc.get("present"):
        out.append({"issue": "dmarc_missing", "detail": "no _dmarc TXT record"})
    elif dmarc.get("policy") in ("", "none"):
        out.append({"issue": "dmarc_policy_none", "detail": "DMARC p=none does not block spoofing"})
    if has_mx and not records.get("dkim"):
        out.append({"issue": "dkim_not_found",
                    "detail": "no DKIM key at common selectors (selector may be custom; not conclusive)"})
    return out


async def run_mail_intel(domain: str, resolve: Resolve,
                         selectors: Iterable[str] = DKIM_SELECTORS) -> Dict[str, Any]:
    domain = domain.strip().strip(".").lower()

    async def q(name: str, rtype: str) -> List[str]:
        try:
            return [str(r).strip() for r in (await resolve(name, rtype)) if str(r).strip()]
        except Exception as exc:  # NXDOMAIN / NoAnswer / timeout
            logger.debug("mail intel lookup %s %s failed: %s", name, rtype, exc)
            return []

    mx = await q(domain, "MX")
    txt = await q(domain, "TXT")
    dmarc_txt = await q(f"_dmarc.{domain}", "TXT")
    dkim_found = []
    for selector in selectors:
        records = await q(f"{selector}._domainkey.{domain}", "TXT")
        if any("p=" in _unquote_txt(r) or "v=dkim1" in _unquote_txt(r).lower() for r in records):
            dkim_found.append(selector)
    bimi = await q(f"default._bimi.{domain}", "TXT")
    mta_sts = await q(f"_mta-sts.{domain}", "TXT")
    mx_hosts = [re.sub(r"^\d+\s+", "", m).rstrip(".").lower() for m in mx][:3]
    dane_hosts = []
    for host in [domain] + mx_hosts:
        if await q(f"_25._tcp.{host}", "TLSA"):
            dane_hosts.append(host)
    spf_detail, dmarc_detail = parse_spf(txt), parse_dmarc(dmarc_txt)
    records = {
        "mx": mx, "spf": spf_detail.get("present", False), "dmarc": dmarc_detail.get("present", False),
        "dkim": bool(dkim_found), "dkim_selectors": dkim_found,
        "bimi": any("v=bimi1" in _unquote_txt(r).lower() for r in bimi),
        "mta_sts": any("v=stsv1" in _unquote_txt(r).lower() for r in mta_sts),
        "dane": bool(dane_hosts), "dane_hosts": dane_hosts,
        "spf_detail": spf_detail, "dmarc_detail": dmarc_detail,
    }
    weaknesses = mail_weaknesses(records)
    return {
        "tool": "query_mail_security", "domain": domain,
        "provider": detect_mail_provider(mx),
        "risk_score": email_risk_score(records),
        "records": records,
        "weaknesses": weaknesses,
        "verdict": "LEAD" if weaknesses else "NO_SIGNAL",
        "note": ("DNS-only posture intel. A missing/permissive SPF or DMARC is a spoofing "
                 "lead, not a finding: report it only where the program counts mail "
                 "posture, with the records above as evidence."),
    }


# ---------------------------------------------------------------------------
# Third-party vendor intel (Vanguard scanners.VENDOR_PATTERNS / run_third_party_intel)
# ---------------------------------------------------------------------------

VENDOR_PATTERNS: Dict[str, Dict[str, str]] = {
    "google-analytics.com": {"name": "Google Analytics", "category": "analytics"},
    "googletagmanager.com": {"name": "Google Tag Manager", "category": "analytics"},
    "facebook.net": {"name": "Facebook Pixel", "category": "advertising"},
    "connect.facebook.net": {"name": "Facebook SDK", "category": "social"},
    "platform.twitter.com": {"name": "Twitter Widgets", "category": "social"},
    "cdn.linkedin.oribi.io": {"name": "LinkedIn Insight", "category": "analytics"},
    "snap.licdn.com": {"name": "LinkedIn", "category": "social"},
    "js.stripe.com": {"name": "Stripe", "category": "payment"},
    "js.braintreegateway.com": {"name": "Braintree", "category": "payment"},
    "www.paypal.com": {"name": "PayPal", "category": "payment"},
    "cdn.shopify.com": {"name": "Shopify", "category": "ecommerce"},
    "cdn.jsdelivr.net": {"name": "jsDelivr CDN", "category": "cdn"},
    "cdnjs.cloudflare.com": {"name": "Cloudflare CDN", "category": "cdn"},
    "unpkg.com": {"name": "unpkg", "category": "cdn"},
    "maxcdn.bootstrapcdn.com": {"name": "Bootstrap CDN", "category": "cdn"},
    "ajax.googleapis.com": {"name": "Google CDN", "category": "cdn"},
    "fonts.googleapis.com": {"name": "Google Fonts", "category": "fonts"},
    "use.typekit.net": {"name": "Adobe Fonts", "category": "fonts"},
    "sentry.io": {"name": "Sentry", "category": "monitoring"},
    "newrelic.com": {"name": "New Relic", "category": "monitoring"},
    "js.datadoghq.com": {"name": "Datadog RUM", "category": "monitoring"},
    "cdn.segment.com": {"name": "Segment", "category": "analytics"},
    "cdn.amplitude.com": {"name": "Amplitude", "category": "analytics"},
    "cdn.heapanalytics.com": {"name": "Heap", "category": "analytics"},
    "cdn.mxpnl.com": {"name": "Mixpanel", "category": "analytics"},
    "static.hotjar.com": {"name": "Hotjar", "category": "analytics"},
    "widget.intercom.io": {"name": "Intercom", "category": "support"},
    "js.hs-scripts.com": {"name": "HubSpot", "category": "marketing"},
    "static.zdassets.com": {"name": "Zendesk", "category": "support"},
    "embed.tawk.to": {"name": "Tawk.to", "category": "support"},
    "js.driftt.com": {"name": "Drift", "category": "support"},
    "recaptcha.net": {"name": "reCAPTCHA", "category": "security"},
    "challenges.cloudflare.com": {"name": "Cloudflare Turnstile", "category": "security"},
    "hcaptcha.com": {"name": "hCaptcha", "category": "security"},
    "optimize.google.com": {"name": "Google Optimize", "category": "testing"},
    "cdn.optimizely.com": {"name": "Optimizely", "category": "testing"},
    "js.chargebee.com": {"name": "Chargebee", "category": "billing"},
    "js.recurly.com": {"name": "Recurly", "category": "billing"},
    "maps.googleapis.com": {"name": "Google Maps", "category": "maps"},
    "api.mapbox.com": {"name": "Mapbox", "category": "maps"},
    "player.vimeo.com": {"name": "Vimeo", "category": "media"},
    "www.youtube.com": {"name": "YouTube", "category": "media"},
    "fast.wistia.com": {"name": "Wistia", "category": "media"},
    "sc-static.net": {"name": "Snapchat Pixel", "category": "advertising"},
    "analytics.tiktok.com": {"name": "TikTok Pixel", "category": "advertising"},
    "bat.bing.com": {"name": "Bing Ads", "category": "advertising"},
    "ads.linkedin.com": {"name": "LinkedIn Ads", "category": "advertising"},
    "ct.pinterest.com": {"name": "Pinterest Tag", "category": "advertising"},
    "akamaihd.net": {"name": "Akamai", "category": "cdn"},
    "cdn.cookielaw.org": {"name": "OneTrust", "category": "privacy"},
    "app.termly.io": {"name": "Termly", "category": "privacy"},
}

_SCRIPT_TAG = re.compile(r"<script\b([^>]*)>", re.IGNORECASE)
_SRC_ATTR = re.compile(r"""\bsrc\s*=\s*["']([^"']+)["']""", re.IGNORECASE)


def detect_vendors(body: str, csp: str = "") -> Dict[str, Dict[str, str]]:
    searchable = f"{body or ''} {csp or ''}"
    detected: Dict[str, Dict[str, str]] = {}
    for pattern, info in VENDOR_PATTERNS.items():
        if pattern in searchable:
            detected[info["name"]] = {**info, "pattern": pattern,
                                      "source": "csp" if pattern in (csp or "") and pattern not in (body or "") else "body"}
    return detected


def external_scripts(body: str, page_url: str) -> List[Dict[str, Any]]:
    """Third-party ``<script src>`` tags and whether they pin Subresource Integrity."""
    own = (urlsplit(page_url).hostname or "").lower()
    out: List[Dict[str, Any]] = []
    for match in _SCRIPT_TAG.finditer(body or ""):
        attrs = match.group(1)
        src = _SRC_ATTR.search(attrs)
        if not src:
            continue
        url = urljoin(page_url, src.group(1))
        host = (urlsplit(url).hostname or "").lower()
        if not host or host == own:
            continue
        out.append({"host": host, "url": url.split("?", 1)[0][:300],
                    "integrity": bool(re.search(r"\bintegrity\s*=", attrs, re.IGNORECASE))})
    return out


def vendor_report(page_url: str, body: str, headers: Dict[str, Any]) -> Dict[str, Any]:
    lower = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    csp = lower.get("content-security-policy", "")
    vendors = detect_vendors(body, csp)
    scripts = external_scripts(body, page_url)
    known_hosts = set(VENDOR_PATTERNS)
    unclassified = sorted({s["host"] for s in scripts
                           if not any(s["host"] == p or s["host"].endswith("." + p) for p in known_hosts)})
    return {
        "vendors": [{"name": n, "category": v["category"], "source": v["source"]}
                    for n, v in sorted(vendors.items())],
        "vendor_count": len(vendors),
        "external_scripts": len(scripts),
        "external_scripts_without_sri": sorted({s["host"] for s in scripts if not s["integrity"]})[:40],
        "unclassified_script_hosts": unclassified[:40],
    }


async def run_third_party_intel(page_url: str, send: Send) -> Dict[str, Any]:
    resp = await send("GET", page_url, {}, "")
    if _status(resp) is None:
        return summarize("detect_third_party_vendors", page_url, [], [resp],
                         inconclusive=f"fetch failed: {resp.get('error') or resp.get('skipped')}")
    report = vendor_report(page_url, _body(resp), resp.get("headers") or {})
    return {
        "tool": "detect_third_party_vendors", "target": page_url, "verdict": "INTEL",
        "http_status": _status(resp), "evidence_ids": _evidence(resp), **report,
        "note": ("Inventory for supply-chain and data-flow review, not a finding. Third-party "
                 "scripts without SRI are a hardening lead; a vendor host that is unclaimed "
                 "or takeover-able is the impactful case."),
    }
