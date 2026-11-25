"""Native verifiers for finding kinds that used to need the LLM validator.

The scanner worker's VALIDATE_FINDING job runs ``finding_revalidation_service``
first. That module replays nuclei templates and probes endpoints; the
functions here cover what was left:

* ``verify_network_service`` - does the claimed service/protocol actually
  answer on host:port (nmap service detection), not just "TCP open"?
* ``verify_secret`` - is the same secret (by fingerprint) still exposed at the
  location it was found? The secret is never used or sent anywhere.
* ``verify_manual`` - replay the HTTP requests written in a manual finding's
  steps and look for the documented indicator in the response.
* ``diagnose_template_logic`` - ask the LLM whether a false positive comes
  from the detection template's own logic (weak matcher, wrong protocol).

Each verifier returns the verdict dict used by ``handle_validate_finding``
(``verdict``, ``confidence``, ``is_false_positive``, ``still_open``,
``recommended_severity``, ``reasoning``, ``evidence``,
``template_logic_issue``, ``method``) plus:

* ``remediation_state`` - ``open`` (reproduces), ``remediated`` (was real,
  now gone), ``never_real`` (the claim never held) or ``unknown``.
* ``native_verifier`` - set when a verifier fully handled the finding; the
  worker's ``auto`` mode then does not escalate to the LLM validator.

Network, HTTP and LLM access are injectable so every verifier is testable
without a network.
"""

from __future__ import annotations

import asyncio
import json
import hashlib
import ipaddress
import logging
import os
import re
import shlex
import subprocess
import xml.etree.ElementTree as ET
from typing import Any, Awaitable, Callable, Optional
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

REMEDIATION_STATES = ("open", "remediated", "never_real", "unknown")

# (method, url, headers, body, timeout) -> {"status", "body", "headers", "error"}
HttpCall = Callable[[str, str, dict, Optional[str], float], dict]
# (host, port, protocol) -> {"name", "product", "version", "extrainfo", "tunnel", "error"}
ServiceProbe = Callable[[str, int, str], dict]
# (system_prompt, user_prompt) -> raw text
LlmCall = Callable[[str, str], Awaitable[str]]

_MAX_BODY = 2 * 1024 * 1024


def _was_real(finding: dict) -> bool:
    """Evidence the finding held at some point: a prior confirmation or a
    detector that verified it when filing."""
    prior = str(finding.get("last_validation_verdict") or "").lower()
    conf = str(finding.get("detection_confidence") or "").lower()
    return prior == "confirmed" or conf == "exploit_confirmed"


def finalize_verdict(verdict: dict, finding: dict) -> dict:
    """Fill ``remediation_state`` and keep the derived booleans consistent."""
    v = str(verdict.get("verdict") or "needs_more_evidence")
    state = verdict.get("remediation_state")
    if state not in REMEDIATION_STATES:
        if v == "confirmed":
            state = "open"
        elif verdict.get("logical_mismatch"):
            state = "never_real"
        elif v == "false_positive" and _was_real(finding):
            state = "remediated"
        else:
            state = "unknown"
    verdict["remediation_state"] = state
    if state == "open":
        verdict["still_open"] = True
    elif state in ("remediated", "never_real"):
        verdict["still_open"] = False
    # A remediated issue was real: it is closed, not a false positive.
    verdict["is_false_positive"] = v == "false_positive" and state != "remediated"
    verdict.setdefault("confidence", "low")
    if not verdict.get("recommended_severity"):
        verdict["recommended_severity"] = (
            finding.get("severity") or "info" if state == "open" else "info"
        )
    return verdict


def _base(finding: dict, **kw) -> dict:
    out = {
        "verdict": "needs_more_evidence",
        "confidence": "low",
        "is_false_positive": False,
        "still_open": None,
        "logical_mismatch": False,
        "recommended_severity": finding.get("severity") or "info",
        "reasoning": "",
        "evidence": "",
        "template_logic_issue": None,
    }
    out.update(kw)
    return out


# ── HTTP transport ─────────────────────────────────────────────────────────────

def default_http_call(method: str, url: str, headers: dict, body: Optional[str],
                      timeout: float = 10.0) -> dict:
    """Bounded single request. Redirects are not followed."""
    try:
        import httpx
        with httpx.Client(verify=False, follow_redirects=False, timeout=timeout) as client:
            with client.stream(method, url, headers=headers or None,
                               content=body.encode() if body else None) as resp:
                buf = bytearray()
                for chunk in resp.iter_bytes():
                    buf.extend(chunk)
                    if len(buf) >= _MAX_BODY:
                        del buf[_MAX_BODY:]
                        break
                return {
                    "status": resp.status_code,
                    "headers": dict(resp.headers),
                    "body": bytes(buf).decode("utf-8", errors="replace"),
                    "error": None,
                }
    except Exception as exc:  # network errors are data here
        return {"status": None, "headers": {}, "body": "", "error": f"{type(exc).__name__}: {exc}"[:200]}


# ── Network service ────────────────────────────────────────────────────────────

# Claimed service -> nmap service names that count as "it answers".
_NMAP_NAMES: dict[str, set[str]] = {
    "postgres": {"postgresql"}, "postgresql": {"postgresql"},
    "mssql": {"ms-sql-s", "ms-sql", "mssql"},
    "smb": {"microsoft-ds", "netbios-ssn", "smb"},
    "rdp": {"ms-wbt-server", "rdp"},
    "mongodb": {"mongodb", "mongod"},
    "ldap": {"ldap", "ldapssl"}, "ldaps": {"ldapssl", "ldap"},
    "smtp": {"smtp", "smtps", "submission"}, "smtps": {"smtps", "smtp"},
    "imap": {"imap", "imaps"}, "imaps": {"imaps", "imap"},
    "pop3": {"pop3", "pop3s"}, "pop3s": {"pop3s", "pop3"},
    "ftp": {"ftp", "ftps"}, "ftps": {"ftps", "ftp"},
    "mysql": {"mysql"}, "mariadb": {"mysql", "mariadb"},
    "dns": {"domain", "dns"},
    "nfs": {"nfs", "rpcbind"},
    "vnc": {"vnc"}, "mqtt": {"mqtt"}, "amqp": {"amqp"},
    "cassandra": {"cassandra"}, "zookeeper": {"zookeeper"}, "kafka": {"kafka"},
    "snmp": {"snmp"}, "sip": {"sip"}, "ssh": {"ssh"}, "telnet": {"telnet"},
    "redis": {"redis"}, "memcached": {"memcached", "memcache"},
}
_UNIDENTIFIED = {"", "unknown", "tcpwrapped"}


def default_service_probe(host: str, port: int, protocol: str = "tcp") -> dict:
    """nmap -sV on one port: the same service detection the port scanner uses."""
    cmd = ["nmap", "-Pn", "-sV", "--version-light", "-sT" if protocol == "tcp" else "-sU",
           "-p", str(port), "-oX", "-", "--", host]
    try:
        if isinstance(ipaddress.ip_address(host), ipaddress.IPv6Address):
            cmd.insert(1, "-6")
    except ValueError:
        pass
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        if result.returncode != 0:
            return {"error": (result.stderr or "nmap_failed")[:200]}
        root = ET.fromstring(result.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired, ET.ParseError, OSError) as exc:
        return {"error": type(exc).__name__}
    for p in root.findall("./host/ports/port"):
        if p.get("portid") != str(port):
            continue
        svc = p.find("service")
        if svc is None:
            return {"name": ""}
        return {k: svc.get(k) or "" for k in ("name", "product", "version", "extrainfo", "tunnel")}
    return {"name": ""}


def claimed_services(finding: dict) -> list[str]:
    from asm_scanner_core.finding_sanity import infer_claimed_services
    claimed = infer_claimed_services(finding)
    meta = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
    service = str(meta.get("service") or meta.get("service_name") or "").lower()
    if service in _NMAP_NAMES and service not in claimed:
        claimed.append(service)
    return [s for s in claimed if s in _NMAP_NAMES or s in ("elasticsearch", "kibana", "couchdb")]


def service_answers(claimed: str, observed: dict) -> bool:
    name = str(observed.get("name") or "").lower()
    blob = " ".join(str(observed.get(k) or "") for k in ("name", "product", "extrainfo")).lower()
    if name in _NMAP_NAMES.get(claimed, set()):
        return True
    # HTTP-fronted services (Elasticsearch, Kibana, CouchDB) and products named
    # after the protocol ("OpenSSH", "MySQL") show up in product/extrainfo.
    return bool(re.search(rf"(?<![a-z]){re.escape(claimed)}", blob)) or (
        claimed in ("postgres", "postgresql") and "postgres" in blob
    )


def verify_network_service(
    finding: dict,
    port_verdict: dict,
    *,
    service_probe: Optional[ServiceProbe] = None,
) -> dict:
    """Refine an nmap port-state verdict with service detection.

    Closed/filtered: not open; ``remediated`` when the port was observed open
    by the port scanner (or previously confirmed), else ``unknown``.
    Open + a different service positively identified: the claimed protocol
    does not answer there - false positive, ``never_real``.
    Open + the claimed service answers: exposure confirmed for port-scanner
    findings; a service *vulnerability* claim (anonymous access, ...) stays
    needs_more_evidence because a handshake does not prove it.
    """
    verdict = dict(port_verdict)
    state = verdict.get("port_state")
    detected_by = (finding.get("detected_by") or "").lower()
    if state in ("closed", "filtered"):
        real = detected_by == "port_scanner" or _was_real(finding)
        verdict["remediation_state"] = "remediated" if real else "unknown"
        verdict["native_verifier"] = "network_service"
        return verdict
    if state != "open":
        return verdict  # nmap unavailable / undetermined: not handled

    verdict["native_verifier"] = "network_service"
    claimed = claimed_services(finding)
    if not claimed:
        return verdict
    probe = service_probe or default_service_probe
    host, port = verdict.get("port_host"), verdict.get("port")
    try:
        observed = probe(str(host), int(port), str(verdict.get("protocol") or "tcp")) or {}
    except Exception as exc:
        observed = {"error": f"{type(exc).__name__}: {exc}"[:200]}
    verdict["observed_service"] = {k: v for k, v in observed.items() if v}
    name = str(observed.get("name") or "").lower()
    endpoint = f"{host}:{port}"
    if observed.get("error") or name in _UNIDENTIFIED:
        verdict["evidence"] = f"{verdict.get('evidence', '')}; service=unidentified".strip("; ")
        return verdict  # keep the state-based verdict
    label = " ".join(filter(None, [observed.get("name"), observed.get("product"),
                                   observed.get("version")]))
    if any(service_answers(c, observed) for c in claimed):
        verdict["evidence"] = f"{verdict.get('evidence', '')}; service={label}".strip("; ")
        verdict["reasoning"] = (
            f"{verdict.get('reasoning', '')} Service detection shows {label} answering on "
            f"{endpoint}, matching the claimed {', '.join(claimed)}."
        ).strip()
        if verdict.get("verdict") == "confirmed":
            verdict["remediation_state"] = "open"
        return verdict

    verdict.update(
        verdict="false_positive",
        confidence="high",
        still_open=False,
        logical_mismatch=True,
        recommended_severity="info",
        remediation_state="never_real",
        reasoning=(
            f"{endpoint} is open but answers as {label}, not the claimed "
            f"{', '.join(claimed)}. The claimed protocol does not run on this port."
        ),
        evidence=f"{verdict.get('evidence', '')}; service={label}; claimed={claimed}".strip("; "),
    )
    if finding.get("template_id"):
        verdict["template_logic_issue"] = (
            f"Template {finding.get('template_id')} reported {', '.join(claimed)} on port "
            f"{port}, but the port speaks {observed.get('name')}. The matcher does not "
            "verify the protocol handshake."
        )
    return verdict


# ── Leaked secret ──────────────────────────────────────────────────────────────

_FP_RE = re.compile(r"^(?:sha256:)?([0-9a-f]{16})$")
_LOCATION_KEYS = ("source_url", "source", "url", "location", "file_url", "request_url",
                  "matched_at", "endpoint")
_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-+/=.:~]{8,}")
_QUOTED_RE = re.compile(r"""(["'`])((?:\\.|(?!\1).){4,4096}?)\1""")


def _secret_record(finding: dict) -> dict:
    meta = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
    ev: dict = {}
    raw_ev = finding.get("evidence")
    if isinstance(raw_ev, dict):
        ev = raw_ev
    elif isinstance(raw_ev, str) and raw_ev.strip().startswith("{"):
        try:
            ev = json.loads(raw_ev)
        except ValueError:
            ev = {}
    merged: dict = {}
    for src in (ev.get("scanner_evidence") if isinstance(ev.get("scanner_evidence"), dict) else {},
                ev, meta):
        for k, v in (src or {}).items():
            if v not in (None, ""):
                merged[k] = v
    return merged


def _normalize_fp(value: Any) -> Optional[str]:
    m = _FP_RE.match(str(value or "").strip().lower())
    return f"sha256:{m.group(1)}" if m else None


def _fp(raw: str) -> str:
    return "sha256:" + hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:16]


def fingerprint_present(body: str, fingerprint: str, length: Optional[int] = None) -> bool:
    """Is a value with this fingerprint in ``body``? Hashes candidates only;
    the secret itself is never reconstructed or stored."""
    candidates: set[str] = set()
    for m in _QUOTED_RE.finditer(body):
        candidates.add(m.group(2))
    for tok in _TOKEN_RE.findall(body):
        candidates.add(tok)
        for part in re.split(r"[=:]", tok):
            if len(part) >= 8:
                candidates.add(part)
    if length:
        candidates = {c for c in candidates if len(c) == length} or candidates
    if any(_fp(c) == fingerprint for c in candidates):
        return True
    # Exact-length sliding window catches values embedded in larger tokens.
    if length and 4 <= length <= 512 and len(body) <= 1_000_000:
        target = fingerprint
        for i in range(0, len(body) - length + 1):
            if _fp(body[i:i + length]) == target:
                return True
    return False


def verify_secret(finding: dict, *, http_call: Optional[HttpCall] = None) -> dict:
    """Re-observe a leaked secret at its exposing location by fingerprint.

    Never authenticates with, tests, or transmits the secret. Present ->
    confirmed exposure (still open). Location fetched and fingerprint gone ->
    remediated. Location or fingerprint unusable -> needs_more_evidence.
    """
    rec = _secret_record(finding)
    location = next(
        (str(rec[k]) for k in _LOCATION_KEYS
         if isinstance(rec.get(k), str) and rec[k].startswith(("http://", "https://"))),
        None,
    )
    if not location:
        t = str(finding.get("target") or "")
        if t.startswith(("http://", "https://")):
            location = t
    fingerprint = _normalize_fp(rec.get("fingerprint")) or _normalize_fp(rec.get("raw_hash"))
    try:
        length = int(rec.get("length")) if rec.get("length") is not None else None
    except (TypeError, ValueError):
        length = None
    common = {"method": "secret_fingerprint_recheck", "native_verifier": "secret",
              "secret_location": location, "secret_fingerprint": fingerprint}

    if not location:
        return _base(finding, **common, remediation_state="unknown", reasoning=(
            "Leaked-secret finding with no re-fetchable HTTP(S) location (e.g. git "
            "history or a private source). The secret is never used to test a "
            "provider, so exposure cannot be re-observed natively."),
            evidence="no_secret_location")
    if not fingerprint:
        return _base(finding, **common, remediation_state="unknown", reasoning=(
            "The exposing location is known but the finding stores no comparable "
            "secret fingerprint, so a re-fetch cannot tell whether the same secret is "
            "still there."), evidence=f"location={location}; fingerprint=unavailable")

    resp = (http_call or default_http_call)("GET", location, {"User-Agent": "asm-finding-revalidator/1.0"},
                                            None, 15.0)
    status, body, error = resp.get("status"), resp.get("body") or "", resp.get("error")
    ev = f"GET {location} -> {status if status is not None else error}; fingerprint={fingerprint}"
    if error or status is None or status >= 500:
        return _base(finding, **common, remediation_state="unknown", reasoning=(
            f"Could not re-fetch {location} ({error or status}); exposure state unknown."),
            evidence=ev)
    if status == 200 and fingerprint_present(body, fingerprint, length):
        return _base(finding, **common, verdict="confirmed", confidence="high", still_open=True,
                     remediation_state="open",
                     recommended_severity=finding.get("severity") or "high",
                     reasoning=(f"The same secret (fingerprint {fingerprint}) is still served at "
                                f"{location}. Treat it as exposed and rotate it."),
                     evidence=ev + "; present=true")
    if status in (200, 404, 410):
        return _base(finding, **common, verdict="false_positive", confidence="medium" if status == 200 else "high",
                     still_open=False, remediation_state="remediated", recommended_severity="info",
                     reasoning=(f"{location} no longer serves the secret with fingerprint "
                                f"{fingerprint} (HTTP {status}). The exposure was removed; rotate "
                                "the credential if that has not been done."),
                     evidence=ev + "; present=false")
    return _base(finding, **common, remediation_state="unknown", reasoning=(
        f"{location} answered HTTP {status}; cannot tell whether the secret is still exposed."),
        evidence=ev)


# ── Manual finding replay ──────────────────────────────────────────────────────

_REPLAY_METHODS = {"GET", "HEAD", "OPTIONS", "POST"}  # never PUT/PATCH/DELETE
_RAW_REQ_RE = re.compile(r"^(GET|POST|HEAD|OPTIONS|PUT|PATCH|DELETE)\s+(\S+)\s+HTTP/[\d.]+\s*$",
                         re.MULTILINE)
_INDICATOR_RE = re.compile(
    r"(?im)^\s*(?:[-*•>]\s*|\d+[.)]\s*)?(?:expected(?:\s+(?:result|response|output))?|"
    r"(?:the\s+)?response\s+(?:contains|includes|shows|returns)|observe[sd]?|look\s+for)"
    r"\s*[:\-]?\s*(.+)$")
_QUOTED_IND_RE = re.compile(r"[\"'`]([^\"'`]{3,200})[\"'`]")


def _parse_curl(cmd: str) -> Optional[dict]:
    try:
        argv = shlex.split(cmd.replace("\\\n", " "))
    except ValueError:
        return None
    if not argv or argv[0] != "curl":
        return None
    method, url, headers, body = None, None, {}, None
    i = 1
    while i < len(argv):
        a = argv[i]
        nxt = argv[i + 1] if i + 1 < len(argv) else None
        if a in ("-X", "--request") and nxt:
            method, i = nxt.upper(), i + 2
            continue
        if a in ("-H", "--header") and nxt:
            if ":" in nxt:
                k, v = nxt.split(":", 1)
                headers[k.strip()] = v.strip()
            i += 2
            continue
        if a in ("-d", "--data", "--data-raw", "--data-binary", "--data-urlencode") and nxt:
            body, i = nxt, i + 2
            continue
        if a in ("-b", "--cookie") and nxt:
            headers["Cookie"], i = nxt, i + 2
            continue
        if a in ("-A", "--user-agent") and nxt:
            headers["User-Agent"], i = nxt, i + 2
            continue
        if a in ("-u", "--user", "-o", "--output", "-e", "--referer", "-x", "--proxy",
                 "--max-time", "-m", "--connect-timeout", "-w", "--write-out") and nxt:
            i += 2
            continue
        if a.startswith(("http://", "https://")):
            url = a
        elif a == "--url" and nxt:
            url, i = nxt, i + 2
            continue
        i += 1
    if not url:
        return None
    return {"method": method or ("POST" if body is not None else "GET"), "url": url,
            "headers": headers, "body": body, "source": "curl"}


def _curl_commands(text: str) -> list[str]:
    text = text.replace("\\\r\n", " ").replace("\\\n", " ")
    out = []
    for line in text.splitlines():
        idx = line.find("curl ")
        if idx >= 0 and (idx == 0 or not line[idx - 1].isalnum()):
            out.append(line[idx:].strip().strip("`"))
    return out


def _raw_requests(text: str, default_base: Optional[str]) -> list[dict]:
    reqs = []
    for m in _RAW_REQ_RE.finditer(text):
        method, path = m.group(1).upper(), m.group(2)
        rest = text[m.end():].lstrip("\r\n")
        head, _, tail = rest.partition("\n\n")
        headers = {}
        for line in head.splitlines():
            if not line.strip() or line.strip().startswith("```"):
                break
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
        body_text = tail.split("```", 1)[0].split("\n\n", 1)[0].strip() if method == "POST" else ""
        host = next((v for k, v in headers.items() if k.lower() == "host"), None)
        if path.startswith(("http://", "https://")):
            url = path
        elif host:
            scheme = urlparse(default_base or "").scheme or "https"
            url = f"{scheme}://{host}{path}"
        elif default_base:
            url = urljoin(default_base, path)
        else:
            continue
        headers = {k: v for k, v in headers.items()
                   if k.lower() not in ("host", "content-length", "connection")}
        reqs.append({"method": method, "url": url, "headers": headers,
                     "body": body_text or None, "source": "raw_http"})
    return reqs


def extract_replay_requests(finding: dict) -> list[dict]:
    """HTTP requests an analyst wrote down (curl lines or raw HTTP blocks)."""
    target = str(finding.get("target") or "")
    base = target if target.startswith(("http://", "https://")) else None
    reqs: list[dict] = []
    for field in ("steps_to_reproduce", "proof_of_concept"):
        text = str(finding.get(field) or "")
        if not text:
            continue
        for cmd in _curl_commands(text):
            r = _parse_curl(cmd)
            if r:
                reqs.append(r)
        reqs.extend(_raw_requests(text, base))
    seen, unique = set(), []
    for r in reqs:
        key = (r["method"], r["url"], r.get("body"))
        if key not in seen:
            seen.add(key)
            unique.append(r)
    return unique[:10]


def extract_indicators(finding: dict) -> list[str]:
    """Strings the analyst says prove the issue in the response."""
    out: list[str] = []
    for field in ("steps_to_reproduce", "proof_of_concept", "evidence"):
        text = str(finding.get(field) or "")
        for m in _INDICATOR_RE.finditer(text):
            line = m.group(1).strip()
            quoted = _QUOTED_IND_RE.findall(line)
            if quoted:
                out.extend(q.strip() for q in quoted)
            elif 3 <= len(line) <= 120 and not re.fullmatch(r"(?:HTTP\s*)?\d{3}\b.*", line, re.I):
                out.append(line.rstrip(".").strip())
    seen, unique = set(), []
    for s in out:
        if s and s.lower() not in seen:
            seen.add(s.lower())
            unique.append(s)
    return unique[:10]


def _allowed_hosts(finding: dict) -> set[str]:
    hosts = set()
    for v in (finding.get("target"), finding.get("asset"), finding.get("affected_component")):
        s = str(v or "").strip()
        if not s:
            continue
        h = urlparse(s if "://" in s else f"//{s}").hostname
        if h:
            hosts.add(h.lower())
    return hosts


def verify_manual(finding: dict, *, http_call: Optional[HttpCall] = None) -> Optional[dict]:
    """Replay the analyst's documented requests and look for the documented result.

    Only GET/HEAD/OPTIONS/POST to the finding's own host are replayed. Returns
    None when there is nothing machine-replayable, so the caller falls back to
    endpoint probing.
    """
    requests_ = extract_replay_requests(finding)
    if not requests_:
        return None
    allowed = _allowed_hosts(finding)
    indicators = extract_indicators(finding)
    call = http_call or default_http_call
    replayed, skipped = [], []
    for r in requests_:
        host = (urlparse(r["url"]).hostname or "").lower()
        if r["method"] not in _REPLAY_METHODS:
            skipped.append(f"{r['method']} {r['url']} (state-changing method)")
            continue
        if allowed and host not in allowed:
            skipped.append(f"{r['method']} {r['url']} (outside the finding's host)")
            continue
        resp = call(r["method"], r["url"], r.get("headers") or {}, r.get("body"), 15.0)
        body = str(resp.get("body") or "")
        hits = [ind for ind in indicators if ind.lower() in body.lower()]
        replayed.append({"method": r["method"], "url": r["url"], "status": resp.get("status"),
                         "error": resp.get("error"), "indicator_hits": hits})
    common = {"method": "manual_request_replay", "replayed": replayed, "skipped": skipped,
              "indicators": indicators}
    if not replayed:
        return _base(finding, **common, reasoning=(
            "The documented requests were not replayed (state-changing or out-of-scope): "
            + "; ".join(skipped[:5])), evidence="no_safe_requests")
    summary = "; ".join(f"{r['method']} {r['url']} -> {r['status'] or r['error']}"
                        for r in replayed[:5])
    answered = [r for r in replayed if r["status"] is not None]
    if any(r["indicator_hits"] for r in replayed):
        hits = sorted({h for r in replayed for h in r["indicator_hits"]})
        return _base(finding, **common, verdict="confirmed", confidence="high", still_open=True,
                     remediation_state="open", native_verifier="manual",
                     recommended_severity=finding.get("severity") or "medium",
                     reasoning=(f"Replayed the documented request(s); the response still shows "
                                f"the documented result ({', '.join(hits[:3])})."),
                     evidence=summary)
    if not answered:
        return _base(finding, **common, verdict="false_positive", confidence="medium",
                     still_open=False, remediation_state="remediated", native_verifier="manual",
                     recommended_severity="info",
                     reasoning=("None of the documented requests get a response any more "
                                "(endpoint gone or host unreachable)."), evidence=summary)
    if indicators:
        # Analyst-filed findings were observed when written: no longer showing
        # the documented result means it was fixed, not that it never held.
        return _base(finding, **common, verdict="false_positive", confidence="medium",
                     still_open=False, remediation_state="remediated", native_verifier="manual",
                     recommended_severity="info",
                     reasoning=("Replayed the documented request(s); the documented result "
                                f"({', '.join(indicators[:3])}) no longer appears."),
                     evidence=summary)
    return _base(finding, **common, reasoning=(
        "Replayed the documented request(s) but the finding states no observable "
        "result to compare against."), evidence=summary)


# ── Template-logic diagnosis (LLM) ─────────────────────────────────────────────

TEMPLATE_DIAGNOSIS_SYSTEM_PROMPT = """You review a security detection template that produced a finding a
re-test could not confirm. Decide whether the template's OWN logic explains the
false positive: a weak matcher (banner, version string, generic login page,
status code only), the wrong protocol or port, or a matcher any similar response
would satisfy. Do not judge the target; judge the detection logic.

Answer with ONE JSON object and nothing else:
{"template_logic_issue": "<the flaw, one or two sentences>" or null,
 "cause": "template_logic" | "target_changed" | "unknown",
 "confidence": "high" | "medium" | "low",
 "reasoning": "<one sentence>"}
Use "template_logic" only when the YAML itself shows the flaw. Use
"target_changed" when the template is sound and the target likely changed."""

_MAX_YAML = 6000
_MAX_EVIDENCE = 2000


def build_template_diagnosis_prompt(finding: dict, verdict: dict) -> str:
    recheck = verdict.get("nuclei_recheck")
    view = {
        "title": finding.get("title"),
        "template_id": finding.get("template_id"),
        "target": finding.get("target"),
        "severity": finding.get("severity"),
        "matcher_name": finding.get("matcher_name"),
        "port": (finding.get("metadata") or {}).get("port") if isinstance(finding.get("metadata"), dict) else None,
    }
    view = {k: v for k, v in view.items() if v not in (None, "")}
    return (
        "## Finding\n" + json.dumps(view, default=str)[:1000] + "\n\n"
        "## Template YAML\n```yaml\n" + str(finding.get("template_yaml") or "").strip()[:_MAX_YAML] + "\n```\n\n"
        "## Original evidence\n" + str(finding.get("evidence") or "")[:_MAX_EVIDENCE] + "\n\n"
        "## Native re-check\n"
        + json.dumps({"verdict": verdict.get("verdict"), "method": verdict.get("method"),
                      "reasoning": verdict.get("reasoning"), "nuclei_recheck": recheck},
                     default=str)[:1500]
    )


def parse_diagnosis(raw: str) -> Optional[dict]:
    text = (raw or "").strip()
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL) or re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        return None
    try:
        data = json.loads(m.group(1) if m.re.groups else m.group(0))
    except (ValueError, IndexError):
        return None
    if not isinstance(data, dict):
        return None
    issue = data.get("template_logic_issue")
    cause = str(data.get("cause") or "unknown").lower()
    if cause not in ("template_logic", "target_changed", "unknown"):
        cause = "unknown"
    conf = str(data.get("confidence") or "low").lower()
    return {
        "template_logic_issue": str(issue).strip()[:1000] if issue and cause == "template_logic" else None,
        "cause": cause,
        "confidence": conf if conf in ("high", "medium", "low") else "low",
        "reasoning": str(data.get("reasoning") or "")[:500],
    }


def _llm_configured() -> bool:
    if os.getenv("AEGIS_VALIDATOR_TEMPLATE_DIAGNOSIS", "true").lower() in ("0", "false", "no"):
        return False
    try:
        from app.core.config import settings
    except Exception:
        return False
    return bool(getattr(settings, "ANTHROPIC_API_KEY", None) or getattr(settings, "OPENAI_API_KEY", None))


async def _default_llm_call(system_prompt: str, user_prompt: str) -> str:
    from app.services.custom_template_ai import call_llm
    return await call_llm(system_prompt, user_prompt, max_tokens=600)


async def diagnose_template_logic(
    finding: dict,
    verdict: dict,
    *,
    llm_call: Optional[LlmCall] = None,
    timeout_sec: float = 60.0,
) -> Optional[dict]:
    """LLM diagnosis of whether a non-confirmed template finding is the
    template's fault. Returns None when it does not apply or on any error."""
    if not finding.get("template_yaml"):
        return None
    if verdict.get("verdict") not in ("false_positive", "needs_more_evidence"):
        return None
    if verdict.get("template_logic_issue") or verdict.get("remediation_state") == "remediated":
        return None
    if llm_call is None:
        if not _llm_configured():
            return None
        llm_call = _default_llm_call
    try:
        raw = await asyncio.wait_for(
            llm_call(TEMPLATE_DIAGNOSIS_SYSTEM_PROMPT, build_template_diagnosis_prompt(finding, verdict)),
            timeout=timeout_sec,
        )
        return parse_diagnosis(raw if isinstance(raw, str) else str(raw))
    except Exception as exc:
        logger.info("Template diagnosis skipped: %s", type(exc).__name__)
        return None


def apply_diagnosis(verdict: dict, diagnosis: Optional[dict]) -> dict:
    if not diagnosis:
        return verdict
    verdict["template_diagnosis"] = diagnosis
    issue = diagnosis.get("template_logic_issue")
    if not issue:
        return verdict
    verdict["template_logic_issue"] = issue
    if verdict.get("verdict") == "false_positive":
        verdict["remediation_state"] = "never_real"
        verdict["is_false_positive"] = True
        verdict["still_open"] = False
    return verdict
