"""Security-header and CORS scoring from ProjectDiscovery httpx JSON lines.

Input is ``httpx -json -include-response-header`` (``-irh``) output. Ported
from Vanguard ``run_security_headers``. Fixes: httpx emits header keys as
``x_frame_options`` (underscores), so Vanguard's lookups for
``x-frame-options`` never matched and every header read as missing; keys are
normalized. HSTS is only expected on HTTPS. ``frame-ancestors`` in CSP counts
for X-Frame-Options. A score and A-F grade are added. Only the security
headers themselves are kept: cookies and other response headers are dropped.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from asm_scanner_core.parsers.base import Observation, ParsedResult, iter_json_lines, run_status, strip_ansi

TOOL = "httpx"

# Header -> weight in the 100-point score.
REQUIRED_HEADERS: Dict[str, int] = {
    "strict-transport-security": 25,
    "content-security-policy": 25,
    "x-frame-options": 15,
    "x-content-type-options": 15,
    "referrer-policy": 10,
    "permissions-policy": 10,
}
_CORS = ("access-control-allow-origin", "access-control-allow-credentials")


def _norm_headers(data: Dict[str, Any]) -> Dict[str, str]:
    raw = data.get("header") or data.get("headers") or data.get("response_header") or {}
    out: Dict[str, str] = {}
    if isinstance(raw, dict):
        for key, value in raw.items():
            if isinstance(value, list):
                value = ", ".join(str(v) for v in value)
            out[str(key).strip().lower().replace("_", "-")] = str(value)
    raw_text = data.get("raw_header") or ""
    if isinstance(raw_text, str):
        for line in raw_text.splitlines()[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                out.setdefault(key.strip().lower(), value.strip())
    return out


def grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def score_headers(headers: Dict[str, str], *, https: bool) -> Dict[str, Any]:
    present: Dict[str, str] = {}
    missing: List[str] = []
    possible = 0
    earned = 0
    csp = headers.get("content-security-policy", "")
    for name, weight in REQUIRED_HEADERS.items():
        if name == "strict-transport-security" and not https:
            continue
        possible += weight
        value = headers.get(name, "").strip()
        if not value and name == "x-frame-options" and "frame-ancestors" in csp.lower():
            value = "(csp frame-ancestors)"
        if value:
            present[name] = value
            earned += weight
        else:
            missing.append(name)
    score = round(100 * earned / possible) if possible else 0
    return {"score": score, "grade": grade(score), "present": present, "missing": missing}


def cors_policy(headers: Dict[str, str]) -> Dict[str, Any]:
    acao = headers.get("access-control-allow-origin", "").strip()
    if not acao:
        return {}
    credentials = "true" in headers.get("access-control-allow-credentials", "").lower()
    wildcard = acao == "*"
    null_origin = acao.lower() == "null"
    policy = {"allow_origin": acao, "wildcard": wildcard, "allow_credentials": credentials,
              "null_origin": null_origin}
    if null_origin and credentials:
        policy["risk"], policy["severity"] = "null origin trusted with credentials", "medium"
    elif wildcard and credentials:
        # Browsers refuse credentialed "*" responses; still a misconfiguration.
        policy["risk"], policy["severity"] = "wildcard origin with credentials", "medium"
    elif credentials:
        policy["risk"], policy["severity"] = ("specific origin with credentials; check whether it is "
                                              "reflected from the request Origin"), "low"
    elif wildcard or null_origin:
        policy["risk"], policy["severity"] = "any origin may read unauthenticated responses", "info"
    return policy


def parse_httpx(output: str, exit_code: Optional[int] = None, *, timed_out: bool = False,
                **_context: Any) -> ParsedResult:
    observations: List[Observation] = []
    hosts = 0
    with_headers = 0
    for data in iter_json_lines(strip_ansi(output or "")):
        url = str(data.get("url") or data.get("input") or "")
        if not url:
            continue
        hosts += 1
        headers = _norm_headers(data)
        if not headers:
            continue
        with_headers += 1
        https = url.lower().startswith("https://") or str(data.get("scheme") or "").lower() == "https"
        scored = score_headers(headers, https=https)
        observations.append(Observation(
            kind="security_headers",
            title=f"Security headers {scored['grade']} ({scored['score']}/100)"
                  + (f", missing {len(scored['missing'])}" if scored["missing"] else ""),
            severity="low" if scored["missing"] else "info", target=url,
            attributes={"score": scored["score"], "grade": scored["grade"], "missing": scored["missing"],
                        "present": sorted(scored["present"]), "status_code": data.get("status_code")},
        ))
        cors = cors_policy(headers)
        if cors:
            observations.append(Observation(
                kind="cors", title=f"CORS allow-origin {cors['allow_origin']}"
                + (f": {cors['risk']}" if cors.get("risk") else ""),
                severity=cors.get("severity", "info"), target=url,
                attributes={k: v for k, v in cors.items() if k not in ("severity",)},
            ))
    status, reason = run_status(exit_code=exit_code, timed_out=timed_out, have_data=bool(hosts))
    if status == "ok" and hosts and not with_headers:
        reason = "no response headers in output (run with -include-response-header)"
    return ParsedResult(tool=TOOL, status=status, observations=observations,
                        counts={"hosts": hosts, "hosts_with_headers": with_headers,
                                "cors_policies": sum(1 for o in observations if o.kind == "cors")},
                        reason=reason)
