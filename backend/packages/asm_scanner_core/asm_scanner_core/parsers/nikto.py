"""nikto (JSON ``-Format json`` or plain text) parser.

Ported from Vanguard ``run_nikto``. Fixes: every item was ``medium`` (JSON) or
``info`` (text); severity is now mapped per item from its message. Text output
no longer counts the scan header (Target IP, Start Time, ...) as findings.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from asm_scanner_core.parsers.base import (
    Observation, ParsedResult, extract_json, run_status, strip_ansi,
)

TOOL = "nikto"

_RULES = (
    ("high", re.compile(
        r"remote (?:code|command)|command (?:execution|injection)|code execution|sql injection|"
        r"directory traversal|path traversal|arbitrary file|file inclusion|\b[lr]fi\b|shellshock|"
        r"backdoor|default (?:credentials|password|account|login)|/etc/passwd|webshell|"
        r"authentication bypass", re.I)),
    ("medium", re.compile(
        r"cross[- ]site scripting|\bxss\b|directory indexing|directory listing|\.git/|\.svn/|\.env\b|"
        r"backup|database|config(?:uration)? file|phpmyadmin|admin(?:istration)? (?:login|page|console|interface)|"
        r"http (?:method|verb)s? .*(?:put|delete)|\bput\b.*allowed|\bdelete\b.*allowed|webdav|"
        r"information disclosure|source code|phpinfo|server-status|server-info|"
        r"(?:outdated|vulnerable|appears to be outdated)", re.I)),
    ("low", re.compile(
        r"x-frame-options|anti-clickjacking|x-content-type-options|strict-transport-security|"
        r"content-security-policy|x-xss-protection|httponly|secure flag|cookie .* without|"
        r"\btrace\b|uncommon header|etag|inode|leaks|retrieved x-powered-by|x-powered-by|"
        r"wildcard|access-control-allow-origin|clickjacking|banner", re.I)),
)

_TEXT_SKIP = re.compile(
    r"^\+\s*(?:Target IP|Target Hostname|Target Port|Start Time|End Time|SSL Info|Subject|Ciphers|"
    r"Issuer|Platform|Root page|\d+ host\(s\) tested|\d+ requests?:|Scan terminated|No web server found|"
    r"-+\s*$|Nikto v)",
    re.I,
)
_TEXT_SERVER = re.compile(r"^\+\s*Server:\s*(.+)$", re.I)


def severity_for(message: str) -> str:
    for sev, pattern in _RULES:
        if pattern.search(message or ""):
            return sev
    return "info"


def _items(data: Any) -> List[Dict[str, Any]]:
    hosts = data if isinstance(data, list) else [data]
    rows: List[Dict[str, Any]] = []
    for host in hosts:
        if not isinstance(host, dict):
            continue
        base = host.get("host") or host.get("ip") or ""
        port = host.get("port") or ""
        for vuln in host.get("vulnerabilities") or []:
            if isinstance(vuln, dict):
                rows.append({**vuln, "_host": base, "_port": port})
    return rows


def parse_nikto(output: str, exit_code: Optional[int] = None, *, timed_out: bool = False,
                **_context: Any) -> ParsedResult:
    text = strip_ansi(output or "")
    observations: List[Observation] = []
    data = extract_json(text)
    parsed_json = isinstance(data, (dict, list)) and any(
        isinstance(h, dict) and "vulnerabilities" in h for h in (data if isinstance(data, list) else [data]))
    if parsed_json:
        for item in _items(data):
            msg = str(item.get("msg") or "Nikto finding")
            target = str(item.get("url") or "")
            if item.get("_host") and target.startswith("/"):
                target = f"{item['_host']}:{item['_port']}{target}" if item.get("_port") else f"{item['_host']}{target}"
            observations.append(Observation(
                kind="vulnerability" if severity_for(msg) != "info" else "observation",
                title=msg, severity=severity_for(msg), target=target,
                attributes={"nikto_id": item.get("id") or "", "method": item.get("method") or "",
                            "references": item.get("references") or item.get("OSVDB") or ""},
            ))
    else:
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("+ ") or _TEXT_SKIP.match(line):
                continue
            server = _TEXT_SERVER.match(line)
            if server:
                observations.append(Observation(kind="technology", title=f"Server: {server.group(1)}",
                                                attributes={"server": server.group(1)}))
                continue
            msg = line[2:].strip()
            path_match = re.match(r"(?:OSVDB-\d+:\s*)?(?:(GET|POST|HEAD|OPTIONS)\s+)?(/\S*?):\s+(.+)", msg)
            target = path_match.group(2) if path_match else ""
            sev = severity_for(msg)
            observations.append(Observation(
                kind="vulnerability" if sev != "info" else "observation",
                title=path_match.group(3) if path_match else msg, severity=sev, target=target,
            ))
    status, reason = run_status(exit_code=exit_code, timed_out=timed_out, have_data=bool(observations),
                                success_exit_codes=(0, 1))
    if status == "ok" and not parsed_json and not observations and text.strip() and "host(s) tested" not in text:
        status, reason = "inconclusive", "no recognizable nikto output"
    return ParsedResult(tool=TOOL, status=status, observations=observations,
                        counts={"items": len(observations)}, reason=reason)
