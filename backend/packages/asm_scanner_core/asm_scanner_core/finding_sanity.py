"""Deterministic logical-sanity checks for re-validating findings.

Catches the classic false positive where a detector claims a non-HTTP service
(LDAP, SMB, Redis, ...) on an HTTP(S) port. Shared by the platform's native
finding revalidation and Aegis Vanguard's LLM validator. Pure functions: no
network, no LLM.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

# Well-known service → expected ports. Used for deterministic logic checks
# before (and as guidance for) the LLM re-test.
SERVICE_PORTS: dict[str, set[int]] = {
    "ldap": {389, 636, 3268, 3269},
    "ldaps": {636, 3269},
    "smtp": {25, 465, 587},
    "smtps": {465},
    "imap": {143, 993},
    "imaps": {993},
    "pop3": {110, 995},
    "pop3s": {995},
    "ftp": {21, 990},
    "ftps": {990},
    "ssh": {22},
    "telnet": {23},
    "mysql": {3306},
    "mariadb": {3306},
    "postgres": {5432},
    "postgresql": {5432},
    "mssql": {1433},
    "redis": {6379},
    "mongodb": {27017},
    "memcached": {11211},
    "elasticsearch": {9200, 9300},
    "kibana": {5601},
    "rdp": {3389},
    "smb": {139, 445},
    "nfs": {2049},
    "vnc": {5900, 5901},
    "mqtt": {1883, 8883},
    "amqp": {5672},
    "cassandra": {9042},
    "couchdb": {5984},
    "zookeeper": {2181},
    "kafka": {9092},
    "dns": {53},
    "snmp": {161, 162},
    "sip": {5060, 5061},
}

WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9443}


def extract_port(finding: dict, target: str) -> int | None:
    """Best-effort port from metadata, target URL, or host:port string."""
    meta = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
    for key in ("port", "nuclei_port", "dst_port"):
        raw = meta.get(key)
        if raw is None:
            continue
        try:
            return int(raw)
        except (TypeError, ValueError):
            pass
    parsed = urlparse(target if "://" in target else f"//{target}")
    if parsed.port:
        return parsed.port
    if parsed.scheme == "https":
        return 443
    if parsed.scheme == "http":
        return 80
    # host:port without scheme
    host = str(finding.get("target") or finding.get("host") or target or "")
    m = re.search(r":(\d{2,5})(?:/|$)", host)
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            return None
    return None


def infer_claimed_services(finding: dict) -> list[str]:
    """Infer which non-HTTP service the finding claims from title/template/tags."""
    blob = " ".join(
        str(x or "")
        for x in (
            finding.get("title"),
            finding.get("description"),
            finding.get("template_id"),
            finding.get("affected_component"),
            " ".join(finding.get("tags") or []),
        )
    ).lower()
    hits: list[str] = []
    for name in SERVICE_PORTS:
        # word-ish match so "ldap" hits ldap-anonymous but not "gladly"
        if re.search(rf"(?<![a-z]){re.escape(name)}(?![a-z])", blob):
            hits.append(name)
    return hits


def logical_sanity_check(finding: dict, target: str) -> dict | None:
    """
    Deterministic pre-check for nonsensical findings.

    Example: LDAP anonymous bind template matched against https://host:443.
    Returns an early false_positive verdict, or None to continue re-testing.
    """
    port = extract_port(finding, target)
    claimed = infer_claimed_services(finding)
    if not claimed or port is None:
        return None

    # Only auto-FP when claimed service is clearly non-web AND port is a web port
    # (or otherwise outside the service's well-known ports).
    mismatches = []
    for svc in claimed:
        expected = SERVICE_PORTS.get(svc) or set()
        if not expected:
            continue
        if port in expected:
            continue
        # Strong signal: non-HTTP service claimed on typical HTTP(S) ports
        if port in WEB_PORTS:
            mismatches.append((svc, expected))
        # Also flag when port is nowhere near the service's range and not a
        # common alternate (keep conservative — only web-port case auto-kills).

    if not mismatches:
        return None

    svc_list = ", ".join(f"{s} (expected ports {sorted(p)})" for s, p in mismatches)
    return {
        "verdict": "false_positive",
        "confidence": "high",
        "is_false_positive": True,
        "still_open": False,
        "logical_mismatch": True,
        "recommended_severity": "info",
        "reasoning": (
            f"Logical mismatch: finding claims {svc_list}, but target port is {port} "
            f"({target}). Non-HTTP service detections on HTTP(S) ports are almost "
            f"always template/protocol false positives."
        ),
        "evidence": (
            f"claimed_services={[s for s, _ in mismatches]} observed_port={port} "
            f"target={target} template_id={finding.get('template_id')}"
        ),
        "template_logic_issue": (
            f"Template/detection for {[s for s, _ in mismatches]} fired against "
            f"port {port} instead of the service's well-known ports. Matcher likely "
            f"does not verify the actual protocol/handshake."
        ),
        "sanity_flags": [
            f"service_port_mismatch:{s}:port_{port}" for s, _ in mismatches
        ],
    }


def sanity_guidance(finding: dict, target: str) -> str:
    """Soft guidance injected into the LLM prompt even when we don't auto-FP."""
    port = extract_port(finding, target)
    claimed = infer_claimed_services(finding)
    lines = [
        "\n## Logical sanity (check BEFORE confirming)\n",
        "- Ask: would this vulnerability class exist on the live service at this port?\n",
        "- LDAP/AD/SMB/SSH/SMTP/DB/Redis/RDP findings on 80/443/8080/8443 → almost always FP.\n",
        "- If probe_http/fingerprint_tech shows a normal web app and the finding is a "
        "non-HTTP protocol issue, mark false_positive with logical_mismatch=true.\n",
        "- Re-check whether the issue is STILL OPEN (still_open). Remediated or "
        "closed ports → false_positive / still_open=false.\n",
    ]
    if port is not None:
        lines.append(f"- Observed port for this target: **{port}**.\n")
    if claimed:
        lines.append(
            f"- Finding text appears to claim service(s): **{', '.join(claimed)}**. "
            f"Verify the live protocol matches before confirming.\n"
        )
    return "".join(lines)


__all__ = [
    "SERVICE_PORTS",
    "WEB_PORTS",
    "extract_port",
    "infer_claimed_services",
    "logical_sanity_check",
    "sanity_guidance",
]
