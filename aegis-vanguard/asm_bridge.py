#!/usr/bin/env python3
"""
ASM Platform Bridge

Client library for Aegis Vanguard agents to communicate findings back to
Judah Security ASM platform. Handles authentication, batching,
retries, and structured finding submission.

Usage inside Aegis Vanguard container:
    from asm_bridge import ASMBridge, Finding
    
    bridge = ASMBridge()  # reads config from env or CLAUDE.md context
    bridge.submit_subdomain("api.example.com", source="subfinder")
    bridge.submit_port("api.example.com", 443, "tcp", service="https")
    bridge.submit_vulnerability(
        host="api.example.com",
        title="SQL Injection",
        severity="high",
        template_id="CVE-2024-1234",
    )
    bridge.flush()  # send any remaining buffered findings
"""

import json
import os
import sys
import time
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field, asdict

try:
    import httpx
    HTTP_CLIENT = "httpx"
except ImportError:
    import urllib.request
    import urllib.error
    HTTP_CLIENT = "urllib"

logger = logging.getLogger("asm_bridge")

# Severity escalation map: (vuln_type, current_severity) -> escalated_severity.
# Applied when PoC confirmation promotes a detected finding to a confirmed one.
_SEVERITY_ESCALATION: Dict[tuple, str] = {
    ("sqli",  "info"):    "high",
    ("sqli",  "low"):     "high",
    ("sqli",  "medium"):  "critical",
    ("sqli",  "high"):    "critical",
    ("xss",   "info"):    "medium",
    ("xss",   "low"):     "medium",
    ("xss",   "medium"):  "high",
    ("ssrf",  "low"):     "medium",
    ("ssrf",  "medium"):  "high",
    ("rce",   "low"):     "critical",
    ("rce",   "medium"):  "critical",
    ("idor",  "low"):     "medium",
    ("idor",  "medium"):  "high",
    ("lfi",   "low"):     "medium",
    ("lfi",   "medium"):  "high",
    ("ssti",  "medium"):  "critical",
    ("xxe",   "medium"):  "high",
}


try:
    from asm_scanner_core.findings import Finding  # shared with platform worker / OpenClaw
except ImportError:
    @dataclass
    class Finding:
        """A single finding to submit to the ASM platform."""
        type: str  # subdomain, domain, ip_address, port, vulnerability, url, technology,
        source: str
        target: str
        host: Optional[str] = None
        ip: Optional[str] = None
        port: Optional[int] = None
        protocol: Optional[str] = None
        url: Optional[str] = None
        title: Optional[str] = None
        description: Optional[str] = None
        severity: str = "info"
        confidence: str = "high"
        cve_id: Optional[str] = None
        cwe_id: Optional[str] = None
        cvss_score: Optional[float] = None
        template_id: Optional[str] = None
        service_name: Optional[str] = None
        service_version: Optional[str] = None
        service_product: Optional[str] = None
        banner: Optional[str] = None
        technologies: List[str] = field(default_factory=list)
        state: Optional[str] = None
        is_risky: bool = False
        risk_reason: Optional[str] = None
        tags: List[str] = field(default_factory=list)
        references: List[str] = field(default_factory=list)
        raw_data: Optional[Dict[str, Any]] = None
        takeover_status: Optional[str] = None
        takeover_service: Optional[str] = None
        cname_target: Optional[str] = None
        tls_version: Optional[str] = None
        cipher_suite: Optional[str] = None
        cert_score: Optional[str] = None
        key_algorithm: Optional[str] = None
        key_size: Optional[int] = None
        ca_type: Optional[str] = None
        cert_expiry_days: Optional[int] = None
        security_headers: Optional[Dict[str, Any]] = None
        cors_policy: Optional[Dict[str, Any]] = None
        mail_records: Optional[Dict[str, Any]] = None
        mail_provider: Optional[str] = None
        email_risk_score: Optional[int] = None
        vendor_name: Optional[str] = None
        vendor_category: Optional[str] = None
        vendor_detection_source: Optional[str] = None

        def to_dict(self) -> dict:
            d = {k: v for k, v in asdict(self).items() if v is not None}
            d["timestamp"] = datetime.now(timezone.utc).isoformat()
            return d


@dataclass
class PoCEvidence:
    """Proof-of-concept evidence attached to a confirmed vulnerability finding.

    Populated by exploit validation tools (sqlmap, playwright, xsstrike, etc.)
    and attached to the finding record via ASMBridge.confirm_finding().
    """
    vuln_type: str          # sqli, xss, dom-xss, ssrf, rce, idor, lfi, ssti, xxe …
    endpoint: str           # exact URL / route where the vuln was confirmed
    payload: str            # the payload that triggered the vulnerability
    request_raw: str = ""   # raw HTTP request (method + headers + body)
    response_snippet: str = ""  # relevant portion of the HTTP response
    screenshot_b64: str = ""    # base64 PNG (optional, for browser-confirmed findings)
    execution_evidence: str = ""  # e.g. "window.__vanguard_xss=https://target/admin"
    tool: str = ""          # sqlmap, playwright, xsstrike, manual …
    confirmed: bool = True

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v not in (None, "", False)}


class ASMBridge:
    """Client for submitting findings to Judah Security ASM platform."""

    def __init__(
        self,
        api_url: Optional[str] = None,
        api_key: Optional[str] = None,
        agent_id: Optional[str] = None,
        batch_size: int = 100,
        auto_flush: bool = True,
    ):
        self.api_url = (api_url or os.environ.get("ASM_API_URL", "")).rstrip("/")
        self.api_key = api_key or os.environ.get("ASM_API_KEY", "")
        self.agent_id = agent_id or os.environ.get("ASM_AGENT_ID", "aegis-vanguard")
        self.batch_size = batch_size
        self.auto_flush = auto_flush
        self._buffer: List[Finding] = []
        self._stats = {"submitted": 0, "created": 0, "errors": 0, "batches": 0}

        if not self.api_url:
            logger.warning("ASM_API_URL not set - findings will be logged but not submitted")
        if not self.api_key:
            logger.warning("ASM_API_KEY not set - submissions will fail auth")

    # =====================================================================
    # Convenience Methods
    # =====================================================================

    def submit_subdomain(self, subdomain: str, source: str = "subfinder", **kwargs):
        self._add(Finding(
            type="subdomain", source=source, target=subdomain,
            host=subdomain, title=f"Subdomain: {subdomain}", **kwargs,
        ))

    def submit_domain(self, domain: str, source: str = "discovery", **kwargs):
        self._add(Finding(
            type="domain", source=source, target=domain,
            host=domain, title=f"Domain: {domain}", **kwargs,
        ))

    def submit_ip(self, ip: str, source: str = "dnsx", **kwargs):
        self._add(Finding(
            type="ip_address", source=source, target=ip,
            ip=ip, title=f"IP: {ip}", **kwargs,
        ))

    def submit_port(
        self, host: str, port: int, protocol: str = "tcp",
        source: str = "naabu", service: Optional[str] = None, **kwargs,
    ):
        self._add(Finding(
            type="port", source=source, target=host,
            host=host, port=port, protocol=protocol,
            service_name=service, state="open",
            title=f"Port {port}/{protocol} on {host}", **kwargs,
        ))

    def submit_vulnerability(
        self, host: str, title: str, severity: str = "info",
        source: str = "nuclei", **kwargs,
    ):
        self._add(Finding(
            type="vulnerability", source=source, target=host,
            host=host, title=title, severity=severity, **kwargs,
        ))

    def submit_url(self, url: str, source: str = "katana", **kwargs):
        from urllib.parse import urlparse
        parsed = urlparse(url)
        self._add(Finding(
            type="url", source=source, target=parsed.hostname or url,
            host=parsed.hostname, url=url,
            title=f"URL: {url}", **kwargs,
        ))

    def submit_takeover(
        self, host: str, status: str, service: str = "",
        cname_target: str = "", source: str = "takeover-check", **kwargs,
    ):
        severity = "high" if status == "confirmed" else "medium" if status == "potential" else "info"
        self._add(Finding(
            type="takeover", source=source, target=host, host=host,
            title=f"Subdomain Takeover ({status}): {host}",
            severity=severity, is_risky=(status in ("confirmed", "potential")),
            takeover_status=status, takeover_service=service,
            cname_target=cname_target,
            tags=["takeover", service] if service else ["takeover"],
            **kwargs,
        ))

    def submit_tls_analysis(
        self, host: str, source: str = "tlsx", **kwargs,
    ):
        self._add(Finding(
            type="tls_analysis", source=source, target=host, host=host,
            title=f"TLS Analysis: {host}", **kwargs,
        ))

    def submit_security_headers(
        self, host: str, url: str = "", source: str = "httpx",
        security_headers: Optional[Dict[str, Any]] = None,
        cors_policy: Optional[Dict[str, Any]] = None, **kwargs,
    ):
        missing = []
        if security_headers:
            for hdr in ("strict-transport-security", "content-security-policy", "x-frame-options"):
                if not security_headers.get(hdr):
                    missing.append(hdr)
        self._add(Finding(
            type="security_header", source=source, target=host, host=host,
            url=url or f"https://{host}",
            title=f"Security Headers: {host}",
            severity="medium" if missing else "info",
            security_headers=security_headers,
            cors_policy=cors_policy,
            tags=["headers"] + ([f"missing:{h}" for h in missing]),
            **kwargs,
        ))

    def submit_mail_intel(
        self, domain: str, source: str = "dnsx",
        mail_records: Optional[Dict[str, Any]] = None,
        mail_provider: str = "", email_risk_score: int = 0, **kwargs,
    ):
        self._add(Finding(
            type="mail_infrastructure", source=source, target=domain, host=domain,
            title=f"Mail Infrastructure: {domain}",
            mail_records=mail_records, mail_provider=mail_provider,
            email_risk_score=email_risk_score, **kwargs,
        ))

    def submit_vendor(
        self, host: str, vendor_name: str, vendor_category: str = "",
        detection_source: str = "", source: str = "vendor-intel", **kwargs,
    ):
        self._add(Finding(
            type="third_party_vendor", source=source, target=host, host=host,
            title=f"Third-Party: {vendor_name} on {host}",
            vendor_name=vendor_name, vendor_category=vendor_category,
            vendor_detection_source=detection_source,
            tags=["vendor", vendor_category] if vendor_category else ["vendor"],
            **kwargs,
        ))

    def submit_finding(self, finding: Finding):
        """Submit an arbitrary finding."""
        self._add(finding)

    def confirm_finding(
        self,
        host: str,
        title: str,
        vuln_type: str,
        poc: "PoCEvidence",
        current_severity: str = "medium",
        source: str = "aegis-vanguard-poc",
    ) -> str:
        """Confirm a vulnerability with PoC evidence, escalating severity as warranted.

        Submits a new '[CONFIRMED]' finding record linked to the original detection.
        Returns the final (possibly escalated) severity string.
        """
        key = (vuln_type.lower(), current_severity.lower())
        escalated = _SEVERITY_ESCALATION.get(key, current_severity)
        did_escalate = escalated != current_severity

        if did_escalate:
            logger.info(
                f"PoC confirmed — severity escalated: {title} "
                f"[{current_severity} → {escalated}] via {poc.tool or vuln_type}"
            )
            self._stats["escalated"] = self._stats.get("escalated", 0) + 1

        tags = ["confirmed", "poc", vuln_type.lower()]
        if did_escalate:
            tags.append(f"escalated_from:{current_severity}")

        self._add(Finding(
            type="vulnerability",
            source=source,
            target=host,
            host=host,
            title=f"[CONFIRMED] {title}",
            severity=escalated,
            confidence="confirmed",
            description=(
                f"PoC confirmed via {poc.tool or vuln_type}. "
                f"Endpoint: {poc.endpoint}. "
                f"Payload: {poc.payload[:300]}"
                + (f". Evidence: {poc.execution_evidence}" if poc.execution_evidence else "")
            ),
            tags=tags,
            raw_data={
                "poc": poc.to_dict(),
                "original_severity": current_severity,
                "escalated": did_escalate,
            },
        ))
        return escalated

    # =====================================================================
    # Buffer Management
    # =====================================================================

    def _add(self, finding: Finding):
        self._buffer.append(finding)
        if self.auto_flush and len(self._buffer) >= self.batch_size:
            self.flush()

    def flush(self) -> Optional[dict]:
        """Send all buffered findings to the ASM platform."""
        if not self._buffer:
            return None

        batch = self._buffer[:]
        self._buffer.clear()

        # Governance: stamp each vulnerability finding with the proof gate's
        # verdict before it is documented or submitted, so an unproven finding
        # can never leave the harness labelled "confirmed".
        for f in batch:
            self._apply_proof_gate(f)

        # Optional local sink: append every flushed finding as a JSON line.
        # Enabled by the benchmarking/batch harness via AEGIS_FINDINGS_SINK so a
        # run produces a stable, machine-readable artifact independent of the
        # platform ingestion API. No-op when the env var is unset.
        self._write_sink(batch)

        payload = {
            "agent_id": self.agent_id,
            "agent_type": "aegis_vanguard",
            "scan_context": "aegis-vanguard-agent",
            "findings": [f.to_dict() for f in batch],
        }

        if not self.api_url:
            logger.info(f"[dry-run] Would submit {len(batch)} findings")
            for f in batch:
                logger.info(f"  {f.type}: {f.target} ({f.title})")
            self._stats["submitted"] += len(batch)
            return {"dry_run": True, "count": len(batch)}

        result = self._post("/api/v1/ingest/findings", payload)
        if result:
            self._stats["batches"] += 1
            self._stats["submitted"] += result.get("total_submitted", 0)
            self._stats["created"] += result.get("created", 0)
            self._stats["errors"] += result.get("errors", 0)
            logger.info(
                f"Batch submitted: {result.get('created', 0)} created, "
                f"{result.get('updated', 0)} updated, "
                f"{result.get('duplicates', 0)} dupes, "
                f"{result.get('errors', 0)} errors"
            )
        return result

    def heartbeat(self) -> Optional[dict]:
        """Send a heartbeat to the ASM platform."""
        payload = {
            "agent_id": self.agent_id,
            "agent_type": "aegis_vanguard",
            "status": "healthy",
            "findings_sent_total": self._stats["submitted"],
            "capabilities": [
                "subdomain_enum", "port_scan", "vuln_scan", "web_crawl",
                "takeover_detection", "tls_analysis", "security_headers",
                "mail_intel", "vendor_intel",
                "browser_crawl", "dom_xss", "poc_confirmation",
            ],
        }
        return self._post("/api/v1/ingest/heartbeat", payload)

    def _apply_proof_gate(self, finding: Finding) -> None:
        """Tag a vulnerability finding with its proof-gate verdict.

        Non-destructive by default: adds a `proof:confirmed` / `proof:needs_evidence`
        tag and stashes the verdict in raw_data. The one governance action is to
        demote a finding that *claims* confidence "confirmed" but has no proof
        token down to "needs_evidence" — impact (severity) is left intact; only
        the trust axis (confidence) is corrected. Disable with
        AEGIS_PROOF_GATE_SUBMISSION=false.
        """
        if os.environ.get("AEGIS_PROOF_GATE_SUBMISSION", "true").lower() == "false":
            return
        if getattr(finding, "type", "") != "vulnerability":
            return
        try:
            from agent.finding_oracle import grade_finding
            verdict = grade_finding(finding.to_dict())
        except Exception as e:  # never let the gate break submission
            logger.debug("proof gate skipped: %s", e)
            return

        tag = "proof:confirmed" if verdict.confirmed else "proof:needs_evidence"
        try:
            if hasattr(finding, "tags") and isinstance(finding.tags, list):
                if tag not in finding.tags:
                    finding.tags.append(tag)
            if hasattr(finding, "raw_data"):
                rd = dict(finding.raw_data or {})
                rd["verification"] = verdict.to_dict()
                finding.raw_data = rd
            claimed = str(getattr(finding, "confidence", "")).lower()
            if not verdict.confirmed and claimed == "confirmed":
                finding.confidence = "needs_evidence"
                if hasattr(finding, "tags") and isinstance(finding.tags, list) \
                        and "downgraded:no_proof" not in finding.tags:
                    finding.tags.append("downgraded:no_proof")
                self._stats["gate_downgraded"] = self._stats.get("gate_downgraded", 0) + 1
                logger.info("proof gate: '%s' had no proof token → confidence "
                            "demoted to needs_evidence", getattr(finding, "title", ""))
        except Exception as e:
            logger.debug("proof gate tagging failed: %s", e)

    def _write_sink(self, batch: List[Finding]) -> None:
        """Append findings to the AEGIS_FINDINGS_SINK JSONL file if configured."""
        sink_path = os.environ.get("AEGIS_FINDINGS_SINK", "")
        if not sink_path:
            return
        try:
            os.makedirs(os.path.dirname(os.path.abspath(sink_path)), exist_ok=True)
            with open(sink_path, "a", encoding="utf-8") as fh:
                for f in batch:
                    fh.write(json.dumps(f.to_dict(), default=str) + "\n")
        except Exception as e:  # never let sink IO break a scan
            logger.warning(f"findings sink write failed ({sink_path}): {e}")

    @property
    def stats(self) -> dict:
        return dict(self._stats)

    # =====================================================================
    # HTTP Transport
    # =====================================================================

    def _post(self, path: str, payload: dict, retries: int = 3) -> Optional[dict]:
        url = f"{self.api_url}{path}"
        headers = {
            "Content-Type": "application/json",
            "X-API-Key": self.api_key,
        }
        body = json.dumps(payload, default=str).encode("utf-8")

        for attempt in range(retries):
            try:
                if HTTP_CLIENT == "httpx":
                    return self._post_httpx(url, headers, body)
                else:
                    return self._post_urllib(url, headers, body)
            except Exception as e:
                wait = 2 ** attempt
                logger.warning(f"Request failed (attempt {attempt + 1}/{retries}): {e}, retrying in {wait}s")
                time.sleep(wait)

        logger.error(f"All {retries} attempts failed for {path}")
        return None

    def _post_httpx(self, url: str, headers: dict, body: bytes) -> dict:
        with httpx.Client(timeout=30) as client:
            resp = client.post(url, content=body, headers=headers)
            resp.raise_for_status()
            return resp.json()

    def _post_urllib(self, url: str, headers: dict, body: bytes) -> dict:
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))


# =========================================================================
# CLI for quick testing
# =========================================================================

def main():
    """CLI entry point for testing the bridge."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    bridge = ASMBridge()

    if len(sys.argv) < 2:
        print("Usage: python asm_bridge.py <command> [args]")
        print()
        print("Commands:")
        print("  test                     Submit test findings (dry-run if no API URL)")
        print("  heartbeat                Send heartbeat")
        print("  subdomain <host>         Submit a subdomain finding")
        print("  port <host> <port>       Submit a port finding")
        print("  vuln <host> <title>      Submit a vulnerability finding")
        return

    cmd = sys.argv[1]

    if cmd == "test":
        bridge.submit_subdomain("test.example.com")
        bridge.submit_port("test.example.com", 443, service="https")
        bridge.submit_port("test.example.com", 22, service="ssh")
        bridge.submit_vulnerability("test.example.com", "Test Finding", severity="low")
        result = bridge.flush()
        print(json.dumps(result, indent=2, default=str))

    elif cmd == "heartbeat":
        result = bridge.heartbeat()
        print(json.dumps(result, indent=2, default=str))

    elif cmd == "subdomain" and len(sys.argv) >= 3:
        bridge.submit_subdomain(sys.argv[2])
        bridge.flush()

    elif cmd == "port" and len(sys.argv) >= 4:
        bridge.submit_port(sys.argv[2], int(sys.argv[3]))
        bridge.flush()

    elif cmd == "vuln" and len(sys.argv) >= 4:
        bridge.submit_vulnerability(sys.argv[2], sys.argv[3])
        bridge.flush()

    else:
        print(f"Unknown command: {cmd}")


if __name__ == "__main__":
    main()
