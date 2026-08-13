"""
Native finding revalidation — replay the original detector / reproduction steps.

Used by the scanner worker for on-demand "Validate finding" without requiring
the Aegis Vanguard Docker image. Strategies:

  1. Nuclei findings  → re-run the matched template against the live target
  2. Port / network   → TCP (and light HTTP) probes of claimed host:ports
  3. Agent / manual   → parse steps_to_reproduce, evidence, and description for
                        URLs / host:port pairs, then re-probe those endpoints

Returns a verdict dict compatible with FindingValidation / handle_validate_finding.
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket
from typing import Any, Optional
from urllib.parse import urlparse
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
_HOSTPORT_RE = re.compile(
    r"\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    r"|(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+))"
    r":(\d{2,5})\b"
)
_PORT_HINT_RE = re.compile(r"(?i)\bports?\s*[:=]?\s*(\d{2,5})\b|\(port\s+(\d{2,5})\)")
_URL_RE = re.compile(r"https?://[^\s\]\)\"'<>]+", re.IGNORECASE)

# Ports where a successful TCP connect alone is weak; try a cheap HTTP GET too.
_HTTPISH_PORTS = {80, 443, 5984, 8080, 8443, 8888, 9200, 9300, 5601, 3000, 5000, 8000, 9443}


def _tcp_open(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def _http_probe(url: str, timeout: float = 5.0) -> dict[str, Any]:
    """Cheap unauthenticated GET — enough to confirm Elasticsearch/CouchDB-style exposure."""
    out: dict[str, Any] = {"url": url, "ok": False, "status": None, "snippet": None, "error": None}
    try:
        req = Request(url, method="GET", headers={"User-Agent": "asm-finding-revalidator/1.0"})
        with urlopen(req, timeout=timeout) as resp:  # noqa: S310 — intentional live re-test
            body = resp.read(512)
            out["ok"] = True
            out["status"] = getattr(resp, "status", None) or resp.getcode()
            out["snippet"] = body.decode("utf-8", errors="replace")[:240]
    except Exception as e:
        out["error"] = str(e)[:200]
    return out


def _extract_endpoints(finding: dict) -> list[dict[str, Any]]:
    """Collect host:port / URL reproduction points from finding fields."""
    endpoints: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(host: Optional[str] = None, port: Optional[int] = None, url: Optional[str] = None, source: str = ""):
        if url:
            key = f"url:{url}"
            if key not in seen:
                seen.add(key)
                endpoints.append({"kind": "url", "url": url, "source": source})
            return
        if not host or not port:
            return
        try:
            port_i = int(port)
        except (TypeError, ValueError):
            return
        if port_i < 1 or port_i > 65535:
            return
        host = str(host).strip().rstrip(".")
        key = f"{host}:{port_i}"
        if key in seen:
            return
        seen.add(key)
        endpoints.append({"kind": "tcp", "host": host, "port": port_i, "source": source})

    meta = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
    asset = finding.get("asset")
    target = finding.get("target") or asset
    meta_port = meta.get("port") or meta.get("nuclei_port") or meta.get("dst_port")
    meta_host = meta.get("scanned_ip") or meta.get("host") or meta.get("ip") or asset

    if meta_host and meta_port:
        add(host=str(meta_host).split(":")[0], port=meta_port, source="metadata")

    # target as URL or host:port
    if target:
        t = str(target).strip()
        if "://" in t:
            add(url=t.split()[0], source="target")
            parsed = urlparse(t)
            if parsed.hostname and parsed.port:
                add(host=parsed.hostname, port=parsed.port, source="target")
        else:
            m = _HOSTPORT_RE.search(t)
            if m:
                add(host=m.group(1), port=int(m.group(2)), source="target")
            elif meta_port and t and not t.startswith("["):
                add(host=t.split(":")[0], port=meta_port, source="target+metadata.port")

    if finding.get("affected_component"):
        ac = str(finding["affected_component"])
        for m in _HOSTPORT_RE.finditer(ac):
            add(host=m.group(1), port=int(m.group(2)), source="affected_component")
        for u in _URL_RE.findall(ac):
            add(url=u.rstrip(".,;"), source="affected_component")

    # Free-text blobs: steps, evidence, description (agent findings often list IPs under port headings)
    blobs = [
        ("steps_to_reproduce", finding.get("steps_to_reproduce")),
        ("proof_of_concept", finding.get("proof_of_concept")),
        ("evidence", finding.get("evidence")),
        ("description", finding.get("description")),
    ]
    for source, blob in blobs:
        if not blob:
            continue
        text = str(blob)
        for u in _URL_RE.findall(text):
            add(url=u.rstrip(".,;"), source=source)
        for m in _HOSTPORT_RE.finditer(text):
            add(host=m.group(1), port=int(m.group(2)), source=source)

        # Section parser: "**MySQL (port 3306)**\n- 1.2.3.4"
        current_port: Optional[int] = None
        for line in text.splitlines():
            ph = _PORT_HINT_RE.search(line)
            if ph:
                current_port = int(ph.group(1) or ph.group(2))
            if current_port is None:
                continue
            for ip in _IPV4_RE.findall(line):
                # Skip if line already matched as host:port
                if f"{ip}:{current_port}" in line or re.search(rf"{re.escape(ip)}:\d+", line):
                    continue
                # Prefer IPs on bullet / bare lines near a port heading
                if re.match(r"^\s*[-*•]?\s*\d+\.\d+\.\d+\.\d+\s*$", line) or ip in line:
                    add(host=ip, port=current_port, source=f"{source}:port_section")

    # Cap to keep validation bounded
    return endpoints[:40]


def _probe_endpoints(endpoints: list[dict[str, Any]], timeout: float = 3.0) -> list[dict[str, Any]]:
    results = []
    for ep in endpoints:
        if ep["kind"] == "url":
            http = _http_probe(ep["url"], timeout=max(timeout, 5.0))
            results.append({**ep, "reachable": bool(http.get("ok")), "http": http})
            continue
        host, port = ep["host"], ep["port"]
        open_ = _tcp_open(host, port, timeout=timeout)
        row: dict[str, Any] = {**ep, "reachable": open_, "tcp_open": open_}
        if open_ and port in _HTTPISH_PORTS:
            scheme = "https" if port in (443, 8443, 9443) else "http"
            http = _http_probe(f"{scheme}://{host}:{port}/", timeout=max(timeout, 5.0))
            row["http"] = http
            # For exposure-style findings, any TCP open counts; HTTP success strengthens.
            if http.get("ok"):
                row["reachable"] = True
        results.append(row)
    return results


def _verdict_from_probes(
    finding: dict,
    probes: list[dict[str, Any]],
    method: str,
) -> dict[str, Any]:
    if not probes:
        return {
            "verdict": "needs_more_evidence",
            "confidence": "low",
            "is_false_positive": False,
            "still_open": None,
            "logical_mismatch": False,
            "recommended_severity": finding.get("severity") or "info",
            "reasoning": (
                "Native revalidation could not extract reproduction endpoints "
                "(host:port / URL) from the finding’s metadata, steps, or evidence."
            ),
            "evidence": "no_endpoints_extracted",
            "template_logic_issue": None,
            "method": method,
            "probes": [],
        }

    open_n = sum(1 for p in probes if p.get("reachable"))
    closed_n = len(probes) - open_n
    open_list = [
        (p.get("url") or f"{p.get('host')}:{p.get('port')}")
        for p in probes if p.get("reachable")
    ]
    closed_list = [
        (p.get("url") or f"{p.get('host')}:{p.get('port')}")
        for p in probes if not p.get("reachable")
    ]

    if open_n == 0:
        return {
            "verdict": "false_positive",
            "confidence": "high" if len(probes) >= 2 else "medium",
            "is_false_positive": True,
            "still_open": False,
            "logical_mismatch": False,
            "recommended_severity": "info",
            "reasoning": (
                f"Re-probed {len(probes)} reproduction endpoint(s) from the original "
                f"detection; none are reachable now (ports closed or URLs gone)."
            ),
            "evidence": f"closed={closed_list[:15]}",
            "template_logic_issue": None,
            "method": method,
            "probes": probes,
        }

    if closed_n == 0 or open_n >= max(1, len(probes) // 2):
        return {
            "verdict": "confirmed",
            "confidence": "high" if closed_n == 0 else "medium",
            "is_false_positive": False,
            "still_open": True,
            "logical_mismatch": False,
            "recommended_severity": finding.get("severity") or "medium",
            "reasoning": (
                f"Re-probed endpoints from the original detection steps: "
                f"{open_n}/{len(probes)} still reachable "
                f"(e.g. {', '.join(open_list[:5])}{'…' if len(open_list) > 5 else ''})."
            ),
            "evidence": f"open={open_list[:20]}; closed={closed_list[:10]}",
            "template_logic_issue": None,
            "method": method,
            "probes": probes,
        }

    return {
        "verdict": "needs_more_evidence",
        "confidence": "medium",
        "is_false_positive": False,
        "still_open": True,
        "logical_mismatch": False,
        "recommended_severity": finding.get("severity") or "medium",
        "reasoning": (
            f"Mixed results on reproduction endpoints ({open_n} open / {closed_n} closed). "
            "Some claimed services still respond; manual review recommended."
        ),
        "evidence": f"open={open_list[:15]}; closed={closed_list[:15]}",
        "template_logic_issue": None,
        "method": method,
        "probes": probes,
    }


async def _revalidate_nuclei(finding: dict) -> Optional[dict[str, Any]]:
    template_yaml = finding.get("template_yaml")
    template_id = finding.get("template_id")
    target = finding.get("target") or finding.get("asset")
    if not target:
        return None
    if not template_yaml and not template_id:
        return None

    try:
        from app.services.custom_template_ai import recheck_template_against_target
        from app.services.nuclei_service import NucleiService
    except Exception as e:
        logger.warning("Native nuclei revalidation imports failed: %s", e)
        return None

    # Prefer full YAML when available; otherwise ask nuclei for the template id.
    if template_yaml:
        recheck = await recheck_template_against_target(template_yaml, str(target), timeout_sec=90)
    else:
        svc = NucleiService()
        if not svc.check_installation():
            return {
                "verdict": "needs_more_evidence",
                "confidence": "low",
                "is_false_positive": False,
                "still_open": None,
                "logical_mismatch": False,
                "recommended_severity": finding.get("severity") or "info",
                "reasoning": "Nuclei is not installed on the scanner worker; cannot re-run template.",
                "evidence": "nuclei_not_installed",
                "template_logic_issue": None,
                "method": "nuclei_template_replay",
            }
        scan = await svc.scan_targets(
            targets=[str(target)],
            severity=["critical", "high", "medium", "low", "info"],
            templates=[str(template_id)],
            timeout=90,
        )
        recheck = {
            "ran": True,
            "still_fires": bool(scan.findings),
            "match_count": len(scan.findings or []),
            "error": None,
        }

    if recheck.get("error") and not recheck.get("ran"):
        return {
            "verdict": "needs_more_evidence",
            "confidence": "low",
            "is_false_positive": False,
            "still_open": None,
            "logical_mismatch": False,
            "recommended_severity": finding.get("severity") or "info",
            "reasoning": f"Nuclei re-check failed: {recheck.get('error')}",
            "evidence": str(recheck),
            "template_logic_issue": None,
            "method": "nuclei_template_replay",
            "nuclei_recheck": recheck,
        }

    still = bool(recheck.get("still_fires"))
    if still:
        return {
            "verdict": "confirmed",
            "confidence": "high",
            "is_false_positive": False,
            "still_open": True,
            "logical_mismatch": False,
            "recommended_severity": finding.get("severity") or "medium",
            "reasoning": (
                f"Re-ran nuclei template {template_id or '(inline yaml)'} against "
                f"{target}; it still matches ({recheck.get('match_count', 0)} hit(s))."
            ),
            "evidence": str(recheck),
            "template_logic_issue": None,
            "method": "nuclei_template_replay",
            "nuclei_recheck": recheck,
        }

    return {
        "verdict": "false_positive",
        "confidence": "high",
        "is_false_positive": True,
        "still_open": False,
        "logical_mismatch": False,
        "recommended_severity": "info",
        "reasoning": (
            f"Re-ran nuclei template {template_id or '(inline yaml)'} against "
            f"{target}; it no longer matches (fixed or original match was a false positive)."
        ),
        "evidence": str(recheck),
        "template_logic_issue": None,
        "method": "nuclei_template_replay",
        "nuclei_recheck": recheck,
    }


async def revalidate_finding(finding: dict) -> dict[str, Any]:
    """
    Revalidate one finding using scanner-native tools and stored reproduction data.

    ``finding`` is the same payload shape built by handle_validate_finding.
    """
    detected_by = (finding.get("detected_by") or "").lower()
    source_kind = (finding.get("source_kind") or "").lower()

    # 1) Nuclei / template-based detectors — replay the exact template when possible.
    if finding.get("template_id") or finding.get("template_yaml"):
        nuclei_verdict = await _revalidate_nuclei(finding)
        if nuclei_verdict:
            return nuclei_verdict

    # 2) Port / agent / manual / generic — probe reproduction endpoints from stored steps.
    endpoints = await asyncio.to_thread(_extract_endpoints, finding)
    method = {
        "network_service": "port_replay",
        "manual": "steps_replay",
        "web": "steps_and_http_replay",
        "secret": "steps_replay",
    }.get(source_kind, "detection_steps_replay")
    if detected_by in ("port_scanner",):
        method = "port_replay"
    elif detected_by in ("agent", "llm_red_team"):
        method = "agent_steps_replay"

    probes = await asyncio.to_thread(_probe_endpoints, endpoints)
    verdict = _verdict_from_probes(finding, probes, method=method)
    verdict["detected_by"] = detected_by
    verdict["source_kind"] = source_kind
    verdict["endpoint_count"] = len(endpoints)
    return verdict
