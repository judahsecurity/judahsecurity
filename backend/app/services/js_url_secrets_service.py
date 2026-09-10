"""
Download web-accessible JavaScript (or text) assets and scan for hardcoded secrets.

Uses Gitleaks in --no-git mode on a temp directory of fetched files, and merges
lightweight regex heuristics from KatanaService.extract_secrets_from_js for
patterns Gitleaks may not label (e.g. some minified bundles).

Also runs a structural scanner for CWE-321 client HMAC keys reconstructed via
Object.keys(obj).join("") / for-in concatenation (iLens/Angular main-es2015
bundles are often 5–10MB; a 2MB cap would miss them).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess
import tempfile
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx

from app.services.js_client_signing_secrets import (
    analyze_js_client_secrets,
    summarize_client_signing_findings,
)
from app.services.katana_service import KatanaService
from app.services.secret_safety import safe_source_url, secret_descriptor, secret_fingerprint

logger = logging.getLogger(__name__)

# Angular main-es2015 production bundles commonly exceed 6MB; secrets often sit
# in APP_CONSTANTS near the end of the file. 2MB dropped those findings.
DEFAULT_MAX_BYTES = 16 * 1024 * 1024
DEFAULT_TAIL_BYTES = 8 * 1024 * 1024
DEFAULT_TIMEOUT = 60.0


def _parse_url_list(urls: str) -> List[str]:
    if not urls or not str(urls).strip():
        return []
    out: List[str] = []
    for line in str(urls).replace(",", "\n").split("\n"):
        u = line.strip()
        if not u:
            continue
        if u.startswith("http://") or u.startswith("https://"):
            out.append(u)
    # dedupe preserving order
    seen = set()
    unique: List[str] = []
    for u in out:
        if u not in seen:
            seen.add(u)
            unique.append(u)
    return unique


def _safe_filename(url: str) -> str:
    h = hashlib.sha256(url.encode("utf-8")).hexdigest()[:20]
    return f"{h}.js"


def _fetch_url(
    client: httpx.Client, url: str, max_bytes: int, timeout: float
) -> Tuple[Optional[bytes], Optional[str], Dict[str, Any]]:
    """Fetch a JS asset. Truncated bodies are still returned for scanning.

    If Content-Length exceeds max_bytes, also pull the last DEFAULT_TAIL_BYTES
    via Range so APP_CONSTANTS at the end of webpack bundles are not dropped.
    """
    meta: Dict[str, Any] = {"truncated": False, "range_tail": False, "content_length": None}
    try:
        with client.stream("GET", url, follow_redirects=True, timeout=timeout) as resp:
            if resp.status_code != 200:
                return None, f"HTTP {resp.status_code}", meta
            try:
                cl = int(resp.headers.get("Content-Length") or 0)
            except (TypeError, ValueError):
                cl = 0
            if cl:
                meta["content_length"] = cl
            buf = bytearray()
            truncated = False
            for chunk in resp.iter_bytes():
                buf.extend(chunk)
                if len(buf) > max_bytes:
                    truncated = True
                    del buf[max_bytes:]
                    break
            body = bytes(buf)
            meta["truncated"] = truncated
        if truncated:
            tail = _fetch_range_tail(client, url, timeout)
            if tail:
                meta["range_tail"] = True
                # Keep head + tail; overlap is fine — analyzer is idempotent.
                body = body + b"\n" + tail
        return body, None, meta
    except Exception as e:
        return None, str(e), meta


def _fetch_range_tail(
    client: httpx.Client, url: str, timeout: float, tail_bytes: int = DEFAULT_TAIL_BYTES
) -> Optional[bytes]:
    try:
        resp = client.get(
            url,
            headers={"Range": f"bytes=-{int(tail_bytes)}"},
            follow_redirects=True,
            timeout=timeout,
        )
        if resp.status_code in (200, 206) and resp.content:
            return bytes(resp.content[: tail_bytes + 1])
    except Exception as e:
        logger.debug("Range tail fetch failed for %s: %s", url[:80], e)
    return None


def _run_gitleaks_no_git(source_dir: str, timeout: int = 180) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    exe = shutil.which("gitleaks")
    if not exe:
        return [], "gitleaks binary not found in PATH"
    report_path = os.path.join(source_dir, ".gitleaks-report.json")
    cmd = [
        exe,
        "detect",
        "--source",
        source_dir,
        "--no-git",
        "--report-format",
        "json",
        "--report-path",
        report_path,
        "--exit-code",
        "0",
        "--redact",
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return [], "gitleaks timed out"
    raw = ""
    try:
        with open(report_path, "r", encoding="utf-8") as report:
            raw = report.read().strip()
    except OSError:
        raw = (proc.stdout or "").strip()
    if not raw:
        if proc.returncode not in (0, 1):
            return [], (proc.stderr or "gitleaks failed")[-1000:]
        return [], None
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return data, None
        if isinstance(data, dict):
            return [data], None
    except json.JSONDecodeError:
        pass
    # Some versions write one JSON object per line
    findings: List[Dict[str, Any]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return findings, None if findings else "could not parse gitleaks JSON"


def _non_empty_regex_hits(blob: Dict[str, List[str]]) -> Dict[str, List[str]]:
    return {k: v for k, v in blob.items() if v}


def _safe_regex_hints(blob: Dict[str, List[str]]) -> Dict[str, List[Dict[str, Any]]]:
    """Preserve detector categories without returning discovered credentials."""
    return {
        kind: [secret_descriptor(value) for value in values]
        for kind, values in blob.items()
        if values
    }


def _safe_client_signing_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Remove reconstructed values/property fragments from agent-visible output."""
    raw = finding.get("reconstructed") or ""
    safe = {
        key: finding.get(key)
        for key in (
            "kind", "role", "severity", "cwe", "source_url", "object_name",
            "object_ref", "reconstruction", "usage", "offset",
            "joined_in_bundle", "ics_signals", "note",
        )
        if finding.get(key) not in (None, "", [])
    }
    safe["source_url"] = safe_source_url(safe.get("source_url"))
    safe.update(secret_descriptor(raw))
    return safe


def _safe_gitleaks_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize Gitleaks output to a persistence-safe evidence record."""
    raw = (
        finding.get("Secret")
        or finding.get("secret")
        or finding.get("Match")
        or finding.get("match")
        or ""
    )
    safe = {
        key: finding.get(key)
        for key in (
            "RuleID", "Description", "StartLine", "EndLine", "File",
            "SymlinkFile", "Commit", "Author", "Email", "Date", "Message",
            "Tags", "Fingerprint", "source_url",
        )
        if finding.get(key) not in (None, "", [])
    }
    if safe.get("File"):
        safe["File"] = os.path.basename(str(safe["File"]))
    safe.update(secret_descriptor(raw))
    safe["source_url"] = safe_source_url(safe.get("source_url"))
    if finding.get("Fingerprint"):
        safe["fingerprint"] = finding["Fingerprint"]
        safe["redacted"] = "[REDACTED by Gitleaks]"
        safe.pop("length", None)
    else:
        safe["fingerprint"] = secret_fingerprint(raw)
    return safe


def scan_js_urls_for_secrets(
    urls: str,
    max_urls: int = 30,
    max_bytes: int = DEFAULT_MAX_BYTES,
    timeout: float = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    """
    Download each URL, write to a temp dir, run gitleaks --no-git, add regex hints per file.

    Args:
        urls: Newline or comma separated http(s) URLs.
        max_urls: Cap number of URLs.
        max_bytes: Max response body per URL.
        timeout: Per-request timeout (seconds).

    Returns:
        Dict with success, urls_scanned, downloads (per-URL status), gitleaks_findings,
        regex_hints (by URL), client_signing_findings (CWE-321 Object.keys HMAC /
        MQTT / RFID), errors.
    """
    parsed = _parse_url_list(urls)[: max(1, min(max_urls, 100))]
    if not parsed:
        return {
            "success": False,
            "error": "No valid http(s) URLs in input",
            "urls_scanned": 0,
            "gitleaks_findings": [],
            "regex_hints": [],
            "client_signing_findings": [],
            "downloads": [],
        }

    ks = KatanaService()
    downloads: List[Dict[str, Any]] = []
    regex_hints: List[Dict[str, Any]] = []
    client_signing: List[Dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="js_secrets_") as tmp:
        files_dir = f"{tmp}/files"
        os.makedirs(files_dir, exist_ok=True)
        with httpx.Client(headers={"User-Agent": "JudahSecurity-JS-Secrets/1.0"}) as client:
            for url in parsed:
                body, err, meta = _fetch_url(client, url, max_bytes, timeout)
                if err or body is None:
                    downloads.append({"url": url, "ok": False, "error": err or "empty"})
                    continue
                fname = _safe_filename(url)
                path = f"{files_dir}/{fname}"
                try:
                    with open(path, "wb") as f:
                        f.write(body)
                except OSError as e:
                    downloads.append({"url": url, "ok": False, "error": str(e)})
                    continue
                text = body.decode("utf-8", errors="replace")
                hints = _non_empty_regex_hits(ks.extract_secrets_from_js(text))
                if hints:
                    regex_hints.append({"url": url, "hints": _safe_regex_hints(hints)})
                signing = analyze_js_client_secrets(text, source_url=url)
                if signing:
                    client_signing.extend(signing)
                downloads.append(
                    {
                        "url": url,
                        "ok": True,
                        "bytes": len(body),
                        "file": fname,
                        "truncated": bool(meta.get("truncated")),
                        "range_tail": bool(meta.get("range_tail")),
                        "content_length": meta.get("content_length"),
                        "client_signing_hits": len(signing),
                    }
                )

        name_to_url: Dict[str, str] = {}
        for d in downloads:
            if d.get("ok") and d.get("url") and d.get("file"):
                name_to_url[d["file"]] = d["url"]

        gl, gl_err = _run_gitleaks_no_git(files_dir, timeout=300)
        for finding in gl:
            fn = finding.get("File") or finding.get("file") or ""
            base = fn.split("/")[-1] if fn else ""
            if base in name_to_url:
                finding["source_url"] = name_to_url[base]

    signing_summary = summarize_client_signing_findings(client_signing)
    # Signing hits first so 20k tool-output truncation cannot drop CWE-321.
    out: Dict[str, Any] = {
        "success": True,
        "client_signing_summary": signing_summary,
        "client_signing_findings": [
            _safe_client_signing_finding(f) for f in client_signing
        ],
        "urls_requested": len(parsed),
        "urls_scanned": sum(1 for d in downloads if d.get("ok")),
        "downloads": downloads,
        "gitleaks_findings": [_safe_gitleaks_finding(f) for f in gl[:40]],
        "gitleaks_error": gl_err,
        "regex_hints": regex_hints[:20],
    }
    if signing_summary.get("submit_without_live_api"):
        out["guidance"] = (
            "CWE-321/CWE-798 client secrets reconstructed from a public bundle. "
            "submit_finding_candidate NOW as Critical. Live API/MQTT accept is "
            "optional extra proof; timeout or unreachable backend is NOT a kill. "
            "queue_finding_followups(vuln_type='js_secrets'). "
            "OAuth client_secret still needs a live read; HMAC/ICS do not."
        )
    if gl_err and not gl:
        out["note"] = gl_err
    return out


def persist_js_url_secret_findings(
    db,
    organization_id: int,
    scan_id: Optional[int],
    result: Dict[str, Any],
) -> int:
    """Persist safe Gitleaks, regex, and structural JS-secret evidence."""
    from app.models.asset import Asset, AssetType
    from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus

    now = datetime.utcnow()
    created = 0
    records: List[Dict[str, Any]] = []

    for finding in result.get("gitleaks_findings") or []:
        records.append({
            "source_url": safe_source_url(finding.get("source_url") or ""),
            "kind": finding.get("RuleID") or "gitleaks",
            "severity": "high",
            "fingerprint": finding.get("fingerprint") or "",
            "evidence": finding,
        })
    for group in result.get("regex_hints") or []:
        for kind, hints in (group.get("hints") or {}).items():
            for hint in hints or []:
                records.append({
                    "source_url": safe_source_url(group.get("url") or ""),
                    "kind": f"regex.{kind}",
                    "severity": "high",
                    "fingerprint": hint.get("fingerprint") or "",
                    "evidence": hint,
                })
    for finding in result.get("client_signing_findings") or []:
        records.append({
            "source_url": safe_source_url(finding.get("source_url") or ""),
            "kind": finding.get("kind") or "structural_secret",
            "severity": finding.get("severity") or "critical",
            "fingerprint": finding.get("fingerprint") or "",
            "evidence": finding,
        })

    severity_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }
    touched_urls: List[str] = []
    for record in records:
        source_url = str(record["source_url"] or "")
        hostname = urlparse(source_url).netloc or source_url or "unknown-js-source"
        asset = (
            db.query(Asset)
            .filter(Asset.organization_id == organization_id, Asset.value == hostname)
            .first()
        )
        if not asset:
            asset = Asset(
                organization_id=organization_id,
                asset_type=AssetType.DOMAIN,
                name=hostname,
                value=hostname,
                discovery_source="js_secret_scan",
            )
            db.add(asset)
            db.flush()

        stable = record["fingerprint"] or secret_descriptor(
            f"{record['kind']}:{source_url}"
        )["fingerprint"]
        stable_material = f"{record['kind']}:{stable}"
        template_hash = hashlib.sha256(stable_material.encode()).hexdigest()[:16]
        template_id = f"js-secret-{template_hash}"
        existing = (
            db.query(Vulnerability)
            .filter(
                Vulnerability.asset_id == asset.id,
                Vulnerability.template_id == template_id,
            )
            .first()
        )
        evidence = {
            "kind": record["kind"],
            "source_url": source_url,
            "fingerprint": stable,
            "scanner_evidence": record["evidence"],
        }
        if existing:
            existing.last_detected = now
            existing.status = VulnerabilityStatus.OPEN
            existing.metadata_ = evidence
            existing.evidence = json.dumps(evidence)[:5000]
            continue

        db.add(Vulnerability(
            title=f"JavaScript Secret: {record['kind']}"[:500],
            description=(
                f"A secret candidate was detected in the public JavaScript asset "
                f"`{source_url}`. The credential value is intentionally redacted; "
                f"use fingerprint `{stable}` for correlation. Treat browser-shipped "
                f"credentials as exposed and rotate after validation."
            )[:4000],
            severity=severity_map.get(str(record["severity"]).lower(), Severity.HIGH),
            asset_id=asset.id,
            scan_id=scan_id,
            detected_by="js_secret_scan",
            template_id=template_id,
            status=VulnerabilityStatus.OPEN,
            evidence=json.dumps(evidence)[:5000],
            tags=["javascript", "secret", "redacted"],
            metadata_=evidence,
            remediation=(
                "Rotate the credential, remove it from browser-delivered code, and "
                "move privileged operations behind a server-side service."
            ),
            last_detected=now,
        ))
        created += 1
        if source_url:
            touched_urls.append(source_url)

    if touched_urls:
        try:
            from app.services.sitemap_service import mark_secrets_on_urls
            mark_secrets_on_urls(db, organization_id, touched_urls, source="js_secret_scan")
        except Exception:
            pass
    db.commit()
    return created
