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
from typing import Any, Dict, List, Optional, Tuple

import httpx

from app.services.js_client_signing_secrets import (
    analyze_js_client_secrets,
    summarize_client_signing_findings,
)
from app.services.katana_service import KatanaService

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
    cmd = [
        exe,
        "detect",
        "--source",
        source_dir,
        "--no-git",
        "--report-format",
        "json",
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
    raw = (proc.stdout or "").strip()
    if not raw:
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
                    regex_hints.append({"url": url, "hints": hints})
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
    out: Dict[str, Any] = {
        "success": True,
        "urls_requested": len(parsed),
        "urls_scanned": sum(1 for d in downloads if d.get("ok")),
        "downloads": downloads,
        "gitleaks_findings": gl,
        "gitleaks_error": gl_err,
        "regex_hints": regex_hints,
        "client_signing_findings": client_signing,
        "client_signing_summary": signing_summary,
    }
    if signing_summary.get("submit_without_live_api"):
        out["guidance"] = (
            "CWE-321/CWE-798 client secrets reconstructed from a public bundle. "
            "submit_finding_candidate now. Live API/MQTT accept is optional extra "
            "proof; timeout or unreachable backend is NOT a kill. "
            "queue_finding_followups(vuln_type='js_secrets')."
        )
    if gl_err and not gl:
        out["note"] = gl_err
    return out
