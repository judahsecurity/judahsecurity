"""
Detect vulnerable JavaScript libraries with Retire.js.

Retire.js only scans local files, so this service downloads web-accessible JS
bundles (typically the URLs surfaced by katana / deep_crawl / gau) into a temp
directory and runs `retire --js --jspath <dir> --outputformat json` over them.
Each finding is mapped back to its source URL so the agent knows exactly which
bundle shipped the vulnerable component (e.g. jQuery 1.8.2, AngularJS 1.5.x).

This complements scan_js_urls_for_secrets (which hunts hardcoded secrets in the
same bundles) — same input, different lens: known-CVE component detection.
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

logger = logging.getLogger(__name__)

DEFAULT_MAX_BYTES = 5 * 1024 * 1024
DEFAULT_TIMEOUT = 35.0


def _parse_url_list(urls: str) -> List[str]:
    if not urls or not str(urls).strip():
        return []
    out: List[str] = []
    for line in str(urls).replace(",", "\n").split("\n"):
        u = line.strip()
        if u.startswith("http://") or u.startswith("https://"):
            out.append(u)
    seen = set()
    unique: List[str] = []
    for u in out:
        if u not in seen:
            seen.add(u)
            unique.append(u)
    return unique


def _safe_filename(url: str) -> str:
    """Preserve a .js suffix so retire's filename heuristics still fire."""
    h = hashlib.sha256(url.encode("utf-8")).hexdigest()[:20]
    tail = url.split("?")[0].rstrip("/").split("/")[-1]
    if tail.lower().endswith(".js") and len(tail) <= 60:
        return f"{h}_{tail}"
    return f"{h}.js"


def _fetch_url(
    client: httpx.Client, url: str, max_bytes: int, timeout: float
) -> Tuple[Optional[bytes], Optional[str]]:
    try:
        with client.stream("GET", url, follow_redirects=True, timeout=timeout) as resp:
            if resp.status_code != 200:
                return None, f"HTTP {resp.status_code}"
            buf = bytearray()
            for chunk in resp.iter_bytes():
                buf.extend(chunk)
                if len(buf) > max_bytes:
                    return None, f"content exceeds max_bytes ({max_bytes})"
            return bytes(buf), None
    except Exception as e:
        return None, str(e)


def _run_retire(source_dir: str, timeout: int = 180) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Run retire.js over a directory of JS files, returning parsed results."""
    exe = shutil.which("retire")
    if not exe:
        return [], "retire binary not found in PATH (npm i -g retire)"
    out_path = os.path.join(source_dir, "_retire_report.json")
    cmd = [
        exe,
        "--js",
        "--jspath", source_dir,
        "--outputformat", "json",
        "--outputpath", out_path,
        # Never fail the process on findings; we read the JSON report instead.
        "--exitwith", "0",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return [], "retire timed out"
    except Exception as e:  # noqa: BLE001
        return [], f"retire failed to run: {e}"

    raw = ""
    if os.path.exists(out_path):
        try:
            with open(out_path, "r", encoding="utf-8", errors="ignore") as f:
                raw = f.read().strip()
        except OSError:
            raw = ""
    if not raw:
        # Older retire versions emit JSON on stdout.
        raw = (proc.stdout or "").strip()
    if not raw:
        err = (proc.stderr or "").strip()
        return [], err or None

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return [], "could not parse retire JSON report"

    # retire's JSON shape has drifted across versions. Normalise to a flat list
    # of {file, results:[...]} entries.
    if isinstance(data, dict) and "data" in data:
        data = data.get("data") or []
    if isinstance(data, dict):
        data = [data]
    return (data if isinstance(data, list) else []), None


def _summarize(entries: List[Dict[str, Any]], name_to_url: Dict[str, str]) -> List[Dict[str, Any]]:
    """Flatten retire results into vulnerable-component findings with source URLs."""
    findings: List[Dict[str, Any]] = []
    for entry in entries:
        fpath = entry.get("file") or entry.get("File") or ""
        base = fpath.split("/")[-1] if fpath else ""
        source_url = name_to_url.get(base)
        for res in entry.get("results", []) or []:
            vulns = res.get("vulnerabilities") or []
            if not vulns:
                continue
            for v in vulns:
                ident = v.get("identifiers", {}) or {}
                findings.append({
                    "component": res.get("component"),
                    "version": res.get("version"),
                    "severity": v.get("severity"),
                    "cve": ident.get("CVE") or ident.get("cve"),
                    "summary": ident.get("summary"),
                    "info": v.get("info"),
                    "source_url": source_url,
                })
    return findings


def scan_js_urls_for_vulns(
    urls: str,
    max_urls: int = 30,
    max_bytes: int = DEFAULT_MAX_BYTES,
    timeout: float = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    """
    Download each JS URL, write to a temp dir, run retire.js, map findings to URLs.

    Args:
        urls: Newline- or comma-separated http(s) URLs (typically .js bundles).
        max_urls: Cap number of URLs (1..100).
        max_bytes: Max response body per URL.
        timeout: Per-request timeout (seconds).

    Returns:
        Dict with success, urls_scanned, downloads (per-URL status),
        vulnerable_components (flattened findings), raw_results, errors.
    """
    parsed = _parse_url_list(urls)[: max(1, min(max_urls, 100))]
    if not parsed:
        return {
            "success": False,
            "error": "No valid http(s) URLs in input",
            "urls_scanned": 0,
            "vulnerable_components": [],
            "downloads": [],
        }

    downloads: List[Dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="retirejs_") as tmp:
        files_dir = os.path.join(tmp, "files")
        os.makedirs(files_dir, exist_ok=True)
        with httpx.Client(headers={"User-Agent": "JudahSecurity-RetireJS/1.0"}) as client:
            for url in parsed:
                body, err = _fetch_url(client, url, max_bytes, timeout)
                if err or body is None:
                    downloads.append({"url": url, "ok": False, "error": err or "empty"})
                    continue
                fname = _safe_filename(url)
                path = os.path.join(files_dir, fname)
                try:
                    with open(path, "wb") as f:
                        f.write(body)
                except OSError as e:
                    downloads.append({"url": url, "ok": False, "error": str(e)})
                    continue
                downloads.append({"url": url, "ok": True, "bytes": len(body), "file": fname})

        name_to_url: Dict[str, str] = {
            d["file"]: d["url"] for d in downloads if d.get("ok") and d.get("file")
        }

        entries, err = _run_retire(files_dir, timeout=int(timeout) + 200)

    vulnerable = _summarize(entries, name_to_url)
    out: Dict[str, Any] = {
        "success": True,
        "urls_requested": len(parsed),
        "urls_scanned": sum(1 for d in downloads if d.get("ok")),
        "downloads": downloads,
        "vulnerable_components": vulnerable,
        "vulnerable_count": len(vulnerable),
        "raw_results": entries,
        "retire_error": err,
    }
    if err and not entries:
        out["note"] = err
    return out
