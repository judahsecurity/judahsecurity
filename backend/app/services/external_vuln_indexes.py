"""Cached metadata indexes for VulnCheck exploits and public Nuclei CVEs.

Only metadata is retained.  Exploit source code, payloads, and template YAML are
never downloaded into the application cache.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import re
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

logger = logging.getLogger(__name__)

NUCLEI_CVE_INDEX_URL = (
    "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json"
)
NUCLEI_CVE_CHECKSUM_URL = (
    "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/"
    "cves.json-checksum.txt"
)
NUCLEI_REPOSITORY_URL = "https://github.com/projectdiscovery/nuclei-templates"
VULNCHECK_EXPLOITS_BACKUP_URL = "https://api.vulncheck.com/v3/backup/exploits"
VULNCHECK_EXPLOITS_URL = "https://api.vulncheck.com/v3/index/exploits"

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
_SAFE_TEMPLATE_PATH_RE = re.compile(r"^[a-zA-Z0-9_.\-/]+\.ya?ml$")
_MATURITY_MAP = {
    "poc": "proof_of_concept",
    "proof-of-concept": "proof_of_concept",
    "proof_of_concept": "proof_of_concept",
    "functional": "public_working_exploit",
    "working": "public_working_exploit",
    "public_working_exploit": "public_working_exploit",
    "weaponized": "weaponized_turnkey",
    "weaponized_turnkey": "weaponized_turnkey",
}


def _cache_dir() -> Path:
    path = Path(
        os.environ.get("EXPLOIT_INTEL_CACHE_DIR")
        or os.environ.get("DELPHI_CACHE_DIR")
        or "/tmp/delphi_cache"
    )
    path.mkdir(parents=True, exist_ok=True)
    return path


def _cache_path(source: str) -> Path:
    return _cache_dir() / f"{source}_cve_index.json"


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _atomic_write(path: Path, payload: dict[str, Any]) -> None:
    fd, temp_path = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, separators=(",", ":"), sort_keys=True)
        os.replace(temp_path, path)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def _download(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: int = 90,
) -> bytes:
    request_headers = {
        "User-Agent": "judahsecurity-external-vuln-indexes/1.0",
        "Accept": "application/json,text/plain,application/zip",
    }
    request_headers.update(headers or {})
    request = urllib.request.Request(url, headers=request_headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310 - fixed URLs
        return response.read()


def _fresh(path: Path, refresh_hours: int) -> bool:
    return path.exists() and (time.time() - path.stat().st_mtime) < refresh_hours * 3600


def _canonical_cve(value: Any) -> str:
    match = _CVE_RE.search(str(value or ""))
    return match.group(0).upper() if match else ""


def _safe_https_url(value: Any) -> str | None:
    url = str(value or "").strip()
    return url if url.startswith("https://") else None


def parse_nuclei_cve_index(raw: bytes | str) -> dict[str, list[dict[str, Any]]]:
    """Parse ProjectDiscovery's generated NDJSON CVE index."""
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
    index: dict[str, list[dict[str, Any]]] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid Nuclei CVE index line {line_number}") from exc
        if not isinstance(row, dict):
            continue
        cve_id = _canonical_cve(row.get("ID"))
        path = str(row.get("file_path") or "").strip()
        if not cve_id or not _SAFE_TEMPLATE_PATH_RE.fullmatch(path) or ".." in path.split("/"):
            continue
        info = row.get("Info") if isinstance(row.get("Info"), dict) else {}
        classification = (
            info.get("Classification")
            if isinstance(info.get("Classification"), dict)
            else {}
        )
        template = {
            "template_id": str(row.get("ID") or cve_id),
            "name": str(info.get("Name") or cve_id),
            "severity": str(info.get("Severity") or "unknown").lower(),
            "description": str(info.get("Description") or "")[:2000],
            "cvss_score": classification.get("CVSSScore"),
            "file_path": path,
            "canonical_url": f"{NUCLEI_REPOSITORY_URL}/blob/main/{path}",
        }
        index.setdefault(cve_id, []).append(template)
    return index


def refresh_nuclei_cve_index(
    *, force: bool = False, refresh_hours: float = 24
) -> dict[str, Any]:
    """Refresh the public Nuclei CVE-to-template index and verify its checksum."""
    path = _cache_path("nuclei")
    if not force and _fresh(path, refresh_hours):
        return {"status": "fresh", "cached": True, "cves": _cached_count(path)}
    try:
        raw = _download(NUCLEI_CVE_INDEX_URL)
        checksum_raw = _download(NUCLEI_CVE_CHECKSUM_URL, timeout=30).decode(
            "utf-8", errors="replace"
        )
        expected = checksum_raw.strip().split()[0].lower() if checksum_raw.strip() else ""
        actual = hashlib.sha256(raw).hexdigest()
        # ProjectDiscovery currently publishes an MD5 value in this legacy
        # checksum file; accept either that format or a future SHA-256 value.
        checksum_actual = hashlib.md5(raw).hexdigest() if len(expected) == 32 else actual  # nosec B324
        if expected and expected != checksum_actual:
            raise ValueError("Nuclei cves.json checksum mismatch")
        entries = parse_nuclei_cve_index(raw)
        if not entries:
            raise ValueError("Nuclei cves.json contained no CVE templates")
        fetched_at = _utcnow()
        _atomic_write(
            path,
            {
                "schema_version": 1,
                "source": "projectdiscovery_nuclei",
                "source_url": NUCLEI_CVE_INDEX_URL,
                "source_sha256": actual,
                "source_checksum": expected or checksum_actual,
                "fetched_at": fetched_at,
                "entries": entries,
            },
        )
        return {
            "status": "fresh",
            "cached": True,
            "cves": len(entries),
            "fetched_at": fetched_at,
        }
    except Exception as exc:
        logger.warning("Nuclei CVE index refresh failed: %s", type(exc).__name__)
        return {
            "status": "stale" if path.exists() else "unavailable",
            "cached": path.exists(),
            "cves": _cached_count(path),
            "error": type(exc).__name__,
        }


def _iter_json_rows(raw: bytes) -> Iterable[dict[str, Any]]:
    """Yield rows from JSON, NDJSON, or a VulnCheck backup zip."""
    payloads: list[bytes] = []
    if zipfile.is_zipfile(io.BytesIO(raw)):
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            for name in archive.namelist():
                if name.lower().endswith((".json", ".jsonl", ".ndjson")):
                    payloads.append(archive.read(name))
    else:
        payloads.append(raw)

    for content in payloads:
        try:
            payload = json.loads(content.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            for line in content.decode("utf-8", errors="replace").splitlines():
                if not line.strip():
                    continue
                row = json.loads(line)
                if isinstance(row, dict):
                    yield row
            continue
        if isinstance(payload, list):
            rows = payload
        elif isinstance(payload, dict):
            rows = payload.get("data") or payload.get("entries") or payload.get("exploits") or []
        else:
            rows = []
        for row in rows:
            if isinstance(row, dict):
                yield row


def _artifact_id(cve_id: str, artifact: dict[str, Any], url: str | None) -> str:
    xdb_id = str(artifact.get("xdb_id") or "").strip()
    if xdb_id:
        return f"vulncheck-xdb:{xdb_id}"
    identity = url or str(artifact.get("name") or artifact.get("id") or cve_id)
    digest = hashlib.sha256(identity.encode("utf-8", errors="replace")).hexdigest()[:16]
    return f"vulncheck:{digest}"


def parse_vulncheck_exploits(
    rows: Iterable[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Normalize safe fields from VulnCheck's aggregate ``exploits`` index."""
    index: dict[str, dict[str, Any]] = {}
    for row in rows:
        cve_id = _canonical_cve(row.get("id") or row.get("cve"))
        if not cve_id:
            continue
        artifacts: list[dict[str, Any]] = []
        raw_artifacts = row.get("exploits") if isinstance(row.get("exploits"), list) else []
        # Community XDB exports can also be a flat record.
        if row.get("xdb_id"):
            raw_artifacts = [row]
        for raw_artifact in raw_artifacts:
            if not isinstance(raw_artifact, dict):
                continue
            url = _safe_https_url(
                raw_artifact.get("xdb_url")
                or raw_artifact.get("url")
                or raw_artifact.get("canonical_url")
            )
            raw_maturity = str(raw_artifact.get("exploit_maturity") or "poc").lower()
            maturity = _MATURITY_MAP.get(raw_maturity, "proof_of_concept")
            validation = str(raw_artifact.get("validation_level") or "uncategorized")
            confidence = (
                "high"
                if validation.startswith("vulncheck-") or validation == "third-party-validated"
                else "medium"
                if validation == "third-party-aggregated"
                else "low"
            )
            artifacts.append(
                {
                    "artifact_id": _artifact_id(cve_id, raw_artifact, url),
                    "source": "vulncheck_xdb" if raw_artifact.get("xdb_id") else "vulncheck",
                    "title": str(raw_artifact.get("name") or raw_artifact.get("xdb_id") or cve_id),
                    "canonical_url": url,
                    "published_at": raw_artifact.get("date_added") or raw_artifact.get("published_at"),
                    "source_timestamp": raw_artifact.get("date_added"),
                    "maturity": maturity,
                    "exploit_type": raw_artifact.get("exploit_type"),
                    "exploit_availability": raw_artifact.get("exploit_availability") or "publicly-available",
                    "validation_level": validation,
                    "confidence": confidence,
                }
            )
        timeline = row.get("timeline") if isinstance(row.get("timeline"), dict) else {}
        epss = row.get("epss") if isinstance(row.get("epss"), dict) else {}
        exploit_types = sorted(
            {
                str(item.get("exploit_type")).strip().lower()
                for item in raw_artifacts
                if isinstance(item, dict) and item.get("exploit_type")
            }
        )
        is_remote = any(
            value in {"initial-access", "remote", "remote-with-credentials", "remote with credentials"}
            for value in exploit_types
        )
        index[cve_id] = {
            "cve_id": cve_id,
            "public_exploit_found": bool(row.get("public_exploit_found") or artifacts),
            "commercial_exploit_found": bool(row.get("commercial_exploit_found")),
            "weaponized_exploit_found": bool(row.get("weaponized_exploit_found")),
            "max_exploit_maturity": row.get("max_exploit_maturity"),
            "reported_exploited": bool(row.get("reported_exploited")),
            "in_cisa_kev": bool(row.get("inKEV") or row.get("in_kev")),
            "in_vulncheck_kev": bool(row.get("inVCKEV") or row.get("in_vckev")),
            "exploit_types": exploit_types,
            "is_remote": is_remote,
            "timeline": timeline,
            "epss_score": epss.get("epss_score"),
            "epss_percentile": epss.get("epss_percentile"),
            "artifacts": artifacts,
        }
    return index


def refresh_vulncheck_exploit_index(
    token: str,
    *,
    force: bool = False,
    refresh_hours: float = 24,
) -> dict[str, Any]:
    """Refresh VulnCheck exploit/XDB metadata.

    The initial load uses the supported backup API. Warm caches use the
    paginated index endpoint with a one-day overlap on ``_timestamp`` so newly
    published and updated exploit records arrive without repeatedly downloading
    the full corpus.
    """
    path = _cache_path("vulncheck_exploits")
    if not token:
        return {
            "status": "stale" if path.exists() else "unavailable",
            "cached": path.exists(),
            "cves": _cached_count(path),
            "error": "missing_token",
        }
    if not force and _fresh(path, refresh_hours):
        return {"status": "fresh", "cached": True, "cves": _cached_count(path)}
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    try:
        cached_payload, _ = _read_cache("vulncheck_exploits")
        cached_entries = (
            dict(cached_payload.get("entries") or {})
            if isinstance(cached_payload.get("entries"), dict)
            else {}
        )
        if cached_entries and not force:
            fetched_at = str(cached_payload.get("fetched_at") or _utcnow())
            try:
                since = datetime.fromisoformat(fetched_at.replace("Z", "+00:00")) - timedelta(days=1)
            except ValueError:
                since = datetime.now(timezone.utc) - timedelta(days=2)
            rows: list[dict[str, Any]] = []
            cursor: str | None = None
            for _ in range(50):
                params: dict[str, Any] = {
                    "lastModStartDate": since.date().isoformat(),
                    "sort": "_timestamp",
                    "order": "asc",
                    "limit": 500,
                }
                params["cursor" if cursor else "start_cursor"] = cursor or "true"
                url = f"{VULNCHECK_EXPLOITS_URL}?{urllib.parse.urlencode(params)}"
                payload = json.loads(
                    _download(url, headers=headers).decode("utf-8", errors="replace")
                )
                if not isinstance(payload, dict):
                    raise ValueError("unexpected VulnCheck exploit index response")
                page_rows = payload.get("data") or []
                rows.extend(row for row in page_rows if isinstance(row, dict))
                meta = payload.get("_meta") or payload.get("meta") or {}
                cursor = str(meta.get("next_cursor") or "").strip() or None
                if not cursor or not page_rows:
                    break
            updates = parse_vulncheck_exploits(rows)
            cached_entries.update(updates)
            refreshed_at = _utcnow()
            _atomic_write(
                path,
                {
                    "schema_version": 1,
                    "source": "vulncheck_exploits",
                    "source_url": VULNCHECK_EXPLOITS_URL,
                    "mode": "incremental",
                    "fetched_at": refreshed_at,
                    "entries": cached_entries,
                },
            )
            return {
                "status": "fresh",
                "cached": True,
                "cves": len(cached_entries),
                "updated_cves": len(updates),
                "fetched_at": refreshed_at,
            }

        meta = json.loads(
            _download(VULNCHECK_EXPLOITS_BACKUP_URL, headers=headers).decode(
                "utf-8", errors="replace"
            )
        )
        candidates = meta.get("data") if isinstance(meta, dict) else []
        first = candidates[0] if isinstance(candidates, list) and candidates else {}
        backup_url = next(
            (
                _safe_https_url(first.get(key))
                for key in ("url", "url_direct", "url_us-east-1", "url_mrap")
                if first.get(key)
            ),
            None,
        )
        if not backup_url:
            raise ValueError("VulnCheck exploit backup metadata omitted a download URL")
        raw = _download(backup_url, timeout=180)
        entries = parse_vulncheck_exploits(_iter_json_rows(raw))
        if not entries:
            raise ValueError("VulnCheck exploit backup contained no CVE rows")
        fetched_at = _utcnow()
        _atomic_write(
            path,
            {
                "schema_version": 1,
                "source": "vulncheck_exploits",
                "source_url": VULNCHECK_EXPLOITS_URL,
                "mode": "backup",
                "fetched_at": fetched_at,
                "entries": entries,
            },
        )
        return {
            "status": "fresh",
            "cached": True,
            "cves": len(entries),
            "fetched_at": fetched_at,
        }
    except Exception as exc:
        logger.warning("VulnCheck exploit index refresh failed: %s", type(exc).__name__)
        return {
            "status": "stale" if path.exists() else "unavailable",
            "cached": path.exists(),
            "cves": _cached_count(path),
            "error": type(exc).__name__,
        }


def _read_cache(source: str) -> tuple[dict[str, Any], Path]:
    path = _cache_path(source)
    if not path.exists():
        return {}, path
    try:
        return json.loads(path.read_text(encoding="utf-8")), path
    except Exception:
        return {}, path


def _cached_count(path: Path) -> int:
    if not path.exists():
        return 0
    try:
        return len(json.loads(path.read_text(encoding="utf-8")).get("entries") or {})
    except Exception:
        return 0


def nuclei_coverage_for_cves(cve_ids: Iterable[str], *, stale_hours: int = 48) -> dict[str, dict[str, Any]]:
    payload, path = _read_cache("nuclei")
    entries = payload.get("entries") if isinstance(payload.get("entries"), dict) else {}
    available = bool(payload and path.exists())
    stale = available and (time.time() - path.stat().st_mtime) > stale_hours * 3600
    output: dict[str, dict[str, Any]] = {}
    for value in cve_ids:
        cve_id = _canonical_cve(value)
        if not cve_id:
            continue
        templates = list(entries.get(cve_id) or [])
        output[cve_id] = {
            "source": "projectdiscovery_nuclei",
            "status": "stale" if stale else "ok" if available else "unavailable",
            "available": available,
            "stale": stale,
            "retrieved_at": payload.get("fetched_at"),
            "canonical_url": NUCLEI_REPOSITORY_URL,
            "found": bool(templates),
            "template_count": len(templates),
            "templates": templates,
        }
    return output


def nuclei_coverage_for_cve(cve_id: str) -> dict[str, Any]:
    return nuclei_coverage_for_cves([cve_id]).get(_canonical_cve(cve_id), {})


def vulncheck_exploits_for_cves(
    cve_ids: Iterable[str], *, stale_hours: int = 48
) -> dict[str, dict[str, Any]]:
    payload, path = _read_cache("vulncheck_exploits")
    entries = payload.get("entries") if isinstance(payload.get("entries"), dict) else {}
    available = bool(payload and path.exists())
    stale = available and (time.time() - path.stat().st_mtime) > stale_hours * 3600
    output: dict[str, dict[str, Any]] = {}
    for value in cve_ids:
        cve_id = _canonical_cve(value)
        if not cve_id:
            continue
        record = dict(entries.get(cve_id) or {})
        artifacts = list(record.get("artifacts") or [])
        output[cve_id] = {
            **record,
            "source": "vulncheck_exploits",
            "status": "stale" if stale else "ok" if available else "unavailable",
            "available": available,
            "stale": stale,
            "retrieved_at": payload.get("fetched_at"),
            "canonical_url": f"https://www.vulncheck.com/xdb/?cve={cve_id}",
            "found": bool(record.get("public_exploit_found") or artifacts),
            "artifacts": artifacts,
        }
    return output


def vulncheck_exploits_for_cve(cve_id: str) -> dict[str, Any]:
    return vulncheck_exploits_for_cves([cve_id]).get(_canonical_cve(cve_id), {})


def external_index_status() -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for source in ("nuclei", "vulncheck_exploits"):
        payload, path = _read_cache(source)
        if not payload or not path.exists():
            output[source] = {"status": "unavailable", "cves": 0}
            continue
        stale = (time.time() - path.stat().st_mtime) > 48 * 3600
        output[source] = {
            "status": "stale" if stale else "ok",
            "cves": len(payload.get("entries") or {}),
            "retrieved_at": payload.get("fetched_at"),
        }
    return output
