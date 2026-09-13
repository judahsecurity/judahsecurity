"""Organization-scoped, redacted Shadowserver report aggregation."""

from __future__ import annotations

import hashlib
import hmac
import csv
import io
import json
import logging
import os
import re
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.models.api_config import APIConfig, ExternalService

logger = logging.getLogger(__name__)

REPORT_TYPE = "event4_honeypot_http_scan"
REPORT_SCHEMA_VERSION = 1
DEFAULT_API_URI = "https://transform.shadowserver.org/api2/"
REPORT_SOURCE_URL = "https://www.shadowserver.org/what-we-do/network-reporting/honeypot-http-scanner-events/"
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
_SAFE_TAG_RE = re.compile(r"^[a-z0-9][a-z0-9_.:+-]{0,63}$", re.I)
_DOWNLOAD_ID_RE = re.compile(r"^[A-Za-z0-9_.?=&-]{1,512}$")
MAX_REPORT_FILES = 14
MAX_DOWNLOAD_BYTES = 20 * 1024 * 1024


def _cache_path(organization_id: int) -> Path:
    root = Path(os.environ.get("EXPLOIT_INTEL_CACHE_DIR") or os.environ.get("DELPHI_CACHE_DIR") or "/tmp/delphi_cache")
    root.mkdir(parents=True, exist_ok=True)
    return root / f"shadowserver_org_{int(organization_id)}_cve.json"


def build_signed_request(api_key: str, api_secret: str, payload: dict[str, Any]) -> tuple[bytes, dict[str, str]]:
    """Build the official HMAC2 JSON request. The secret is never serialized."""
    body = dict(payload)
    body["apikey"] = api_key
    encoded = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature = hmac.new(api_secret.encode("utf-8"), encoded, hashlib.sha256).hexdigest()
    return encoded, {"Content-Type": "application/json", "Accept": "application/json", "HMAC2": signature,
                     "User-Agent": "judahsecurity-shadowserver/1.0"}


def _timestamp(value: Any) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_tags(value: Any) -> list[str]:
    values = value if isinstance(value, list) else re.split(r"[;,]", str(value or ""))
    return sorted({str(tag).strip().lower() for tag in values if _SAFE_TAG_RE.fullmatch(str(tag).strip())})[:20]


def parse_honeypot_http_rows(rows: list[dict[str, Any]], *, retrieved_at: str) -> dict[str, dict[str, Any]]:
    """Reduce subscriber rows to safe CVE-level facts and discard all raw identifiers/content."""
    aggregates: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        enum = str(row.get("vulnerability_enum") or "").strip().upper()
        raw_ids = str(row.get("vulnerability_id") or "")
        cves = {match.group(0).upper() for match in _CVE_RE.finditer(raw_ids)}
        if enum and enum != "CVE" and not cves:
            continue
        seen = _timestamp(row.get("timestamp"))
        if not seen:
            continue
        for cve in cves:
            item = aggregates.setdefault(cve, {
                "cve_id": cve, "first_seen": seen, "last_seen": seen, "sighting_count": 0,
                "observation_days": 0,
                "report_type": REPORT_TYPE, "schema_version": REPORT_SCHEMA_VERSION,
                "vendors": [], "products": [], "tags": [], "retrieved_at": retrieved_at,
                "canonical_url": REPORT_SOURCE_URL, "confidence": "high",
                "telemetry_class": "observed_exploitation_attempt",
                "successful_compromise": False,
            })
            item["first_seen"] = min(item["first_seen"], seen)
            item["last_seen"] = max(item["last_seen"], seen)
            item["sighting_count"] += 1
            dates = set(item.pop("_observation_dates", []))
            dates.add(seen[:10])
            item["_observation_dates"] = sorted(dates)
            item["observation_days"] = len(dates)
            vendor = str(row.get("target_vendor") or "").strip()
            product = str(row.get("target_product") or "").strip()
            if vendor and vendor not in item["vendors"] and len(item["vendors"]) < 10:
                item["vendors"].append(vendor[:128])
            if product and product not in item["products"] and len(item["products"]) < 10:
                item["products"].append(product[:128])
            item["tags"] = sorted(set(item["tags"]) | set(_safe_tags(row.get("session_tags"))))[:20]
    for item in aggregates.values():
        item.pop("_observation_dates", None)
    return aggregates


def _credentials(db: Session, organization_id: int) -> tuple[APIConfig | None, str, str, str]:
    config = db.query(APIConfig).filter(
        APIConfig.organization_id == organization_id,
        APIConfig.service_name == ExternalService.SHADOWSERVER,
        APIConfig.is_active == True,
    ).first()
    if not config:
        return None, "", "", DEFAULT_API_URI
    uri = str((config.config or {}).get("api_uri") or DEFAULT_API_URI)
    if not uri.startswith("https://transform.shadowserver.org/api2/"):
        uri = DEFAULT_API_URI
    return config, config.get_api_key() or "", config.get_api_secret() or "", uri.rstrip("/") + "/"


def refresh_shadowserver_cache(db: Session, organization_id: int, *, days: int = 2, limit: int = 1000,
                               opener=urllib.request.urlopen) -> dict[str, Any]:
    """List the subscribed report type, parse bounded CSVs in memory, and persist aggregates."""
    days = max(1, min(int(days), 7))
    limit = max(1, min(int(limit), 1000))
    config, api_key, api_secret, uri = _credentials(db, organization_id)
    if not config or not api_key or not api_secret:
        return {"status": "disabled", "configured": False, "error": "Shadowserver key and secret are required"}
    end = datetime.now(timezone.utc).date()
    start = end - timedelta(days=days - 1)
    payload = {
        "date": f"{start.isoformat()}:{end.isoformat()}",
        "type": REPORT_TYPE,
        "limit": MAX_REPORT_FILES,
    }
    body, headers = build_signed_request(api_key, api_secret, payload)
    request = urllib.request.Request(uri + "reports/list", data=body, headers=headers, method="POST")
    cache_path = _cache_path(organization_id)
    try:
        with opener(request, timeout=45) as response:  # nosec - fixed allowlisted HTTPS endpoint
            raw = response.read()
        report_rows = json.loads(raw.decode("utf-8", errors="replace"))
        if not isinstance(report_rows, list):
            raise ValueError("unexpected Shadowserver response")
        reports = [
            row for row in report_rows
            if isinstance(row, dict)
            and row.get("type") in (None, REPORT_TYPE)
            and _DOWNLOAD_ID_RE.fullmatch(str(row.get("id") or ""))
        ][:MAX_REPORT_FILES]
        rows: list[dict[str, Any]] = []
        downloaded_bytes = 0
        for report in reports:
            download = urllib.request.Request(
                "https://dl.shadowserver.org/" + str(report["id"]),
                headers={"Accept": "text/csv", "User-Agent": "judahsecurity-shadowserver/1.0"},
            )
            with opener(download, timeout=45) as response:  # nosec - fixed host, validated opaque ID
                csv_bytes = response.read(min(MAX_DOWNLOAD_BYTES - downloaded_bytes + 1, MAX_DOWNLOAD_BYTES + 1))
            downloaded_bytes += len(csv_bytes)
            if downloaded_bytes > MAX_DOWNLOAD_BYTES:
                raise ValueError("Shadowserver report download exceeded byte limit")
            for row in csv.DictReader(io.StringIO(csv_bytes.decode("utf-8-sig", errors="replace"))):
                rows.append(dict(row))
                if len(rows) >= limit:
                    break
            if len(rows) >= limit:
                break
        retrieved_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        aggregates = parse_honeypot_http_rows(rows, retrieved_at=retrieved_at)
        payload_out = {"schema_version": REPORT_SCHEMA_VERSION, "organization_id": organization_id,
                       "retrieved_at": retrieved_at, "window_days": days, "limited": len(rows) >= limit,
                       "report_type": REPORT_TYPE, "cves": aggregates}
        fd, temp_path = tempfile.mkstemp(prefix=f".{cache_path.name}.", dir=str(cache_path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload_out, handle, separators=(",", ":"), sort_keys=True)
            os.replace(temp_path, cache_path)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
        config.increment_usage()
        config.is_valid = True
        config.last_error = None
        db.commit()
        return {"status": "ok", "configured": True, "retrieved_at": retrieved_at,
                "cve_count": len(aggregates), "row_count": len(rows), "report_count": len(reports),
                "limited": len(rows) >= limit}
    except urllib.error.HTTPError as exc:
        status = "rate_limited" if exc.code == 429 else "unavailable"
        if exc.code in {401, 403}:
            config.is_valid = False
        config.last_error = f"Shadowserver refresh failed: HTTP {exc.code}"
        db.commit()
        logger.warning("Shadowserver report refresh returned HTTP %s for organization %s", exc.code, organization_id)
        return {"status": status, "configured": True, "cached": cache_path.exists(), "http_status": exc.code}
    except Exception as exc:
        config.last_error = f"Shadowserver refresh failed: {type(exc).__name__}"
        db.commit()
        logger.warning("Shadowserver report refresh failed for organization %s: %s", organization_id, type(exc).__name__)
        return {"status": "unavailable", "configured": True, "cached": cache_path.exists(),
                "error": type(exc).__name__}


def shadowserver_cve_signal(db: Session, organization_id: int | None, cve_id: str, *, stale_hours: int = 48) -> dict[str, Any]:
    """Read the tenant's redacted cache only; never fetch reports in a CVE request."""
    if organization_id is None:
        return {"status": "disabled", "configured": False, "found": False, "source": "shadowserver_reports"}
    config, api_key, api_secret, _ = _credentials(db, organization_id)
    if not config or not api_key or not api_secret:
        return {"status": "disabled", "configured": False, "found": False, "source": "shadowserver_reports",
                "canonical_url": REPORT_SOURCE_URL, "confidence": "unknown"}
    path = _cache_path(organization_id)
    if not path.exists():
        return {"status": "unavailable", "configured": True, "found": False, "source": "shadowserver_reports",
                "canonical_url": REPORT_SOURCE_URL, "confidence": "unknown", "error": "cache not refreshed"}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        stale = (time.time() - path.stat().st_mtime) > stale_hours * 3600
        signal = dict((payload.get("cves") or {}).get(cve_id.upper()) or {})
        return {"source": "shadowserver_reports", "status": "stale" if stale else "ok",
                "configured": True, "found": bool(signal), "stale": stale,
                "retrieved_at": payload.get("retrieved_at"), "canonical_url": REPORT_SOURCE_URL,
                "confidence": "medium" if stale else "high", "error": None, **signal}
    except Exception as exc:
        return {"source": "shadowserver_reports", "status": "unavailable", "configured": True,
                "found": False, "canonical_url": REPORT_SOURCE_URL, "confidence": "unknown",
                "error": f"invalid cache: {type(exc).__name__}"}
