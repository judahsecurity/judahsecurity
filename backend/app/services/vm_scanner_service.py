"""Vulnerability Management (VM) scanner integration service.

Read-only clients for the supported VM vendor APIs plus the sync logic that
imports scanned hosts and vulnerability detections into this platform.

Supported providers:

    tenable  Tenable Vulnerability Management (cloud.tenable.com)
             Auth: ``X-ApiKeys: accessKey=..; secretKey=..`` header.
             Assets via GET /workbenches/assets, per-asset findings via
             GET /workbenches/assets/{uuid}/vulnerabilities.

    qualys   Qualys VMDR (customer-specific API server, e.g.
             qualysapi.qualys.com). Auth: HTTP basic + ``X-Requested-With``.
             Host detections via GET /api/2.0/fo/asset/host/vm/detection/
             (XML, truncation-based pagination), titles enriched from the
             KnowledgeBase endpoint.

    rapid7   Rapid7 InsightVM (Insight platform, region API host, e.g.
             us.api.insight.rapid7.com). Auth: ``X-Api-Key`` header.
             Assets/findings/definitions via the /vm/v4/integration/* endpoints.

    nessus   Tenable Nessus (standalone scanner, https://host:8834).
             Auth: ``X-ApiKeys`` header. Findings read from the latest
             completed scan histories via /scans endpoints. Self-signed
             certificates are common, hence the per-connection verify_ssl.

Every client normalizes its output to the same shape so one import path
serves all vendors:

    host    {"value": "10.0.0.5" | "www.example.com", "metadata": {...}}
    finding {"asset_value": ..., "title": ..., "severity": Severity, ...}
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import httpx
from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetStatus, AssetType
from app.models.vm_scanner_integration import VmScannerIntegration
from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus

logger = logging.getLogger(__name__)

# ── Provider registry ─────────────────────────────────────────────────────────
# credential_fields drive validation here and the credential form in the UI.
PROVIDERS: Dict[str, Dict[str, Any]] = {
    "tenable": {
        "label": "Tenable Vulnerability Management",
        "default_base_url": "https://cloud.tenable.com",
        "base_url_required": False,
        "credential_fields": [
            {"key": "access_key", "label": "Access key", "secret": True},
            {"key": "secret_key", "label": "Secret key", "secret": True},
        ],
        "docs_url": "https://docs.tenable.com/vulnerability-management/Content/Settings/my-account/GenerateAPIKey.htm",
    },
    "qualys": {
        "label": "Qualys VMDR",
        "default_base_url": None,
        "base_url_required": True,  # platform-specific API server
        "base_url_hint": "Your Qualys API server, e.g. https://qualysapi.qualys.com",
        "credential_fields": [
            {"key": "username", "label": "Username", "secret": False},
            {"key": "password", "label": "Password", "secret": True},
        ],
        "docs_url": "https://docs.qualys.com/en/vm/api/",
    },
    "rapid7": {
        "label": "Rapid7 InsightVM",
        "default_base_url": "https://us.api.insight.rapid7.com",
        "base_url_required": False,
        "base_url_hint": "Insight platform region host, e.g. https://us.api.insight.rapid7.com",
        "credential_fields": [
            {"key": "api_key", "label": "Platform API key", "secret": True},
        ],
        "docs_url": "https://docs.rapid7.com/insight/managing-platform-api-keys/",
    },
    "nessus": {
        "label": "Tenable Nessus",
        "default_base_url": None,
        "base_url_required": True,
        "base_url_hint": "Scanner URL, e.g. https://nessus.internal:8834",
        "credential_fields": [
            {"key": "access_key", "label": "Access key", "secret": True},
            {"key": "secret_key", "label": "Secret key", "secret": True},
        ],
        "docs_url": "https://docs.tenable.com/nessus/Content/GenerateAnAPIKey.htm",
    },
}

# discovery_source / detected_by values per provider.
DISCOVERY_SOURCES = {
    "tenable": "tenable_vm",
    "qualys": "qualys_vmdr",
    "rapid7": "rapid7_insightvm",
    "nessus": "nessus",
}

# Tenable/Nessus numeric severities (0-4) → internal Severity enum.
_TENABLE_SEVERITY = {
    4: Severity.CRITICAL,
    3: Severity.HIGH,
    2: Severity.MEDIUM,
    1: Severity.LOW,
    0: Severity.INFO,
}

# Qualys severities (1-5) → internal Severity enum.
_QUALYS_SEVERITY = {
    5: Severity.CRITICAL,
    4: Severity.HIGH,
    3: Severity.MEDIUM,
    2: Severity.LOW,
    1: Severity.INFO,
}

_NAMED_SEVERITY = {
    "critical": Severity.CRITICAL,
    "severe": Severity.HIGH,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
}


def map_severity(value: Any, scale: Optional[Dict[int, Severity]] = None) -> Severity:
    """Map a vendor severity (numeric or named) to the internal enum."""
    if isinstance(value, str) and not value.isdigit():
        return _NAMED_SEVERITY.get(value.strip().lower(), Severity.MEDIUM)
    try:
        num = int(value)
    except (TypeError, ValueError):
        return Severity.MEDIUM
    return (scale or _TENABLE_SEVERITY).get(num, Severity.MEDIUM)


def infer_asset_type(value: str) -> AssetType:
    """Best-effort asset type for a scanner host identifier (IP or hostname)."""
    value = (value or "").strip()
    try:
        ipaddress.ip_address(value)
        return AssetType.IP_ADDRESS
    except ValueError:
        pass
    if "." in value:
        # foo.example.com -> subdomain, example.com -> domain
        return AssetType.SUBDOMAIN if value.count(".") >= 2 else AssetType.DOMAIN
    return AssetType.OTHER


def validate_config(provider: str, base_url: Optional[str], credentials: Dict[str, str]) -> Optional[str]:
    """Return an error message if the provider config is invalid, else None."""
    meta = PROVIDERS.get(provider)
    if not meta:
        return f"Unknown provider '{provider}'. Supported: {', '.join(sorted(PROVIDERS))}."
    if meta["base_url_required"] and not (base_url or "").strip():
        return f"{meta['label']} requires an API base URL."
    missing = [
        f["label"]
        for f in meta["credential_fields"]
        if not (credentials or {}).get(f["key"], "").strip()
    ]
    if missing:
        return f"Missing credential field(s): {', '.join(missing)}."
    return None


def _resolve_base_url(provider: str, base_url: Optional[str]) -> str:
    url = (base_url or "").strip() or (PROVIDERS[provider].get("default_base_url") or "")
    return url.rstrip("/")


def _first(d: Dict, *keys: str) -> Optional[Any]:
    for k in keys:
        v = d.get(k)
        if v not in (None, ""):
            return v
    return None


# ── Provider clients ──────────────────────────────────────────────────────────


class _BaseClient:
    """Shared HTTP plumbing for the vendor clients."""

    TIMEOUT = 60.0
    PAGE_SIZE = 100
    MAX_PAGES = 100          # pagination safety cap per endpoint
    MAX_ASSETS = 2000        # cap on per-asset detail fan-out
    RATE_LIMIT_DELAY = 0.3

    def __init__(self, base_url: str, credentials: Dict[str, str], verify_ssl: bool = True):
        self.base_url = base_url
        self.credentials = credentials
        self.verify_ssl = verify_ssl

    def _client_kwargs(self) -> Dict[str, Any]:
        return {"timeout": self.TIMEOUT, "verify": self.verify_ssl}

    async def _request(
        self,
        method: str,
        path: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict] = None,
        json_body: Optional[Dict] = None,
        auth: Optional[Tuple[str, str]] = None,
    ) -> Optional[httpx.Response]:
        url = f"{self.base_url}{path}"
        try:
            async with httpx.AsyncClient(**self._client_kwargs()) as client:
                resp = await client.request(
                    method, url, headers=headers, params=params, json=json_body, auth=auth
                )
                if resp.status_code == 429:
                    logger.warning("%s rate limited on %s, backing off 10s", type(self).__name__, path)
                    await asyncio.sleep(10)
                    return await self._request(
                        method, path, headers=headers, params=params, json_body=json_body, auth=auth
                    )
                return resp
        except Exception as exc:  # noqa: BLE001 — network errors are expected
            logger.error("%s %s %s error: %s", type(self).__name__, method, path, exc)
            return None

    # Subclasses implement:
    async def test(self) -> Tuple[bool, str]:
        raise NotImplementedError

    async def fetch(self) -> Tuple[List[Dict], List[Dict]]:
        """Return (hosts, findings) in the normalized shape."""
        raise NotImplementedError


class TenableClient(_BaseClient):
    """Tenable Vulnerability Management (cloud) via the workbenches API."""

    @property
    def _headers(self) -> Dict[str, str]:
        return {
            "X-ApiKeys": (
                f"accessKey={self.credentials.get('access_key', '')};"
                f"secretKey={self.credentials.get('secret_key', '')}"
            ),
            "Accept": "application/json",
        }

    async def _get_json(self, path: str, params: Optional[Dict] = None) -> Optional[Dict]:
        resp = await self._request("GET", path, headers=self._headers, params=params)
        if resp is None:
            return None
        if resp.status_code in (401, 403):
            logger.error("Tenable VM: unauthorized (HTTP %s) on %s", resp.status_code, path)
            return None
        if resp.status_code != 200:
            logger.warning("Tenable VM GET %s -> HTTP %s: %s", path, resp.status_code, resp.text[:200])
            return None
        return resp.json()

    async def test(self) -> Tuple[bool, str]:
        payload = await self._get_json("/session")
        if payload is None:
            return False, "Could not authenticate to Tenable Vulnerability Management with these API keys."
        who = _first(payload, "username", "name", "email") or "API user"
        return True, f"Connected to Tenable Vulnerability Management as {who}."

    async def fetch(self) -> Tuple[List[Dict], List[Dict]]:
        hosts: List[Dict] = []
        findings: List[Dict] = []

        payload = await self._get_json("/workbenches/assets", params={"date_range": 90})
        assets = (payload or {}).get("assets") or []
        for asset in assets[: self.MAX_ASSETS]:
            asset_id = _first(asset, "id", "uuid")
            value = None
            for key in ("ipv4", "fqdn", "hostname", "ipv6", "netbios_name"):
                candidates = asset.get(key)
                if isinstance(candidates, list) and candidates:
                    value = str(candidates[0])
                    break
                if isinstance(candidates, str) and candidates:
                    value = candidates
                    break
            if not value:
                continue
            hosts.append({"value": value, "metadata": {"tenable_asset_id": asset_id}})

            if asset_id is None:
                continue
            vulns_payload = await self._get_json(f"/workbenches/assets/{asset_id}/vulnerabilities")
            for vuln in (vulns_payload or {}).get("vulnerabilities") or []:
                plugin_id = _first(vuln, "plugin_id", "pluginId")
                findings.append(
                    {
                        "asset_value": value,
                        "external_id": f"tenable:{asset_id}:{plugin_id}",
                        "title": _first(vuln, "plugin_name", "pluginName") or f"Tenable plugin {plugin_id}",
                        "severity": map_severity(vuln.get("severity"), _TENABLE_SEVERITY),
                        "description": None,
                        "solution": None,
                        "cvss_score": None,
                        "cve_id": None,
                        "port": None,
                        "extra": {"plugin_id": plugin_id, "count": vuln.get("count")},
                    }
                )
            await asyncio.sleep(self.RATE_LIMIT_DELAY)

        return hosts, findings


class QualysClient(_BaseClient):
    """Qualys VMDR via the v2 host-detection API (XML)."""

    @property
    def _headers(self) -> Dict[str, str]:
        return {"X-Requested-With": "judahsecurity-asm"}

    @property
    def _auth(self) -> Tuple[str, str]:
        return (self.credentials.get("username", ""), self.credentials.get("password", ""))

    async def _get_xml(self, path: str, params: Optional[Dict] = None) -> Optional[ET.Element]:
        resp = await self._request("GET", path, headers=self._headers, params=params, auth=self._auth)
        if resp is None:
            return None
        if resp.status_code in (401, 403):
            logger.error("Qualys: unauthorized (HTTP %s) on %s", resp.status_code, path)
            return None
        if resp.status_code != 200:
            logger.warning("Qualys GET %s -> HTTP %s: %s", path, resp.status_code, resp.text[:200])
            return None
        try:
            # Qualys serves its own XML; stdlib ElementTree does not resolve
            # external entities, which is the exposure that matters here.
            return ET.fromstring(resp.text)
        except ET.ParseError as exc:
            logger.warning("Qualys XML parse error on %s: %s", path, exc)
            return None

    async def test(self) -> Tuple[bool, str]:
        root = await self._get_xml(
            "/api/2.0/fo/asset/host/",
            params={"action": "list", "truncation_limit": 1},
        )
        if root is None:
            return False, "Could not authenticate to Qualys with this username/password."
        if root.find(".//RESPONSE/CODE") is not None:
            text = root.findtext(".//RESPONSE/TEXT") or "Qualys API returned an error."
            return False, f"Qualys error: {text}"
        return True, "Connected to Qualys VMDR successfully."

    async def _fetch_kb_titles(self, qids: List[str]) -> Dict[str, Dict]:
        """Best-effort KnowledgeBase lookup: QID -> {title, cvss, ...}."""
        info: Dict[str, Dict] = {}
        for start in range(0, len(qids), 400):
            batch = qids[start : start + 400]
            root = await self._get_xml(
                "/api/2.0/fo/knowledge_base/vuln/",
                params={"action": "list", "ids": ",".join(batch), "details": "Basic"},
            )
            if root is None:
                break
            for vuln in root.iter("VULN"):
                qid = vuln.findtext("QID")
                if not qid:
                    continue
                info[qid] = {
                    "title": vuln.findtext("TITLE"),
                    "solution": vuln.findtext("SOLUTION"),
                    "cvss": vuln.findtext("CVSS/BASE") or vuln.findtext("CVSS_V3/BASE"),
                    "cve_id": vuln.findtext(".//CVE/ID"),
                }
            await asyncio.sleep(self.RATE_LIMIT_DELAY)
        return info

    async def fetch(self) -> Tuple[List[Dict], List[Dict]]:
        hosts: List[Dict] = []
        findings: List[Dict] = []

        path = "/api/2.0/fo/asset/host/vm/detection/"
        params: Optional[Dict] = {
            "action": "list",
            "show_igs": 0,               # skip pure information-gathered entries
            "truncation_limit": 1000,
            "status": "New,Active,Re-Opened",
        }
        for _ in range(self.MAX_PAGES):
            root = await self._get_xml(path, params=params)
            if root is None:
                break
            for host in root.iter("HOST"):
                value = host.findtext("DNS") or host.findtext("IP")
                if not value:
                    continue
                hosts.append({"value": value, "metadata": {"qualys_host_id": host.findtext("ID")}})
                for det in host.iter("DETECTION"):
                    qid = det.findtext("QID")
                    if not qid:
                        continue
                    findings.append(
                        {
                            "asset_value": value,
                            "external_id": f"qualys:{host.findtext('ID')}:{qid}",
                            "title": f"Qualys QID {qid}",  # replaced from KB below
                            "severity": map_severity(det.findtext("SEVERITY"), _QUALYS_SEVERITY),
                            "description": (det.findtext("RESULTS") or "")[:5000] or None,
                            "solution": None,
                            "cvss_score": None,
                            "cve_id": None,
                            "port": det.findtext("PORT"),
                            "extra": {"qid": qid, "detection_type": det.findtext("TYPE")},
                        }
                    )
            # Truncation pagination: a WARNING element carries the next URL.
            next_url = root.findtext(".//WARNING/URL")
            if not next_url:
                break
            # The next URL is absolute and already carries the query string.
            path = next_url.replace(self.base_url, "", 1)
            params = None
            await asyncio.sleep(self.RATE_LIMIT_DELAY)

        # Enrich titles/CVSS from the KnowledgeBase (best effort).
        qids = sorted({f["extra"]["qid"] for f in findings})
        if qids:
            kb = await self._fetch_kb_titles(qids)
            for f in findings:
                entry = kb.get(f["extra"]["qid"])
                if not entry:
                    continue
                if entry.get("title"):
                    f["title"] = entry["title"]
                f["solution"] = entry.get("solution")
                f["cve_id"] = entry.get("cve_id")
                try:
                    f["cvss_score"] = float(entry["cvss"]) if entry.get("cvss") else None
                except (TypeError, ValueError):
                    pass

        return hosts, findings


class Rapid7Client(_BaseClient):
    """Rapid7 InsightVM via the Insight platform /vm/v4/integration API."""

    @property
    def _headers(self) -> Dict[str, str]:
        return {
            "X-Api-Key": self.credentials.get("api_key", ""),
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    async def _post_json(self, path: str, params: Optional[Dict] = None) -> Optional[Dict]:
        resp = await self._request("POST", path, headers=self._headers, params=params, json_body={})
        if resp is None:
            return None
        if resp.status_code in (401, 403):
            logger.error("Rapid7: unauthorized (HTTP %s) on %s", resp.status_code, path)
            return None
        if resp.status_code != 200:
            logger.warning("Rapid7 POST %s -> HTTP %s: %s", path, resp.status_code, resp.text[:200])
            return None
        return resp.json()

    async def test(self) -> Tuple[bool, str]:
        resp = await self._request("GET", "/validate", headers=self._headers)
        if resp is not None and resp.status_code == 200:
            return True, "Connected to the Rapid7 Insight platform successfully."
        return False, "Could not authenticate to the Rapid7 Insight platform with this API key."

    async def _paginate(self, path: str) -> List[Dict]:
        results: List[Dict] = []
        cursor: Optional[str] = None
        for _ in range(self.MAX_PAGES):
            params: Dict[str, Any] = {"size": self.PAGE_SIZE}
            if cursor:
                params["cursor"] = cursor
            payload = await self._post_json(path, params=params)
            if not payload:
                break
            batch = payload.get("data") or []
            if not isinstance(batch, list) or not batch:
                break
            results.extend(batch)
            meta = payload.get("metadata") or {}
            cursor = meta.get("cursor")
            if not cursor:
                break
            await asyncio.sleep(self.RATE_LIMIT_DELAY)
        return results

    async def fetch(self) -> Tuple[List[Dict], List[Dict]]:
        hosts: List[Dict] = []
        findings: List[Dict] = []

        # Vulnerability definitions: id -> title/severity/cvss (best effort).
        definitions: Dict[str, Dict] = {}
        for d in await self._paginate("/vm/v4/integration/vulnerability_definitions"):
            def_id = _first(d, "id", "identifier")
            if def_id:
                definitions[str(def_id)] = d

        asset_values: Dict[str, str] = {}  # rapid7 asset id -> normalized value
        for asset in await self._paginate("/vm/v4/integration/assets"):
            asset_id = _first(asset, "id", "asset_id")
            value = _first(asset, "host_name", "hostname", "ip", "ip_address")
            if not value:
                continue
            value = str(value)
            hosts.append({"value": value, "metadata": {"rapid7_asset_id": asset_id}})
            if asset_id is not None:
                asset_values[str(asset_id)] = value

        for vuln in await self._paginate("/vm/v4/integration/vulnerabilities"):
            asset_id = _first(vuln, "asset_id", "assetId")
            value = asset_values.get(str(asset_id)) if asset_id is not None else None
            if not value:
                continue
            def_id = _first(vuln, "vulnerability_id", "vulnerabilityId", "definition_id", "key")
            definition = definitions.get(str(def_id), {}) if def_id else {}
            cvss = _first(definition, "cvss_v3_score", "cvss_score", "cvssV3Score")
            try:
                cvss = float(cvss) if cvss is not None else None
            except (TypeError, ValueError):
                cvss = None
            findings.append(
                {
                    "asset_value": value,
                    "external_id": f"rapid7:{asset_id}:{def_id}",
                    "title": _first(definition, "title", "name") or f"InsightVM vulnerability {def_id}",
                    "severity": map_severity(
                        _first(definition, "severity", "severity_score") or vuln.get("severity")
                    ),
                    "description": _first(definition, "description"),
                    "solution": None,
                    "cvss_score": cvss,
                    "cve_id": _first(definition, "cve", "cve_id"),
                    "port": _first(vuln, "port"),
                    "extra": {"definition_id": def_id, "status": vuln.get("status")},
                }
            )

        return hosts, findings


class NessusClient(_BaseClient):
    """Standalone Tenable Nessus scanner via its /scans REST API."""

    MAX_SCANS = 20  # most recent completed scans to read per sync

    @property
    def _headers(self) -> Dict[str, str]:
        return {
            "X-ApiKeys": (
                f"accessKey={self.credentials.get('access_key', '')};"
                f"secretKey={self.credentials.get('secret_key', '')}"
            ),
            "Accept": "application/json",
        }

    async def _get_json(self, path: str, params: Optional[Dict] = None) -> Optional[Dict]:
        resp = await self._request("GET", path, headers=self._headers, params=params)
        if resp is None:
            return None
        if resp.status_code in (401, 403):
            logger.error("Nessus: unauthorized (HTTP %s) on %s", resp.status_code, path)
            return None
        if resp.status_code != 200:
            logger.warning("Nessus GET %s -> HTTP %s: %s", path, resp.status_code, resp.text[:200])
            return None
        return resp.json()

    async def test(self) -> Tuple[bool, str]:
        payload = await self._get_json("/server/status")
        if payload is None:
            # /server/status is unauthenticated on some builds; fall back to /scans.
            payload = await self._get_json("/scans")
            if payload is None:
                return False, "Could not reach or authenticate to the Nessus scanner."
            return True, "Connected to Nessus successfully."
        scans = await self._get_json("/scans")
        if scans is None:
            return False, "Nessus is reachable but rejected these API keys."
        return True, f"Connected to Nessus (server status: {payload.get('status', 'unknown')})."

    async def fetch(self) -> Tuple[List[Dict], List[Dict]]:
        hosts: List[Dict] = []
        findings: List[Dict] = []
        seen_values: set[str] = set()

        payload = await self._get_json("/scans")
        scans = (payload or {}).get("scans") or []
        completed = [s for s in scans if s.get("status") == "completed"]
        completed.sort(key=lambda s: s.get("last_modification_date") or 0, reverse=True)

        for scan in completed[: self.MAX_SCANS]:
            scan_id = scan.get("id")
            detail = await self._get_json(f"/scans/{scan_id}")
            if not detail:
                continue
            for host in detail.get("hosts") or []:
                host_id = host.get("host_id")
                host_detail = await self._get_json(f"/scans/{scan_id}/hosts/{host_id}")
                if not host_detail:
                    continue
                info = host_detail.get("info") or {}
                value = (
                    _first(info, "host-fqdn", "host-ip")
                    or host.get("hostname")
                )
                if not value:
                    continue
                value = str(value)
                if value not in seen_values:
                    seen_values.add(value)
                    hosts.append({"value": value, "metadata": {"nessus_scan_id": scan_id}})
                for vuln in host_detail.get("vulnerabilities") or []:
                    plugin_id = _first(vuln, "plugin_id", "pluginId")
                    findings.append(
                        {
                            "asset_value": value,
                            "external_id": f"nessus:{plugin_id}",
                            "title": _first(vuln, "plugin_name", "pluginName") or f"Nessus plugin {plugin_id}",
                            "severity": map_severity(vuln.get("severity"), _TENABLE_SEVERITY),
                            "description": None,
                            "solution": None,
                            "cvss_score": None,
                            "cve_id": None,
                            "port": None,
                            "extra": {
                                "plugin_id": plugin_id,
                                "plugin_family": vuln.get("plugin_family"),
                                "scan_id": scan_id,
                            },
                        }
                    )
                await asyncio.sleep(self.RATE_LIMIT_DELAY)

        return hosts, findings


_CLIENTS = {
    "tenable": TenableClient,
    "qualys": QualysClient,
    "rapid7": Rapid7Client,
    "nessus": NessusClient,
}


def _build_client(
    provider: str, base_url: Optional[str], credentials: Dict[str, str], verify_ssl: bool
) -> _BaseClient:
    return _CLIENTS[provider](_resolve_base_url(provider, base_url), credentials, verify_ssl)


async def test_connection(
    provider: str,
    base_url: Optional[str],
    credentials: Dict[str, str],
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    """Validate a VM scanner connection. Returns {ok, message}."""
    error = validate_config(provider, base_url, credentials)
    if error:
        return {"ok": False, "message": error}
    ok, message = await _build_client(provider, base_url, credentials, verify_ssl).test()
    return {"ok": ok, "message": message}


# ── Sync orchestration ────────────────────────────────────────────────────────


class _Stats:
    def __init__(self) -> None:
        self.assets_created = 0
        self.assets_updated = 0
        self.vulns_created = 0
        self.vulns_updated = 0
        self.hosts_seen = 0
        self.findings_seen = 0

    def as_dict(self) -> Dict[str, int]:
        return {
            "assets_created": self.assets_created,
            "assets_updated": self.assets_updated,
            "vulns_created": self.vulns_created,
            "vulns_updated": self.vulns_updated,
            "hosts_seen": self.hosts_seen,
            "findings_seen": self.findings_seen,
        }


def _upsert_asset(
    db: Session,
    org_id: int,
    value: str,
    source: str,
    provider_label: str,
    stats: _Stats,
    *,
    metadata: Optional[Dict] = None,
) -> Optional[Asset]:
    """Create the asset if missing, else refresh last_seen. Returns the asset."""
    value = (value or "").strip()
    if not value:
        return None
    existing = (
        db.query(Asset)
        .filter(Asset.organization_id == org_id, Asset.value == value)
        .first()
    )
    if existing:
        existing.last_seen = datetime.utcnow()
        tags = list(existing.tags or [])
        if f"source:{source}" not in tags:
            tags.append(f"source:{source}")
            existing.tags = tags
        stats.assets_updated += 1
        return existing

    asset = Asset(
        name=value,
        asset_type=infer_asset_type(value),
        value=value,
        organization_id=org_id,
        status=AssetStatus.DISCOVERED,
        discovery_source=source,
        association_reason=f"Scanned by {provider_label}",
        association_confidence=90,
        tags=[f"source:{source}"],
        metadata_=metadata or {},
    )
    db.add(asset)
    db.flush()  # assign id for finding association
    stats.assets_created += 1
    return asset


def _import_finding(
    db: Session,
    org_id: int,
    finding: Dict,
    asset_index: Dict[str, Asset],
    source: str,
    provider_label: str,
    stats: _Stats,
    can_create_assets: bool,
) -> None:
    value = (finding.get("asset_value") or "").strip()
    if not value:
        return

    asset = asset_index.get(value)
    if asset is None:
        asset = (
            db.query(Asset)
            .filter(Asset.organization_id == org_id, Asset.value == value)
            .first()
        )
    if asset is None:
        if not can_create_assets:
            return
        asset = _upsert_asset(db, org_id, value, source, provider_label, stats)
    if asset is None:
        return
    asset_index[value] = asset

    title = (finding.get("title") or f"{provider_label} finding")[:500]
    external_id = finding.get("external_id")

    # Dedup: match by vendor finding id in metadata, else by title+asset.
    existing = None
    if external_id:
        existing = (
            db.query(Vulnerability)
            .filter(
                Vulnerability.asset_id == asset.id,
                Vulnerability.metadata_["vm_finding_id"].astext == str(external_id),
            )
            .first()
        )
    if existing is None:
        existing = (
            db.query(Vulnerability)
            .filter(
                Vulnerability.asset_id == asset.id,
                Vulnerability.title == title,
                Vulnerability.detected_by == source,
            )
            .first()
        )

    if existing:
        existing.severity = finding["severity"]
        existing.last_detected = datetime.utcnow()
        if finding.get("cvss_score") is not None:
            existing.cvss_score = finding["cvss_score"]
        stats.vulns_updated += 1
        return

    vuln = Vulnerability(
        title=title,
        description=finding.get("description"),
        severity=finding["severity"],
        cvss_score=finding.get("cvss_score"),
        cve_id=(str(finding["cve_id"])[:50] if finding.get("cve_id") else None),
        asset_id=asset.id,
        detected_by=source,
        status=VulnerabilityStatus.OPEN,
        remediation=finding.get("solution"),
        tags=[f"source:{source}"],
        metadata_={
            "vm_finding_id": str(external_id) if external_id else None,
            "vm_provider": provider_label,
            "port": finding.get("port"),
            "source": source,
            **(finding.get("extra") or {}),
        },
    )
    db.add(vuln)
    stats.vulns_created += 1


async def sync_integration(db: Session, integration: VmScannerIntegration) -> Dict[str, Any]:
    """Pull hosts and/or detections from a VM scanner and import them.

    Returns a result dict compatible with :class:`VmScannerSyncResult`.
    """
    org_id = integration.organization_id
    provider = integration.provider
    provider_label = PROVIDERS.get(provider, {}).get("label", provider)
    source = DISCOVERY_SOURCES.get(provider, provider)

    credentials = integration.get_credentials()
    error = validate_config(provider, integration.base_url, credentials)
    if error:
        return {"ok": False, "message": error}

    client = _build_client(provider, integration.base_url, credentials, integration.verify_ssl)
    stats = _Stats()
    asset_index: Dict[str, Asset] = {}

    try:
        hosts, findings = await client.fetch()
        stats.hosts_seen = len(hosts)
        stats.findings_seen = len(findings)

        if integration.import_assets:
            for host in hosts:
                asset = _upsert_asset(
                    db, org_id, host["value"], source, provider_label, stats,
                    metadata=host.get("metadata"),
                )
                if asset:
                    asset_index[host["value"]] = asset
            db.commit()

        if integration.import_vulnerabilities:
            for finding in findings:
                _import_finding(
                    db, org_id, finding, asset_index, source, provider_label,
                    stats, integration.import_assets,
                )
            db.commit()

        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = True
        integration.last_error = None
        integration.last_sync_stats = stats.as_dict()
        db.commit()

        return {
            "ok": True,
            "message": (
                f"Imported {stats.assets_created} new asset(s) and "
                f"{stats.vulns_created} new finding(s) from {provider_label}."
            ),
            **stats.as_dict(),
        }
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        logger.exception("%s sync failed for org %s", provider_label, org_id)
        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = False
        integration.last_error = str(exc)[:1000]
        db.commit()
        return {"ok": False, "message": f"Sync failed: {exc}", **stats.as_dict()}
