"""Read-only NetBrain evidence collection and exploit-prerequisite evaluation."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import ipaddress
import logging
from typing import Any
from urllib.parse import urlsplit

import httpx
from sqlalchemy.orm import Session, joinedload

from app.models.asset import Asset
from app.models.netbrain_integration import NetBrainIntegration
from app.models.vulnerability import Vulnerability, VulnerabilityStatus

logger = logging.getLogger(__name__)

SUPPORTED_CVES = frozenset({"CVE-2023-20198", "CVE-2023-20273"})
API_ROOT = "/ServicesAPI/API/V1"
REQUEST_TIMEOUT = httpx.Timeout(60.0, connect=15.0)


def normalize_base_url(value: str) -> str:
    value = (value or "").strip().rstrip("/")
    if value and not value.startswith(("http://", "https://")):
        value = f"https://{value}"
    return value


def _status_ok(payload: dict[str, Any]) -> bool:
    status = payload.get("statusCode")
    return status in (None, 790200, "790200")


def _api_error(action: str, response: httpx.Response, payload: dict[str, Any] | None = None) -> RuntimeError:
    payload = payload or {}
    description = payload.get("statusDescription") or response.text[:300]
    return RuntimeError(f"NetBrain {action} failed ({response.status_code}): {description}")


class NetBrainClient:
    """Async client for the documented NetBrain northbound REST API."""

    def __init__(self, base_url: str, username: str, password: str, *, tenant_id: str,
                 domain_id: str, authentication_id: str | None = None, verify_ssl: bool = True):
        self.base_url = normalize_base_url(base_url)
        self.username = username
        self.password = password
        self.tenant_id = tenant_id
        self.domain_id = domain_id
        self.authentication_id = authentication_id
        self.verify_ssl = verify_ssl
        self.token: str | None = None
        self.client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "NetBrainClient":
        self.client = httpx.AsyncClient(
            verify=self.verify_ssl,
            timeout=REQUEST_TIMEOUT,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )
        await self.login()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        try:
            await self.logout()
        finally:
            if self.client:
                await self.client.aclose()
                self.client = None

    def _http(self) -> httpx.AsyncClient:
        if not self.client:
            raise RuntimeError("NetBrainClient must be used as an async context manager.")
        return self.client

    def _headers(self) -> dict[str, str]:
        return {"Token": self.token} if self.token else {}

    async def login(self) -> None:
        body = {"username": self.username, "password": self.password}
        if self.authentication_id:
            body["authentication_id"] = self.authentication_id
        response = await self._http().post(f"{self.base_url}{API_ROOT}/Session", json=body)
        payload = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
        if response.status_code >= 400 or not _status_ok(payload) or not payload.get("token"):
            raise _api_error("login", response, payload)
        self.token = str(payload["token"])
        response = await self._http().put(
            f"{self.base_url}{API_ROOT}/Session/CurrentDomain",
            json={"tenantId": self.tenant_id, "domainId": self.domain_id},
            headers=self._headers(),
        )
        payload = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
        if response.status_code >= 400 or not _status_ok(payload):
            raise _api_error("domain selection", response, payload)

    async def logout(self) -> None:
        if not self.token or not self.client:
            return
        try:
            await self.client.delete(f"{self.base_url}{API_ROOT}/Session", headers=self._headers())
        except Exception as exc:  # noqa: BLE001
            logger.debug("NetBrain logout failed (non-fatal): %s", exc)
        self.token = None

    async def get_devices(self, *, ip: str | None = None, hostname: str | None = None,
                          limit: int = 100) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"version": 1, "fullattr": 1, "limit": max(10, min(limit, 100))}
        if hostname:
            params["hostname"] = hostname
            params["ignoreCase"] = "true"
        elif ip:
            params["ip"] = ip
        response = await self._http().get(
            f"{self.base_url}{API_ROOT}/CMDB/Devices", params=params, headers=self._headers()
        )
        payload = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
        if response.status_code >= 400 or not _status_ok(payload):
            raise _api_error("device lookup", response, payload)
        devices = payload.get("devices") or []
        return [item for item in devices if isinstance(item, dict)]

    async def get_configuration(self, hostname: str) -> tuple[str, str | None]:
        response = await self._http().get(
            f"{self.base_url}{API_ROOT}/CMDB/DataEngine/DeviceData/Configuration",
            params={"hostname": hostname}, headers=self._headers(),
        )
        payload = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
        if response.status_code >= 400 or not _status_ok(payload):
            raise _api_error("configuration retrieval", response, payload)
        configuration = payload.get("configuration")
        if not isinstance(configuration, str) or not configuration.strip():
            raise RuntimeError(f"NetBrain returned no configuration for {hostname}.")
        return configuration, payload.get("time")


def _config_lines(configuration: str) -> set[str]:
    return {line.strip().lower() for line in (configuration or "").splitlines() if line.strip()}


def evaluate_cisco_ios_xe_web_ui(configuration: str) -> dict[str, Any]:
    """Evaluate the Cisco-documented Web UI prerequisites for two 2023 CVEs."""
    lines = _config_lines(configuration)
    http_enabled = "ip http server" in lines and "no ip http server" not in lines
    https_enabled = "ip http secure-server" in lines and "no ip http secure-server" not in lines
    http_modules_disabled = "ip http active-session-modules none" in lines
    https_modules_disabled = "ip http secure-active-session-modules none" in lines
    http_exploitable = http_enabled and not http_modules_disabled
    https_exploitable = https_enabled and not https_modules_disabled
    relevant = sorted(line for line in lines if line.startswith(("ip http server", "ip http secure-server",
        "no ip http server", "no ip http secure-server", "ip http active-session-modules",
        "ip http secure-active-session-modules")))
    prerequisite_present = http_exploitable or https_exploitable
    return {
        "verdict": "prerequisite_present" if prerequisite_present else "prerequisite_absent",
        "http_server_enabled": http_enabled,
        "https_server_enabled": https_enabled,
        "http_session_modules_disabled": http_modules_disabled,
        "https_session_modules_disabled": https_modules_disabled,
        "exploitable_transports": [name for name, active in (("http", http_exploitable), ("https", https_exploitable)) if active],
        "relevant_configuration": relevant,
        "analysis": (
            "Cisco Web UI has an enabled exploit path in the running configuration."
            if prerequisite_present else
            "The Cisco Web UI exploit prerequisite is absent from the running configuration."
        ),
        "suggested_remediation": (
            "Upgrade to a fixed IOS XE release. If the Web UI is unnecessary, disable the HTTP/HTTPS server; "
            "otherwise apply Cisco's documented session-module restrictions and access controls."
        ),
    }


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def _asset_candidates(asset: Asset) -> tuple[list[str], list[str]]:
    ips: list[str] = []
    hosts: list[str] = []
    values = [asset.value, asset.name, asset.ip_address, *(asset.ip_addresses or [])]
    for raw in values:
        if not isinstance(raw, str) or not raw.strip():
            continue
        value = raw.strip()
        try:
            value = urlsplit(value if "://" in value else f"//{value}").hostname or value
        except ValueError:
            pass
        try:
            canonical = str(ipaddress.ip_address(value))
            if canonical not in ips:
                ips.append(canonical)
        except ValueError:
            host = value.lower().rstrip(".")
            if host and host not in hosts:
                hosts.append(host)
    return ips, hosts


async def _match_device(client: NetBrainClient, asset: Asset) -> tuple[dict[str, Any] | None, str]:
    ips, hosts = _asset_candidates(asset)
    matches: dict[str, dict[str, Any]] = {}
    for ip in ips:
        for device in await client.get_devices(ip=ip):
            if str(device.get("mgmtIP") or "") == ip:
                matches[str(device.get("id") or device.get("hostname") or device.get("name"))] = device
    if not matches:
        for host in hosts:
            for device in await client.get_devices(hostname=host):
                device_host = str(device.get("hostname") or device.get("name") or "").lower().rstrip(".")
                if device_host == host:
                    matches[str(device.get("id") or device_host)] = device
    if len(matches) == 1:
        return next(iter(matches.values())), "exact_management_ip_or_hostname"
    return None, "device_not_found" if not matches else "ambiguous_device_match"


def _managed_assessment(metadata: dict[str, Any]) -> dict[str, Any]:
    value = metadata.get("netbrain_exposure")
    return value if isinstance(value, dict) else {}


def apply_assessment(vulnerability: Vulnerability, assessment: dict[str, Any], *, auto_mitigate: bool) -> str:
    """Persist evidence and apply only reversible, NetBrain-owned status transitions."""
    metadata = deepcopy(vulnerability.metadata_ or {})
    previous = _managed_assessment(metadata)
    action = "evidence_updated"
    now = datetime.now(timezone.utc).isoformat()
    managed_status = bool(previous.get("managed_status")) and vulnerability.status == VulnerabilityStatus.MITIGATED
    managed_integration_id = previous.get("managed_integration_id", previous.get("integration_id"))
    current_integration_id = assessment.get("integration_id")
    verdict = assessment.get("verdict")

    if auto_mitigate and verdict == "prerequisite_absent" and vulnerability.status in {
        VulnerabilityStatus.OPEN, VulnerabilityStatus.IN_PROGRESS
    }:
        vulnerability.status = VulnerabilityStatus.MITIGATED
        vulnerability.resolved_at = None
        managed_status = True
        managed_integration_id = current_integration_id
        action = "mitigated"
    elif managed_status and verdict == "prerequisite_present":
        vulnerability.status = VulnerabilityStatus.OPEN
        vulnerability.resolved_at = None
        managed_status = False
        managed_integration_id = None
        action = "reopened"
    elif (
        managed_status
        and verdict == "unknown"
        and (
            managed_integration_id is None
            or current_integration_id is None
            or managed_integration_id == current_integration_id
        )
    ):
        vulnerability.status = VulnerabilityStatus.OPEN
        vulnerability.resolved_at = None
        managed_status = False
        managed_integration_id = None
        action = "reopened"

    metadata["netbrain_exposure"] = {
        **assessment,
        "managed_status": managed_status,
        "managed_integration_id": managed_integration_id,
        "evaluated_at": now,
        "status_action": action,
    }
    vulnerability.metadata_ = metadata
    return action


async def test_connection(integration: NetBrainIntegration) -> dict[str, Any]:
    try:
        async with _client_for(integration) as client:
            devices = await client.get_devices(limit=10)
            return {"ok": True, "message": "Connected to NetBrain and selected the configured domain.",
                    "device_count": len(devices)}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "message": str(exc)[:500], "device_count": None}


def _client_for(integration: NetBrainIntegration) -> NetBrainClient:
    return NetBrainClient(
        integration.base_url, integration.get_username() or "", integration.get_password() or "",
        tenant_id=integration.tenant_id, domain_id=integration.domain_id,
        authentication_id=integration.authentication_id, verify_ssl=bool(integration.verify_ssl),
    )


async def sync_integration(db: Session, integration: NetBrainIntegration) -> dict[str, Any]:
    stats = {key: 0 for key in ("findings_seen", "findings_assessed", "findings_mitigated",
        "findings_reopened", "prerequisites_present", "prerequisites_absent", "unknown")}
    now = datetime.now(timezone.utc)
    try:
        findings = (
            db.query(Vulnerability)
            .options(joinedload(Vulnerability.asset))
            .join(Asset, Vulnerability.asset_id == Asset.id)
            .filter(
                Asset.organization_id == integration.organization_id,
                Vulnerability.cve_id.in_(SUPPORTED_CVES),
                Vulnerability.status.in_([
                    VulnerabilityStatus.OPEN, VulnerabilityStatus.IN_PROGRESS, VulnerabilityStatus.MITIGATED
                ]),
            ).all()
        )
        stats["findings_seen"] = len(findings)
        async with _client_for(integration) as client:
            for finding in findings:
                assessment: dict[str, Any]
                try:
                    device, match_basis = await _match_device(client, finding.asset)
                    if not device:
                        assessment = {"verdict": "unknown", "reason": match_basis}
                    else:
                        hostname = str(device.get("hostname") or device.get("name") or "")
                        configuration, config_time_raw = await client.get_configuration(hostname)
                        config_time = _parse_time(config_time_raw)
                        age_hours = ((now - config_time).total_seconds() / 3600) if config_time else None
                        if age_hours is None or age_hours > integration.max_config_age_hours:
                            assessment = {
                                "verdict": "unknown", "reason": "stale_or_undated_configuration",
                                "configuration_time": config_time_raw, "configuration_age_hours": age_hours,
                            }
                        else:
                            assessment = evaluate_cisco_ios_xe_web_ui(configuration)
                            assessment.update({
                                "reason": "cisco_documented_configuration_prerequisite",
                                "configuration_time": config_time.isoformat(),
                                "configuration_age_hours": round(age_hours, 2),
                                "configuration_sha256": hashlib.sha256(configuration.encode()).hexdigest(),
                            })
                        assessment.update({
                            "source": "netbrain", "integration_id": integration.id,
                            "device_id": device.get("id") or device.get("deviceId"),
                            "device_hostname": hostname, "device_management_ip": device.get("mgmtIP"),
                            "asset_match_basis": match_basis,
                        })
                except Exception as exc:  # noqa: BLE001
                    assessment = {"verdict": "unknown", "reason": "collection_error", "error": str(exc)[:300]}

                action = apply_assessment(finding, assessment, auto_mitigate=integration.auto_mitigate_enabled)
                stats["findings_assessed"] += 1
                verdict = assessment.get("verdict")
                if verdict == "prerequisite_present":
                    stats["prerequisites_present"] += 1
                elif verdict == "prerequisite_absent":
                    stats["prerequisites_absent"] += 1
                else:
                    stats["unknown"] += 1
                if action == "mitigated":
                    stats["findings_mitigated"] += 1
                elif action == "reopened":
                    stats["findings_reopened"] += 1

        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = True
        integration.last_sync_stats = stats
        integration.last_error = None
        db.commit()
        return {"ok": True, "message": f"Assessed {stats['findings_assessed']} supported finding(s).", **stats}
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = False
        integration.last_error = str(exc)[:500]
        db.add(integration)
        db.commit()
        return {"ok": False, "message": str(exc)[:500], **stats}
