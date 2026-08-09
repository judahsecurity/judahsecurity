"""Akamai WAF (Application Security) integration service.

Read-only client for the Akamai Application Security API plus sync logic that
imports security configurations, policies, and protected hostnames into the ASM
platform.

API reference (Application Security / Kona Site Defender / App & API Protector):
    Base URL : https://{api_host}
    Auth     : Akamai EdgeGrid (EG1-HMAC-SHA256)
    Configs  : GET /appsec/v1/configs
    Policies : GET /appsec/v1/configs/{configId}/versions/{version}/security-policies
    Hosts    : GET /appsec/v1/configs/{configId}/versions/{version}/selected-hostnames

Credentials never leave encrypted storage except to sign outbound HTTPS requests.
The integration never writes back to Akamai.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx
from sqlalchemy.orm import Session

from app.models.akamai_integration import AkamaiWafIntegration
from app.models.asset import Asset, AssetStatus, AssetType

logger = logging.getLogger(__name__)

DISCOVERY_SOURCE = "akamai_waf"
SYNC_TIMEOUT_SECONDS = 180.0


# ── EdgeGrid signing (GET-only subset; no third-party dependency) ─────────────

def _eg_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H:%M:%S+0000")


def _base64_hmac_sha256(data: str, key: str) -> str:
    digest = hmac.new(key.encode("utf-8"), data.encode("utf-8"), hashlib.sha256).digest()
    return base64.b64encode(digest).decode("utf-8")


def _edgegrid_auth_header(
    *,
    method: str,
    url: str,
    client_token: str,
    client_secret: str,
    access_token: str,
) -> str:
    """Build an EG1-HMAC-SHA256 Authorization header for a request with no body."""
    parsed = urlparse(url)
    path_and_query = parsed.path or "/"
    if parsed.query:
        path_and_query = f"{path_and_query}?{parsed.query}"

    timestamp = _eg_timestamp()
    nonce = str(uuid.uuid4())
    auth_header = (
        f"EG1-HMAC-SHA256 client_token={client_token};"
        f"access_token={access_token};"
        f"timestamp={timestamp};"
        f"nonce={nonce};"
    )
    # method \t scheme \t host \t path+query \t headers \t content_hash \t auth
    data_to_sign = "\t".join(
        [
            method.upper(),
            parsed.scheme,
            parsed.netloc,
            path_and_query,
            "",  # no signed headers
            "",  # GET has no content hash
            auth_header,
        ]
    )
    signing_key = _base64_hmac_sha256(timestamp, client_secret)
    signature = _base64_hmac_sha256(data_to_sign, signing_key)
    return auth_header + f"signature={signature}"


class AkamaiAppSecClient:
    """Thin async client for the read-only Akamai Application Security API."""

    RATE_LIMIT_DELAY = 0.25

    def __init__(
        self,
        api_host: str,
        client_token: str,
        client_secret: str,
        access_token: str,
        *,
        timeout: float = SYNC_TIMEOUT_SECONDS,
    ):
        host = (api_host or "").strip()
        if host.lower().startswith("https://") or host.lower().startswith("http://"):
            raise ValueError("API Host should not include protocol — enter only the hostname")
        if not host:
            raise ValueError("missing Akamai API host")
        if not client_token:
            raise ValueError("missing EdgeGrid client_token")
        if not client_secret:
            raise ValueError("missing EdgeGrid client_secret")
        if not access_token:
            raise ValueError("missing EdgeGrid access_token")

        self.api_host = host.split("/")[0]
        self.client_token = client_token
        self.client_secret = client_secret
        self.access_token = access_token
        self.timeout = timeout
        self.base_url = f"https://{self.api_host}"

    async def _get(self, path: str) -> Tuple[Optional[Dict], Optional[str], Optional[int]]:
        """GET path. Returns (json, error_message, status_code)."""
        url = f"{self.base_url}{path}"
        try:
            auth = _edgegrid_auth_header(
                method="GET",
                url=url,
                client_token=self.client_token,
                client_secret=self.client_secret,
                access_token=self.access_token,
            )
            headers = {
                "Authorization": auth,
                "Accept": "application/json",
            }
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code in (401, 403):
                    return None, (
                        f"Unauthorized (HTTP {resp.status_code}). "
                        "Check EdgeGrid credentials and Application Security READ access."
                    ), resp.status_code
                if resp.status_code != 200:
                    snippet = (resp.text or "")[:200]
                    return None, (
                        f"Unexpected API response (HTTP {resp.status_code}) on {path}: {snippet}"
                    ), resp.status_code
                try:
                    return resp.json(), None, resp.status_code
                except Exception:  # noqa: BLE001
                    return None, f"Invalid JSON response from {path}", resp.status_code
        except httpx.TimeoutException:
            return None, f"Request to {path} timed out after {self.timeout}s", None
        except Exception as exc:  # noqa: BLE001
            logger.error("Akamai AppSec GET %s error: %s", path, exc)
            return None, str(exc), None

    async def list_configs(self) -> Tuple[List[Dict], Optional[str]]:
        """Fetch all Application Security configurations."""
        payload, err, _ = await self._get("/appsec/v1/configs")
        if err:
            return [], err
        if not isinstance(payload, dict):
            return [], "Unexpected configs response shape"
        configs = payload.get("configurations") or payload.get("configs") or []
        if not isinstance(configs, list):
            return [], "Unexpected configs response shape"
        return configs, None

    async def get_security_policies(
        self, config_id: int | str, version: int | str
    ) -> Tuple[List[Dict], Optional[str]]:
        path = f"/appsec/v1/configs/{config_id}/versions/{version}/security-policies"
        payload, err, _ = await self._get(path)
        if err:
            return [], err
        if not isinstance(payload, dict):
            return [], None
        policies = (
            payload.get("securityPolicies")
            or payload.get("policies")
            or payload.get("security_policies")
            or []
        )
        return policies if isinstance(policies, list) else [], None

    async def get_selected_hostnames(
        self, config_id: int | str, version: int | str
    ) -> Tuple[List[str], Optional[str]]:
        path = f"/appsec/v1/configs/{config_id}/versions/{version}/selected-hostnames"
        payload, err, _ = await self._get(path)
        if err:
            return [], err
        hostnames: List[str] = []
        if isinstance(payload, dict):
            # Common shapes: {"hostnameList": [{"hostname": "..."}, ...]} or {"hostnames": [...]}
            items = (
                payload.get("hostnameList")
                or payload.get("selectedHostnames")
                or payload.get("hostnames")
                or []
            )
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, str) and item.strip():
                        hostnames.append(item.strip().lower())
                    elif isinstance(item, dict):
                        hn = item.get("hostname") or item.get("name") or item.get("cname")
                        if hn and str(hn).strip():
                            hostnames.append(str(hn).strip().lower())
        return hostnames, None


def _config_version(cfg: Dict) -> Optional[int | str]:
    """Pick the best version number from a config summary object."""
    for key in (
        "productionVersion",
        "production_version",
        "latestVersion",
        "latest_version",
        "stagingVersion",
        "staging_version",
        "version",
    ):
        v = cfg.get(key)
        if v not in (None, "", 0, "0"):
            return v
    return None


def _config_id(cfg: Dict) -> Optional[int | str]:
    return cfg.get("id") or cfg.get("configId") or cfg.get("config_id")


def _config_name(cfg: Dict) -> str:
    return (
        cfg.get("name")
        or cfg.get("configName")
        or cfg.get("config_name")
        or f"Akamai Config {_config_id(cfg) or 'unknown'}"
    )


def _is_hostname(value: str) -> bool:
    v = (value or "").strip().lower()
    if not v or " " in v or "/" in v:
        return False
    if v.startswith("*."):
        v = v[2:]
    return "." in v and not v.startswith(".") and not v.endswith(".")


def _asset_type_for_hostname(hostname: str) -> AssetType:
    """Treat multi-label names as subdomains; two-label as domains."""
    # Strip wildcard prefix for typing.
    hn = hostname[2:] if hostname.startswith("*.") else hostname
    labels = [p for p in hn.split(".") if p]
    if len(labels) <= 2:
        return AssetType.DOMAIN
    return AssetType.SUBDOMAIN


async def test_connection(
    api_host: str,
    client_token: str,
    client_secret: str,
    access_token: str,
) -> Dict[str, Any]:
    """Validate EdgeGrid credentials by listing Application Security configs."""
    try:
        client = AkamaiAppSecClient(api_host, client_token, client_secret, access_token)
    except ValueError as exc:
        return {"ok": False, "message": str(exc), "configs_found": None}

    configs, err = await client.list_configs()
    if err:
        return {"ok": False, "message": err, "configs_found": None}
    return {
        "ok": True,
        "message": (
            f"Connected to Akamai Application Security successfully "
            f"({len(configs)} configuration(s) found)."
        ),
        "configs_found": len(configs),
    }


# ── Sync orchestration ────────────────────────────────────────────────────────

class _Stats:
    def __init__(self) -> None:
        self.assets_created = 0
        self.assets_updated = 0
        self.configs_seen = 0
        self.policies_seen = 0
        self.hostnames_seen = 0

    def as_dict(self) -> Dict[str, int]:
        return {
            "assets_created": self.assets_created,
            "assets_updated": self.assets_updated,
            "configs_seen": self.configs_seen,
            "policies_seen": self.policies_seen,
            "hostnames_seen": self.hostnames_seen,
        }


def _upsert_asset(
    db: Session,
    org_id: int,
    value: str,
    asset_type: AssetType,
    stats: _Stats,
    *,
    name: Optional[str] = None,
    metadata: Optional[Dict] = None,
    description: Optional[str] = None,
    hosting_provider: Optional[str] = None,
    hosting_type: Optional[str] = None,
) -> Optional[Asset]:
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
        if f"source:{DISCOVERY_SOURCE}" not in tags:
            tags.append(f"source:{DISCOVERY_SOURCE}")
            existing.tags = tags
        if metadata:
            merged = dict(existing.metadata_ or {})
            merged.update(metadata)
            existing.metadata_ = merged
        if hosting_provider and not existing.hosting_provider:
            existing.hosting_provider = hosting_provider
        if hosting_type and not existing.hosting_type:
            existing.hosting_type = hosting_type
        stats.assets_updated += 1
        return existing

    asset = Asset(
        name=(name or value)[:255],
        asset_type=asset_type,
        value=value[:500],
        organization_id=org_id,
        status=AssetStatus.DISCOVERED,
        description=description,
        discovery_source=DISCOVERY_SOURCE,
        association_reason="Protected by / imported from Akamai Application Security (WAF)",
        association_confidence=95,
        tags=[f"source:{DISCOVERY_SOURCE}", "waf:akamai"],
        metadata_=metadata or {},
        hosting_provider=hosting_provider,
        hosting_type=hosting_type,
    )
    db.add(asset)
    db.flush()
    stats.assets_created += 1
    return asset


def _policy_summary(policies: List[Dict]) -> List[Dict[str, Any]]:
    summaries: List[Dict[str, Any]] = []
    for p in policies:
        summaries.append(
            {
                "policy_id": p.get("policyId") or p.get("id") or p.get("policy_id"),
                "policy_name": p.get("policyName") or p.get("name") or p.get("policy_name"),
                "policy_mode": (
                    p.get("mode")
                    or p.get("policyMode")
                    or p.get("operationalMode")
                    or p.get("policy_mode")
                ),
            }
        )
    return summaries


async def sync_integration(db: Session, integration: AkamaiWafIntegration) -> Dict[str, Any]:
    """Pull WAF configs/policies/hostnames and import them as assets/seeds.

    Returns a result dict compatible with :class:`AkamaiSyncResult`.
    """
    org_id = integration.organization_id
    client_token = integration.get_client_token()
    client_secret = integration.get_client_secret()
    access_token = integration.get_access_token()

    if not all([integration.api_host, client_token, client_secret, access_token]):
        return {"ok": False, "message": "Incomplete EdgeGrid credentials stored for this connection."}

    try:
        client = AkamaiAppSecClient(
            integration.api_host,
            client_token,
            client_secret,
            access_token,
        )
    except ValueError as exc:
        return {"ok": False, "message": str(exc)}

    stats = _Stats()

    try:
        configs, err = await client.list_configs()
        if err:
            integration.last_sync_at = datetime.utcnow()
            integration.last_sync_ok = False
            integration.last_error = err[:1000]
            db.commit()
            return {"ok": False, "message": err, **stats.as_dict()}

        stats.configs_seen = len(configs)

        for cfg in configs:
            cfg_id = _config_id(cfg)
            version = _config_version(cfg)
            cfg_name = _config_name(cfg)

            policies: List[Dict] = []
            hostnames: List[str] = []

            if cfg_id is not None and version is not None:
                policies, pol_err = await client.get_security_policies(cfg_id, version)
                if pol_err:
                    logger.warning(
                        "Akamai WAF: policies fetch failed for config %s: %s", cfg_id, pol_err
                    )
                stats.policies_seen += len(policies)

                if integration.import_hostnames:
                    hostnames, hn_err = await client.get_selected_hostnames(cfg_id, version)
                    if hn_err:
                        logger.warning(
                            "Akamai WAF: hostnames fetch failed for config %s: %s",
                            cfg_id,
                            hn_err,
                        )
                    # Also pull any hostnames embedded on the config summary.
                    for key in ("hostnames", "productionHostnames", "stagingHostnames"):
                        embedded = cfg.get(key) or []
                        if isinstance(embedded, list):
                            for item in embedded:
                                if isinstance(item, str):
                                    hostnames.append(item.strip().lower())
                                elif isinstance(item, dict):
                                    hn = item.get("hostname") or item.get("name")
                                    if hn:
                                        hostnames.append(str(hn).strip().lower())
                    # Dedup while preserving order
                    seen_hn: set[str] = set()
                    deduped: List[str] = []
                    for hn in hostnames:
                        if hn and hn not in seen_hn:
                            seen_hn.add(hn)
                            deduped.append(hn)
                    hostnames = deduped
                    stats.hostnames_seen += len(hostnames)

            if integration.import_configurations and cfg_id is not None:
                # Store WAF configuration as a CLOUD_RESOURCE asset.
                cfg_value = f"akamai-waf-config:{cfg_id}"
                _upsert_asset(
                    db,
                    org_id,
                    cfg_value,
                    AssetType.CLOUD_RESOURCE,
                    stats,
                    name=f"Akamai WAF: {cfg_name}"[:255],
                    description=(
                        cfg.get("description")
                        or f"Akamai Application Security configuration '{cfg_name}'"
                    ),
                    hosting_provider="akamai",
                    hosting_type="cdn",
                    metadata={
                        "akamai_config_id": cfg_id,
                        "akamai_config_name": cfg_name,
                        "akamai_version": version,
                        "akamai_policies": _policy_summary(policies),
                        "akamai_hostnames": hostnames,
                        "akamai_contract_id": cfg.get("contractId") or cfg.get("contract_id"),
                        "akamai_group_id": cfg.get("groupId") or cfg.get("group_id"),
                        "source": DISCOVERY_SOURCE,
                        "asset_kind": "waf_configuration",
                    },
                )

            if integration.import_hostnames:
                for hn in hostnames:
                    if not _is_hostname(hn):
                        continue
                    # Store wildcard as value with leading "*." preserved.
                    atype = _asset_type_for_hostname(hn)
                    _upsert_asset(
                        db,
                        org_id,
                        hn,
                        atype,
                        stats,
                        hosting_provider="akamai",
                        hosting_type="cdn",
                        metadata={
                            "akamai_config_id": cfg_id,
                            "akamai_config_name": cfg_name,
                            "akamai_version": version,
                            "source": DISCOVERY_SOURCE,
                            "protected_by_waf": True,
                        },
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
                f"Imported {stats.assets_created} new asset(s) from Akamai WAF "
                f"({stats.configs_seen} config(s), {stats.policies_seen} polic(ies), "
                f"{stats.hostnames_seen} hostname(s))."
            ),
            **stats.as_dict(),
        }
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        logger.exception("Akamai WAF sync failed for org %s", org_id)
        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = False
        integration.last_error = str(exc)[:1000]
        db.commit()
        return {"ok": False, "message": f"Sync failed: {exc}", **stats.as_dict()}
