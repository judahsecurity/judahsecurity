"""Black Kite security-ratings integration.

Read-only client for the Black Kite API (v2) plus the sync logic that imports
the customer's *own* companies into this platform:

* active company subdomains            -> assets
* per-category vulnerability findings  -> risks (severity from CVSS when present)
* fraudulent / look-alike domains      -> risks on the company's primary domain

Black Kite tenants usually monitor many third parties. Only companies that
match the configured ecosystem names or company domains are imported;
everything else in the tenant is ignored.

API reference:
    Base URL : https://tprm-api.blackkitetech.com/api/v2
    Auth     : OAuth2 client credentials -> POST /oauth/token
    Scope    : GET /ecosystems, GET /ecosystems/{id}/companies, GET /companies
    Assets   : GET /companies/{id}/subdomains
    Findings : GET /companies/{id}/findings/{category}

Black Kite payload field names vary by endpoint and API revision, so parsing
is deliberately defensive (PascalCase and camelCase keys, list or wrapped
responses).
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import httpx
from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetStatus, AssetType
from app.models.blackkite_integration import BlackKiteIntegration
from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus

logger = logging.getLogger(__name__)

DISCOVERY_SOURCE = "blackkite"
SOURCE_TAG = "source:blackkite"
BASE_URL = "https://tprm-api.blackkitetech.com/api/v2"
TOKEN_PATH = "/oauth/token"

# Per-category technical findings imported as risks.
FINDING_CATEGORIES: Dict[str, str] = {
    "patchmanagement": "Patch Management",
    "applicationsecurity": "Application Security",
    "websecurity": "Web Security",
    "sslhealth": "SSL/TLS Strength",
    "dnshealth": "DNS Health",
    "emailsecurity": "Email Security",
    "networksecurity": "Network Security",
    "ddos": "DDoS Resiliency",
    "credentialmanagement": "Credential Management",
    "ipreputation": "IP Reputation",
    "attacksurface": "Attack Surface",
    "informationdisclosure": "Information Disclosure",
}
# Brand-protection findings: domains registered by others that impersonate us.
FRAUD_CATEGORIES: Dict[str, str] = {
    "fraudulentdomains": "Fraudulent Domains",
}

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "very high": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "very low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "information": Severity.INFO,
}
_RESOLVED_STATUSES = {"closed", "resolved", "fixed", "inactive", "remediated", "passive"}
_INACTIVE_SUBDOMAIN_STATUSES = {"inactive", "passive", "down", "dead", "removed", "closed"}
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


class BlackKiteApiError(RuntimeError):
    """A safe, user-displayable Black Kite API error."""


# ── Generic payload helpers ─────────────────────────────────────────────────


def _first(d: Dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = d.get(key)
        if value not in (None, "", []):
            return value
    return None


def _items(payload: Any) -> List[Dict[str, Any]]:
    """Return the record list from a bare-list or wrapped Black Kite response."""
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in (
            "Items", "items", "Data", "data", "Results", "results", "Findings", "findings",
            "Companies", "companies", "Ecosystems", "ecosystems", "Subdomains", "subdomains",
        ):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
            if isinstance(value, dict):
                nested = _items(value)
                if nested:
                    return nested
    return []


def normalize_domain(value: Any) -> str:
    """Lower-case a host/domain and strip scheme, path, port, wildcard and www."""
    raw = str(value or "").strip().lower()
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    raw = raw.split("/", 1)[0].split("?", 1)[0].split("@")[-1]
    if raw.count(":") == 1:
        raw = raw.split(":", 1)[0]
    raw = raw.strip(".")
    for prefix in ("*.", "www."):
        if raw.startswith(prefix):
            raw = raw[len(prefix):]
    return raw


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def severity_from_cvss(score: float) -> Severity:
    """CVSS v3 qualitative rating bands."""
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


def _cvss_score(finding: Dict[str, Any]) -> Optional[float]:
    raw = _first(
        finding,
        "CvssScore", "cvssScore", "Cvss3Score", "cvss3Score", "CVSS", "Cvss", "cvss",
        "CvssV3", "BaseScore", "baseScore",
    )
    if isinstance(raw, dict):
        raw = _first(raw, "BaseScore", "baseScore", "Score", "score")
    try:
        score = float(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None
    if score is None or score < 0 or score > 10:
        return None
    return score


def finding_severity(finding: Dict[str, Any]) -> Tuple[Severity, Optional[float]]:
    """Severity from CVSS when present, else Black Kite's own severity label."""
    score = _cvss_score(finding)
    if score is not None:
        return severity_from_cvss(score), score
    label = _first(finding, "Severity", "severity", "RiskLevel", "riskLevel", "Risk", "risk")
    return _SEVERITY_MAP.get(str(label or "").strip().lower(), Severity.MEDIUM), None


def _parse_datetime(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def _company_ref(company: Dict[str, Any]) -> Optional[Dict[str, Optional[str]]]:
    company_id = _first(company, "CompanyId", "companyId", "Id", "id")
    if company_id is None:
        return None
    domain = _first(company, "DomainName", "domainName", "Domain", "domain", "MainDomain", "mainDomain")
    name = _first(company, "CompanyName", "companyName", "Name", "name")
    return {
        "id": str(company_id),
        "name": str(name) if name else None,
        "domain": normalize_domain(domain) or None,
    }


# ── API client ──────────────────────────────────────────────────────────────


class BlackKiteClient:
    """Minimal OAuth2 client for the read-only Black Kite API."""

    PAGE_SIZE = 100
    MAX_PAGES = 200
    RATE_LIMIT_DELAY = 0.25

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        *,
        base_url: str = BASE_URL,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = base_url.rstrip("/")
        self._transport = transport
        self._token: Optional[str] = None

    def _http(self, timeout: float) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=timeout, transport=self._transport)

    async def authenticate(self) -> str:
        try:
            async with self._http(30.0) as client:
                response = await client.post(
                    f"{self.base_url}{TOKEN_PATH}",
                    data={
                        "grant_type": "client_credentials",
                        "client_id": self.client_id,
                        "client_secret": self.client_secret,
                    },
                    headers={"Accept": "application/json"},
                )
        except httpx.HTTPError as exc:
            raise BlackKiteApiError(f"Could not reach the Black Kite API: {exc}") from exc
        if response.status_code in (400, 401, 403):
            raise BlackKiteApiError(
                "Black Kite rejected the client credentials; check the Client ID and Client Secret."
            )
        if response.status_code != 200:
            raise BlackKiteApiError(f"Black Kite authentication failed (HTTP {response.status_code}).")
        try:
            token = response.json().get("access_token")
        except (ValueError, AttributeError) as exc:
            raise BlackKiteApiError("Black Kite authentication returned an invalid response.") from exc
        if not token:
            raise BlackKiteApiError("Black Kite authentication response did not contain an access token.")
        self._token = str(token)
        return self._token

    async def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Optional[Any]:
        """GET a JSON resource. Returns None on 404 (category/endpoint not available)."""
        token = self._token or await self.authenticate()
        reauthed = False
        for attempt in range(4):
            try:
                async with self._http(60.0) as client:
                    response = await client.get(
                        f"{self.base_url}{path}",
                        params=params,
                        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                    )
            except httpx.HTTPError as exc:
                if attempt == 3:
                    raise BlackKiteApiError(f"Could not reach the Black Kite API: {exc}") from exc
                await asyncio.sleep(2 ** attempt)
                continue
            if response.status_code == 401 and not reauthed:
                reauthed = True
                token = await self.authenticate()
                continue
            if response.status_code in (429, 502, 503, 504) and attempt < 3:
                await asyncio.sleep(2 ** attempt)
                continue
            if response.status_code == 404:
                return None
            if response.status_code in (401, 403):
                raise BlackKiteApiError(
                    f"Black Kite rejected the request (HTTP {response.status_code}); "
                    "check that the credential is scoped to the tenant to import."
                )
            if response.status_code != 200:
                raise BlackKiteApiError(f"Black Kite request {path} failed (HTTP {response.status_code}).")
            try:
                return response.json()
            except ValueError as exc:
                raise BlackKiteApiError(f"Black Kite returned invalid JSON for {path}.") from exc
        raise BlackKiteApiError(f"Black Kite request {path} failed after retries.")

    async def paginate(self, path: str) -> Optional[List[Dict[str, Any]]]:
        """Collect all pages. Returns None if the endpoint does not exist (404)."""
        results: List[Dict[str, Any]] = []
        for page in range(1, self.MAX_PAGES + 1):
            payload = await self.get(path, params={"page_number": page, "page_size": self.PAGE_SIZE})
            if payload is None:
                return None if page == 1 else results
            batch = _items(payload)
            results.extend(batch)
            total_pages = None
            if isinstance(payload, dict):
                total_pages = _first(payload, "TotalPages", "totalPages", "total_pages")
            if not batch or len(batch) < self.PAGE_SIZE:
                break
            if total_pages is not None and page >= int(total_pages):
                break
            await asyncio.sleep(self.RATE_LIMIT_DELAY)
        return results

    async def list_ecosystems(self) -> List[Dict[str, Any]]:
        return await self.paginate("/ecosystems") or []

    async def list_ecosystem_companies(self, ecosystem_id: str) -> List[Dict[str, Any]]:
        return await self.paginate(f"/ecosystems/{ecosystem_id}/companies") or []

    async def list_companies(self) -> List[Dict[str, Any]]:
        return await self.paginate("/companies") or []

    async def get_subdomains(self, company_id: str) -> Optional[List[Dict[str, Any]]]:
        return await self.paginate(f"/companies/{company_id}/subdomains")

    async def get_findings(self, company_id: str, category: str) -> Optional[List[Dict[str, Any]]]:
        return await self.paginate(f"/companies/{company_id}/findings/{category}")


# ── Scope resolution ────────────────────────────────────────────────────────


async def resolve_companies(
    client: BlackKiteClient,
    ecosystem_names: Iterable[str],
    company_domains: Iterable[str],
) -> Tuple[List[Dict[str, Optional[str]]], List[str]]:
    """Return (in-scope companies, configured entries that matched nothing)."""
    matched: Dict[str, Dict[str, Optional[str]]] = {}
    unmatched: List[str] = []

    wanted_ecosystems = {name.strip().lower(): name for name in ecosystem_names if name and name.strip()}
    if wanted_ecosystems:
        found: Set[str] = set()
        for eco in await client.list_ecosystems():
            name = str(_first(eco, "Name", "name", "EcosystemName", "ecosystemName") or "").strip()
            eco_id = _first(eco, "EcosystemId", "ecosystemId", "Id", "id")
            if eco_id is None or name.lower() not in wanted_ecosystems:
                continue
            found.add(name.lower())
            for company in await client.list_ecosystem_companies(str(eco_id)):
                ref = _company_ref(company)
                if ref:
                    matched.setdefault(ref["id"], ref)
        unmatched.extend(orig for key, orig in wanted_ecosystems.items() if key not in found)

    wanted_domains = {normalize_domain(d): d for d in company_domains if normalize_domain(d)}
    if wanted_domains:
        found_domains: Set[str] = set()
        for company in await client.list_companies():
            ref = _company_ref(company)
            if ref and ref["domain"] in wanted_domains:
                found_domains.add(ref["domain"])
                existing = matched.get(ref["id"])
                if existing is None or not existing.get("domain"):
                    matched[ref["id"]] = ref
        unmatched.extend(orig for key, orig in wanted_domains.items() if key not in found_domains)

    return list(matched.values()), unmatched


def _client_for(integration: BlackKiteIntegration) -> BlackKiteClient:
    client_id = integration.get_client_id()
    client_secret = integration.get_client_secret()
    if not client_id or not client_secret:
        raise BlackKiteApiError("No Black Kite client credentials are stored for this connection.")
    return BlackKiteClient(client_id, client_secret)


async def test_connection(
    client_id: str,
    client_secret: str,
    ecosystem_names: List[str],
    company_domains: List[str],
    *,
    client: Optional[BlackKiteClient] = None,
) -> Dict[str, Any]:
    """Validate credentials and confirm the scope matches at least one company."""
    try:
        client = client or BlackKiteClient(client_id, client_secret)
        await client.authenticate()
        companies, unmatched = await resolve_companies(client, ecosystem_names, company_domains)
    except BlackKiteApiError as exc:
        return {"ok": False, "message": str(exc), "matched_companies": []}
    if not companies:
        return {
            "ok": False,
            "message": (
                "Credentials are valid, but none of the configured ecosystem names or company "
                "domains match a company in this Black Kite tenant."
            ),
            "matched_companies": [],
        }
    message = f"Connected to Black Kite; {len(companies)} company(ies) in scope."
    if unmatched:
        message += f" No match for: {', '.join(unmatched)}."
    return {"ok": True, "message": message, "matched_companies": companies}


# ── Sync ────────────────────────────────────────────────────────────────────


class _Stats:
    def __init__(self) -> None:
        self.companies_synced = 0
        self.assets_created = 0
        self.assets_updated = 0
        self.vulns_created = 0
        self.vulns_updated = 0
        self.vulns_resolved = 0
        self.subdomains_seen = 0
        self.findings_seen = 0
        self.fraudulent_domains_seen = 0

    def as_dict(self) -> Dict[str, int]:
        return vars(self).copy()


def _upsert_asset(
    db: Session,
    org_id: int,
    value: str,
    asset_type: AssetType,
    stats: _Stats,
    *,
    company: Dict[str, Optional[str]],
    ip_address: Optional[str] = None,
) -> Optional[Asset]:
    value = (value or "").strip().lower()
    if not value:
        return None
    asset = db.query(Asset).filter(Asset.organization_id == org_id, Asset.value == value).first()
    if asset:
        asset.last_seen = datetime.utcnow()
        tags = list(asset.tags or [])
        if SOURCE_TAG not in tags:
            tags.append(SOURCE_TAG)
            asset.tags = tags
        if ip_address and not asset.ip_address:
            asset.ip_address = ip_address
        stats.assets_updated += 1
        return asset
    asset = Asset(
        name=value[:255],
        asset_type=asset_type,
        value=value[:500],
        organization_id=org_id,
        status=AssetStatus.DISCOVERED,
        discovery_source=DISCOVERY_SOURCE,
        association_reason=(
            f"Active asset of in-scope Black Kite company {company.get('name') or company['id']}"
        ),
        association_confidence=90,
        tags=[SOURCE_TAG],
        ip_address=ip_address,
        metadata_={"blackkite": {"company_id": company["id"], "company_name": company.get("name")}},
    )
    db.add(asset)
    db.flush()
    stats.assets_created += 1
    return asset


def _asset_type_for(host: str, root_domain: Optional[str]) -> AssetType:
    if _is_ip(host):
        return AssetType.IP_ADDRESS
    if root_domain and host == root_domain:
        return AssetType.DOMAIN
    return AssetType.SUBDOMAIN


def _subdomain_host(record: Dict[str, Any]) -> Optional[str]:
    host = _first(record, "Subdomain", "subdomain", "Hostname", "hostname", "Host", "host", "Name", "name", "Domain", "domain")
    return normalize_domain(host) or None


def _subdomain_is_active(record: Dict[str, Any]) -> bool:
    flag = _first(record, "IsActive", "isActive", "Active", "active")
    if isinstance(flag, bool):
        return flag
    status = str(_first(record, "Status", "status") or "").strip().lower()
    return status not in _INACTIVE_SUBDOMAIN_STATUSES


def _finding_host(finding: Dict[str, Any]) -> Optional[str]:
    host = _first(
        finding,
        "Subdomain", "subdomain", "Hostname", "hostname", "Host", "host", "Domain", "domain",
        "IpAddress", "ipAddress", "Ip", "ip", "Asset", "asset",
    )
    if isinstance(host, dict):
        host = _first(host, "Name", "name", "Value", "value")
    return normalize_domain(host) or None


def _finding_id(finding: Dict[str, Any], host: Optional[str], title: str) -> str:
    raw = _first(finding, "FindingId", "findingId", "Id", "id")
    if raw is not None:
        return str(raw)
    return hashlib.sha1(f"{host or ''}|{title}".encode()).hexdigest()[:16]


def _finding_resolved(finding: Dict[str, Any]) -> bool:
    status = str(_first(finding, "Status", "status", "FindingStatus", "findingStatus") or "").strip().lower()
    return status in _RESOLVED_STATUSES


def _cve(finding: Dict[str, Any], title: str) -> Optional[str]:
    raw = _first(finding, "CveId", "cveId", "Cve", "cve", "CVE")
    if isinstance(raw, list):
        raw = raw[0] if raw else None
    for candidate in (raw, title, _first(finding, "Detail", "detail", "Description", "description")):
        match = _CVE_RE.search(str(candidate or ""))
        if match:
            return match.group(0).upper()
    return None


def _upsert_vulnerability(
    db: Session,
    asset: Asset,
    *,
    template_id: str,
    title: str,
    description: Optional[str],
    severity: Severity,
    cvss_score: Optional[float],
    cve_id: Optional[str],
    resolved: bool,
    first_seen: Optional[datetime],
    last_seen: Optional[datetime],
    remediation: Optional[str],
    metadata: Dict[str, Any],
    stats: _Stats,
) -> None:
    existing = db.query(Vulnerability).filter(
        Vulnerability.asset_id == asset.id,
        Vulnerability.detected_by == DISCOVERY_SOURCE,
        Vulnerability.template_id == template_id,
    ).first()
    now = datetime.utcnow()
    if existing:
        existing.title = title
        existing.description = description
        existing.severity = severity
        existing.cvss_score = cvss_score
        existing.cve_id = cve_id
        existing.remediation = remediation
        existing.last_detected = last_seen or now
        existing.metadata_ = metadata
        if resolved and existing.status != VulnerabilityStatus.RESOLVED:
            existing.status = VulnerabilityStatus.RESOLVED
            existing.resolved_at = now
        elif not resolved and existing.status == VulnerabilityStatus.RESOLVED:
            existing.status = VulnerabilityStatus.OPEN
            existing.resolved_at = None
        stats.vulns_updated += 1
        return
    db.add(
        Vulnerability(
            title=title[:500],
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            cve_id=cve_id,
            remediation=remediation,
            asset_id=asset.id,
            detected_by=DISCOVERY_SOURCE,
            template_id=template_id,
            status=VulnerabilityStatus.RESOLVED if resolved else VulnerabilityStatus.OPEN,
            first_detected=first_seen or now,
            last_detected=last_seen or now,
            resolved_at=now if resolved else None,
            tags=[SOURCE_TAG],
            metadata_=metadata,
        )
    )
    stats.vulns_created += 1


def _template_id(company_id: str, category: str, finding_id: str) -> str:
    return f"blackkite:{company_id}:{category}:{finding_id}"[:255]


def _resolve_missing(
    db: Session, org_id: int, company_id: str, category: str, seen: Set[str], stats: _Stats
) -> None:
    """Close open Black Kite risks in a category that the latest pull no longer reports."""
    prefix = f"blackkite:{company_id}:{category}:"
    stale = (
        db.query(Vulnerability)
        .join(Asset, Vulnerability.asset_id == Asset.id)
        .filter(
            Asset.organization_id == org_id,
            Vulnerability.detected_by == DISCOVERY_SOURCE,
            Vulnerability.template_id.like(f"{prefix}%"),
            Vulnerability.status == VulnerabilityStatus.OPEN,
        )
        .all()
    )
    now = datetime.utcnow()
    for vuln in stale:
        if vuln.template_id not in seen:
            vuln.status = VulnerabilityStatus.RESOLVED
            vuln.resolved_at = now
            stats.vulns_resolved += 1


async def _sync_company(
    db: Session,
    client: BlackKiteClient,
    org_id: int,
    company: Dict[str, Optional[str]],
    stats: _Stats,
) -> None:
    company_id = company["id"]
    root_domain = company.get("domain")
    assets: Dict[str, Asset] = {}

    def asset_for(host: Optional[str]) -> Optional[Asset]:
        host = host or root_domain
        if not host:
            return None
        if host not in assets:
            found = _upsert_asset(
                db, org_id, host, _asset_type_for(host, root_domain), stats, company=company
            )
            if found is None:
                return None
            assets[host] = found
        return assets[host]

    root_asset = asset_for(root_domain) if root_domain else None

    # 1. Active subdomains -> assets
    for record in await client.get_subdomains(company_id) or []:
        host = _subdomain_host(record)
        if not host or not _subdomain_is_active(record):
            continue
        stats.subdomains_seen += 1
        if host in assets:
            continue
        ip = _first(record, "IpAddress", "ipAddress", "Ip", "ip")
        ip = str(ip) if ip and _is_ip(str(ip)) else None
        created = _upsert_asset(
            db, org_id, host, _asset_type_for(host, root_domain), stats, company=company, ip_address=ip
        )
        if created:
            assets[host] = created

    # 2. Per-category vulnerability findings -> risks
    for category, label in FINDING_CATEGORIES.items():
        findings = await client.get_findings(company_id, category)
        if findings is None:
            continue  # category not offered for this tenant/plan
        seen: Set[str] = set()
        for finding in findings:
            stats.findings_seen += 1
            title = str(_first(finding, "Title", "title", "Name", "name", "FindingName") or f"{label} finding")
            host = _finding_host(finding)
            asset = asset_for(host)
            if asset is None:
                continue
            severity, score = finding_severity(finding)
            template_id = _template_id(company_id, category, _finding_id(finding, host, title))
            seen.add(template_id)
            _upsert_vulnerability(
                db,
                asset,
                template_id=template_id,
                title=f"[Black Kite] {title}",
                description=_first(finding, "Detail", "detail", "Description", "description"),
                severity=severity,
                cvss_score=score,
                cve_id=_cve(finding, title),
                resolved=_finding_resolved(finding),
                first_seen=_parse_datetime(_first(finding, "FirstSeen", "firstSeen", "FindingDate", "CreatedDate")),
                last_seen=_parse_datetime(_first(finding, "LastSeen", "lastSeen", "UpdatedDate")),
                remediation=_first(finding, "Remediation", "remediation", "Recommendation", "recommendation"),
                metadata={
                    "source": DISCOVERY_SOURCE,
                    "blackkite_company_id": company_id,
                    "blackkite_company_name": company.get("name"),
                    "blackkite_category": label,
                    "blackkite_finding_id": _first(finding, "FindingId", "findingId", "Id", "id"),
                    "blackkite_status": _first(finding, "Status", "status"),
                    "blackkite_severity": _first(finding, "Severity", "severity"),
                },
                stats=stats,
            )
        _resolve_missing(db, org_id, company_id, category, seen, stats)

    # 3. Fraudulent / look-alike domains -> risks on the company's primary domain
    for category, label in FRAUD_CATEGORIES.items():
        findings = await client.get_findings(company_id, category)
        if findings is None or root_asset is None:
            continue
        seen = set()
        for finding in findings:
            domain = normalize_domain(
                _first(finding, "Domain", "domain", "DomainName", "domainName", "FraudulentDomain", "Name", "name")
            )
            if not domain:
                continue
            stats.fraudulent_domains_seen += 1
            kind = str(_first(finding, "Type", "type", "Category", "category", "Title", "title") or "")
            noun = "Look-alike domain" if "look" in kind.lower() else "Fraudulent domain"
            severity, score = finding_severity(finding)
            template_id = _template_id(company_id, category, _finding_id(finding, domain, domain))
            seen.add(template_id)
            _upsert_vulnerability(
                db,
                root_asset,
                template_id=template_id,
                title=f"[Black Kite] {noun}: {domain}",
                description=(
                    _first(finding, "Detail", "detail", "Description", "description")
                    or f"{domain} may impersonate {root_domain} (reported by Black Kite)."
                ),
                severity=severity,
                cvss_score=score,
                cve_id=None,
                resolved=_finding_resolved(finding),
                first_seen=_parse_datetime(_first(finding, "FirstSeen", "firstSeen", "CreatedDate", "RegistrationDate")),
                last_seen=_parse_datetime(_first(finding, "LastSeen", "lastSeen", "UpdatedDate")),
                remediation="Review the domain and request a takedown if it is malicious.",
                metadata={
                    "source": DISCOVERY_SOURCE,
                    "blackkite_company_id": company_id,
                    "blackkite_company_name": company.get("name"),
                    "blackkite_category": label,
                    "fraudulent_domain": domain,
                    "blackkite_finding_id": _first(finding, "FindingId", "findingId", "Id", "id"),
                },
                stats=stats,
            )
        _resolve_missing(db, org_id, company_id, category, seen, stats)

    stats.companies_synced += 1


async def sync_integration(
    db: Session,
    integration: BlackKiteIntegration,
    *,
    client: Optional[BlackKiteClient] = None,
) -> Dict[str, Any]:
    stats = _Stats()
    org_id = integration.organization_id
    try:
        client = client or _client_for(integration)
        companies, _ = await resolve_companies(
            client, integration.ecosystem_names or [], integration.company_domains or []
        )
        if not companies:
            raise BlackKiteApiError(
                "None of the configured ecosystem names or company domains match a company in this Black Kite tenant."
            )
        integration.matched_companies = companies
        for company in companies:
            await _sync_company(db, client, org_id, company, stats)
            db.commit()

        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = True
        integration.last_error = None
        integration.last_sync_stats = stats.as_dict()
        db.commit()
        return {
            "ok": True,
            "message": (
                f"Imported {stats.assets_created} new asset(s) and {stats.vulns_created} new risk(s) "
                f"from {stats.companies_synced} Black Kite company(ies)."
            ),
            **stats.as_dict(),
        }
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        logger.exception("Black Kite sync failed for organization %s", org_id)
        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = False
        integration.last_error = str(exc)[:1000]
        integration.last_sync_stats = stats.as_dict()
        db.commit()
        return {"ok": False, "message": f"Sync failed: {exc}", **stats.as_dict()}
