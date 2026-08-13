"""HackerOne bug bounty integration service.

Read-only client for the HackerOne API plus sync logic that imports:
  - Vulnerability reports → Vulnerability findings
  - Eligible program scopes → Assets

API reference (Praetorian-compatible):
    Base URL : https://api.hackerone.com
    Auth     : HTTP Basic (API Identifier : API Token)
    Programs : GET /v1/me/programs
    Reports  : GET /v1/reports?filter[program][]={handle}&page[size]=100
    Scopes   : GET /v1/programs/{programID}/structured_scopes?page[size]=100

Data flows one direction only — from HackerOne into this platform.
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx
from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetStatus, AssetType
from app.models.hackerone_integration import HackerOneIntegration, HackerOneReportLink
from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus

logger = logging.getLogger(__name__)

DISCOVERY_SOURCE = "hackerone"

# HackerOne severity ratings → internal Severity enum.
_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "none": Severity.INFO,
    "null": Severity.INFO,
    "info": Severity.INFO,
    "informational": Severity.INFO,
}

# HackerOne report state → internal VulnerabilityStatus.
# Soft-closed states (duplicate/spam/informative/N/A) map to FALSE_POSITIVE
# so they remain queryable but leave the active remediation queue.
_STATUS_MAP = {
    "new": VulnerabilityStatus.OPEN,
    "pending-program-review": VulnerabilityStatus.OPEN,
    "needs-more-info": VulnerabilityStatus.OPEN,
    "triaged": VulnerabilityStatus.IN_PROGRESS,
    "retesting": VulnerabilityStatus.IN_PROGRESS,
    "resolved": VulnerabilityStatus.RESOLVED,
    "not-applicable": VulnerabilityStatus.FALSE_POSITIVE,
    "duplicate": VulnerabilityStatus.FALSE_POSITIVE,
    "spam": VulnerabilityStatus.FALSE_POSITIVE,
    "informative": VulnerabilityStatus.FALSE_POSITIVE,
}

# HackerOne structured-scope asset_type → AssetType.
_SCOPE_TYPE_MAP = {
    "url": AssetType.URL,
    "domain": AssetType.DOMAIN,
    "wildcard": AssetType.DOMAIN,
    "ip_address": AssetType.IP_ADDRESS,
    "ip-address": AssetType.IP_ADDRESS,
    "cidr": AssetType.IP_RANGE,
}


def _map_severity(value: Optional[str]) -> Severity:
    return _SEVERITY_MAP.get((value or "").strip().lower(), Severity.INFO)


def _map_status(state: Optional[str]) -> VulnerabilityStatus:
    return _STATUS_MAP.get((state or "").strip().lower(), VulnerabilityStatus.OPEN)


def _first(d: Dict, *keys: str) -> Optional[Any]:
    for k in keys:
        v = d.get(k)
        if v not in (None, ""):
            return v
    return None


def _attrs(resource: Dict) -> Dict:
    """Return attributes dict from a JSON:API resource, or the resource itself."""
    if not isinstance(resource, dict):
        return {}
    attrs = resource.get("attributes")
    return attrs if isinstance(attrs, dict) else resource


class HackerOneClient:
    """Thin async client for the read-only HackerOne API."""

    BASE_URL = "https://api.hackerone.com"
    PAGE_SIZE = 100
    MAX_PAGES = 200
    RATE_LIMIT_DELAY = 0.5

    def __init__(self, api_identifier: str, api_token: str):
        self.auth = (api_identifier, api_token)
        self._headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    async def _get(
        self, path: str, params: Optional[Dict] = None
    ) -> Optional[Dict]:
        url = path if path.startswith("http") else f"{self.BASE_URL}{path}"
        try:
            async with httpx.AsyncClient(
                timeout=45.0, headers=self._headers, auth=self.auth
            ) as client:
                resp = await client.get(url, params=params)
                if resp.status_code == 429:
                    logger.warning("HackerOne rate limited on %s, backing off 15s", path)
                    await asyncio.sleep(15)
                    return await self._get(path, params)
                if resp.status_code in (401, 403):
                    logger.error(
                        "HackerOne: unauthorized (HTTP %s) on %s",
                        resp.status_code,
                        path,
                    )
                    return None
                if resp.status_code != 200:
                    logger.warning(
                        "HackerOne GET %s -> HTTP %s: %s",
                        path,
                        resp.status_code,
                        resp.text[:300],
                    )
                    return None
                return resp.json()
        except Exception as exc:  # noqa: BLE001
            logger.error("HackerOne GET %s error: %s", path, exc)
            return None

    async def _paginate(
        self, path: str, params: Optional[Dict] = None
    ) -> Tuple[List[Dict], List[Dict]]:
        """Paginate a JSON:API collection. Returns (data_items, included_items)."""
        results: List[Dict] = []
        included: List[Dict] = []
        page = 1
        query = dict(params or {})
        query.setdefault("page[size]", self.PAGE_SIZE)

        while page <= self.MAX_PAGES:
            query["page[number]"] = page
            payload = await self._get(path, params=query)
            if not payload:
                break
            batch = payload.get("data") or []
            if not isinstance(batch, list):
                break
            results.extend(batch)
            extra = payload.get("included") or []
            if isinstance(extra, list):
                included.extend(extra)

            links = payload.get("links") or {}
            has_next = bool(links.get("next"))
            # Also stop when a short page is returned.
            if not has_next or len(batch) < self.PAGE_SIZE:
                break
            page += 1
            await asyncio.sleep(self.RATE_LIMIT_DELAY)

        return results, included

    async def get_programs(self) -> List[Dict]:
        data, _ = await self._paginate("/v1/me/programs")
        return data

    async def get_reports(self, program_handle: str) -> Tuple[List[Dict], List[Dict]]:
        return await self._paginate(
            "/v1/reports",
            params={f"filter[program][]": program_handle},
        )

    async def get_structured_scopes(self, program_id: str) -> List[Dict]:
        data, _ = await self._paginate(
            f"/v1/programs/{program_id}/structured_scopes"
        )
        return data

    async def get_report(self, report_id: str) -> Optional[Tuple[Dict, List[Dict]]]:
        """Fetch a single report by ID. Returns (report, included) or None."""
        payload = await self._get(f"/v1/reports/{report_id}")
        if not payload:
            return None
        data = payload.get("data")
        if not isinstance(data, dict):
            return None
        included = payload.get("included") or []
        if not isinstance(included, list):
            included = []
        return data, included


def parse_report_id(report_id_or_url: str) -> Optional[str]:
    """Extract a numeric HackerOne report id from a raw id or URL."""
    raw = (report_id_or_url or "").strip()
    if not raw:
        return None
    # https://hackerone.com/reports/1234567 (optional query/fragment)
    match = re.search(r"hackerone\.com/reports/(\d+)", raw, re.IGNORECASE)
    if match:
        return match.group(1)
    # Bare numeric id
    if re.fullmatch(r"\d+", raw):
        return raw
    # "report 1234567" / "#1234567"
    match = re.search(r"(?:report[#\s-]*)?(\d{4,})", raw, re.IGNORECASE)
    if match:
        return match.group(1)
    return None


def report_url_for(report_id: str) -> str:
    return f"https://hackerone.com/reports/{report_id}"


def summarize_report(
    report: Dict, included: Optional[List[Dict]] = None
) -> Dict[str, Any]:
    """Normalize a HackerOne report resource into link/display fields."""
    included_index = _index_included(included or [])
    attrs = _attrs(report)
    report_id = str(report.get("id") or "")
    title = _first(attrs, "title")
    state = (_first(attrs, "state") or "").strip().lower() or None
    severity = _extract_severity(report, included_index)
    reporter = _extract_reporter(report, included_index)

    # Program handle from relationship when present
    program_handle = None
    for rel_name in ("program",):
        program = _resolve_rel(report, included_index, rel_name)
        if program:
            program_handle = _first(_attrs(program), "handle", "name")
            break
    if not program_handle:
        program_handle = _first(attrs, "program_handle", "handle")

    return {
        "report_id": report_id,
        "report_url": report_url_for(report_id) if report_id else None,
        "title": title,
        "state": state,
        "severity": severity.value if severity else None,
        "reporter": reporter,
        "program": program_handle,
    }


async def test_connection(
    api_identifier: str, api_token: str
) -> Dict[str, Any]:
    """Validate HackerOne credentials by fetching accessible programs."""
    client = HackerOneClient(api_identifier, api_token)
    # Probe first so we can distinguish auth failure from "zero programs".
    probe = await client._get(
        "/v1/me/programs", params={"page[size]": 1, "page[number]": 1}
    )
    if probe is None:
        return {
            "ok": False,
            "message": (
                "Could not authenticate to HackerOne. "
                "Check your API Identifier and Token."
            ),
            "program_count": None,
        }

    programs = await client.get_programs()
    count = len(programs) if isinstance(programs, list) else 0
    return {
        "ok": True,
        "message": f"Connected to HackerOne successfully ({count} program(s) accessible).",
        "program_count": count,
    }


# ── Sync helpers ──────────────────────────────────────────────────────────────


class _Stats:
    def __init__(self) -> None:
        self.assets_created = 0
        self.assets_updated = 0
        self.vulns_created = 0
        self.vulns_updated = 0
        self.programs_seen = 0
        self.scopes_seen = 0
        self.reports_seen = 0
        self.reports_skipped = 0

    def as_dict(self) -> Dict[str, int]:
        return {
            "assets_created": self.assets_created,
            "assets_updated": self.assets_updated,
            "vulns_created": self.vulns_created,
            "vulns_updated": self.vulns_updated,
            "programs_seen": self.programs_seen,
            "scopes_seen": self.scopes_seen,
            "reports_seen": self.reports_seen,
            "reports_skipped": self.reports_skipped,
        }


def _normalize_url(value: str) -> str:
    """Normalize a URL scope to https://... for consistent asset identity."""
    value = (value or "").strip()
    if not value:
        return value
    if not re.match(r"^https?://", value, re.IGNORECASE):
        value = f"https://{value}"
    parsed = urlparse(value)
    # Drop trailing slash on bare host URLs for stable identity.
    path = parsed.path.rstrip("/") if parsed.path == "/" else parsed.path
    netloc = parsed.netloc.lower()
    return f"https://{netloc}{path}" if path else f"https://{netloc}"


def _normalize_scope_value(asset_type: AssetType, raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        return raw
    if asset_type == AssetType.URL:
        return _normalize_url(raw)
    if asset_type == AssetType.DOMAIN:
        # Strip leading "*." from wildcards for domain asset value.
        return raw.lstrip("*.").lower().rstrip(".")
    if asset_type == AssetType.IP_ADDRESS:
        return raw
    if asset_type == AssetType.IP_RANGE:
        return raw
    return raw


def _upsert_asset(
    db: Session,
    org_id: int,
    value: str,
    asset_type: AssetType,
    stats: _Stats,
    *,
    metadata: Optional[Dict] = None,
    association_reason: str = "Imported from HackerOne program scope",
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
        if existing.in_scope is False:
            existing.in_scope = True
        stats.assets_updated += 1
        return existing

    asset = Asset(
        name=value[:255] if len(value) > 255 else value,
        asset_type=asset_type,
        value=value,
        organization_id=org_id,
        status=AssetStatus.DISCOVERED,
        discovery_source=DISCOVERY_SOURCE,
        association_reason=association_reason,
        association_confidence=95,
        in_scope=True,
        is_owned=True,
        tags=[f"source:{DISCOVERY_SOURCE}"],
        metadata_=metadata or {},
    )
    db.add(asset)
    db.flush()
    stats.assets_created += 1
    return asset


def _index_included(included: List[Dict]) -> Dict[Tuple[str, str], Dict]:
    """Index JSON:API included resources by (type, id)."""
    index: Dict[Tuple[str, str], Dict] = {}
    for item in included:
        if not isinstance(item, dict):
            continue
        t = item.get("type")
        i = item.get("id")
        if t and i:
            index[(str(t), str(i))] = item
    return index


def _resolve_rel(
    resource: Dict, included_index: Dict[Tuple[str, str], Dict], name: str
) -> Optional[Dict]:
    rels = resource.get("relationships") or {}
    rel = rels.get(name) or {}
    data = rel.get("data")
    if not isinstance(data, dict):
        return None
    key = (str(data.get("type")), str(data.get("id")))
    return included_index.get(key)


def _extract_severity(
    report: Dict, included_index: Dict[Tuple[str, str], Dict]
) -> Severity:
    # Prefer included severity-rating relationship.
    for rel_name in ("severity_rating", "severity-rating", "severity"):
        rating = _resolve_rel(report, included_index, rel_name)
        if rating:
            attrs = _attrs(rating)
            sev = _first(attrs, "rating", "severity", "severity_rating")
            if sev:
                return _map_severity(str(sev))
    # Inline attributes fallback.
    attrs = _attrs(report)
    sev = _first(attrs, "severity_rating", "severity", "rating")
    if isinstance(sev, dict):
        sev = _first(sev, "rating", "severity")
    return _map_severity(str(sev) if sev else None)


def _extract_cwe(
    report: Dict, included_index: Dict[Tuple[str, str], Dict]
) -> Optional[str]:
    for rel_name in ("weakness", "cwe"):
        weakness = _resolve_rel(report, included_index, rel_name)
        if weakness:
            attrs = _attrs(weakness)
            external_id = _first(attrs, "external_id", "cwe_id", "id")
            name = _first(attrs, "name", "title")
            if external_id:
                eid = str(external_id)
                if not eid.upper().startswith("CWE"):
                    eid = f"CWE-{eid}"
                return eid[:50]
            if name and "CWE-" in str(name).upper():
                match = re.search(r"CWE-?\d+", str(name), re.IGNORECASE)
                if match:
                    return match.group(0).upper().replace("CWE", "CWE-").replace("CWE--", "CWE-")[:50]
    attrs = _attrs(report)
    cwe = _first(attrs, "cwe_id", "cwe")
    return str(cwe)[:50] if cwe else None


def _extract_cvss(report: Dict, included_index: Dict[Tuple[str, str], Dict]) -> Optional[float]:
    for rel_name in ("severity_rating", "severity-rating", "severity"):
        rating = _resolve_rel(report, included_index, rel_name)
        if rating:
            attrs = _attrs(rating)
            score = _first(attrs, "score", "cvss_score", "cvss")
            if score is not None:
                try:
                    return float(score)
                except (TypeError, ValueError):
                    pass
    attrs = _attrs(report)
    score = _first(attrs, "cvss_score", "score")
    if score is not None:
        try:
            return float(score)
        except (TypeError, ValueError):
            pass
    return None


def _extract_reporter(
    report: Dict, included_index: Dict[Tuple[str, str], Dict]
) -> Optional[str]:
    reporter = _resolve_rel(report, included_index, "reporter")
    if reporter:
        attrs = _attrs(reporter)
        return _first(attrs, "username", "name", "handle")
    return None


def _extract_structured_scope(
    report: Dict, included_index: Dict[Tuple[str, str], Dict]
) -> Optional[Dict]:
    for rel_name in ("structured_scope", "structured-scope"):
        scope = _resolve_rel(report, included_index, rel_name)
        if scope:
            return scope
    return None


def _scope_to_asset_ref(scope: Dict) -> Optional[Tuple[str, AssetType]]:
    """Return (normalized_value, AssetType) for a structured scope, or None if unsupported."""
    attrs = _attrs(scope)
    raw_type = (
        _first(attrs, "asset_type", "assetType", "type") or ""
    ).strip().lower().replace(" ", "_")
    identifier = _first(attrs, "asset_identifier", "assetIdentifier", "identifier", "asset")
    if not identifier:
        return None
    asset_type = _SCOPE_TYPE_MAP.get(raw_type)
    if asset_type is None:
        return None
    value = _normalize_scope_value(asset_type, str(identifier))
    if not value:
        return None
    return value, asset_type


def _fallback_program_asset(
    db: Session, org_id: int, program_handle: str, stats: _Stats
) -> Optional[Asset]:
    """Synthetic asset used when a report has no supported structured scope."""
    value = f"hackerone:{program_handle}"
    return _upsert_asset(
        db,
        org_id,
        value,
        AssetType.OTHER,
        stats,
        metadata={"hackerone_program": program_handle, "synthetic": True},
        association_reason="Fallback asset for HackerOne reports without a supported scope",
    )


def _import_scope(
    db: Session,
    org_id: int,
    scope: Dict,
    program_handle: str,
    stats: _Stats,
) -> Optional[Asset]:
    attrs = _attrs(scope)
    eligible = attrs.get("eligible_for_submission")
    if eligible is False:
        return None
    # Some payloads use eligible_for_bounty; prefer submission eligibility.
    if eligible is None and attrs.get("eligible_for_bounty") is False:
        # Still import if explicitly marked eligible_for_submission elsewhere;
        # when both are missing, treat as eligible (HackerOne default for listed scopes).
        pass

    ref = _scope_to_asset_ref(scope)
    if not ref:
        return None
    value, asset_type = ref
    stats.scopes_seen += 1
    return _upsert_asset(
        db,
        org_id,
        value,
        asset_type,
        stats,
        metadata={
            "hackerone_program": program_handle,
            "hackerone_scope_id": scope.get("id"),
            "hackerone_asset_type": _first(attrs, "asset_type", "assetType"),
            "source": DISCOVERY_SOURCE,
        },
    )


def upsert_report_link(
    db: Session,
    integration: HackerOneIntegration,
    vulnerability_id: int,
    *,
    report_id: str,
    report_url: Optional[str] = None,
    program: Optional[str] = None,
    title: Optional[str] = None,
    state: Optional[str] = None,
    severity: Optional[str] = None,
    reporter: Optional[str] = None,
    is_associated: bool = False,
) -> HackerOneReportLink:
    """Create or refresh a HackerOne report link for a vulnerability."""
    report_id = str(report_id)
    url = report_url or report_url_for(report_id)

    link = (
        db.query(HackerOneReportLink)
        .filter(
            HackerOneReportLink.vulnerability_id == vulnerability_id,
            HackerOneReportLink.hackerone_report_id == report_id,
        )
        .first()
    )
    if link:
        # Reactivate if previously disconnected
        link.disconnected_at = None
        link.integration_id = integration.id
        if program:
            link.hackerone_program = program
        if title:
            link.hackerone_title = (title or "")[:500]
        if state:
            link.hackerone_state = state
        if severity:
            link.hackerone_severity = severity
        if reporter:
            link.hackerone_reporter = reporter
        link.hackerone_report_url = url
        link.updated_at = datetime.utcnow()
        # Don't downgrade a manual association to sync-imported
        if is_associated:
            link.is_associated = True
        return link

    link = HackerOneReportLink(
        integration_id=integration.id,
        vulnerability_id=vulnerability_id,
        hackerone_report_id=report_id,
        hackerone_report_url=url,
        hackerone_program=program,
        hackerone_title=(title or "")[:500] if title else None,
        hackerone_state=state,
        hackerone_severity=severity,
        hackerone_reporter=reporter,
        is_associated=is_associated,
    )
    db.add(link)
    db.flush()
    return link


def _import_report(
    db: Session,
    org_id: int,
    report: Dict,
    included_index: Dict[Tuple[str, str], Dict],
    program_handle: str,
    asset_index: Dict[str, Asset],
    stats: _Stats,
    can_create_assets: bool,
    integration: HackerOneIntegration,
) -> None:
    """Import a single HackerOne report as a Vulnerability."""
    report_id = report.get("id")
    attrs = _attrs(report)
    title = _first(attrs, "title") or "HackerOne report"
    state = (_first(attrs, "state") or "new").strip().lower()
    status = _map_status(state)
    severity = _extract_severity(report, included_index)
    description = _first(attrs, "vulnerability_information", "vulnerabilityInformation")
    impact = _first(attrs, "impact")
    submitted_at = _first(attrs, "created_at", "submitted_at")
    cwe_id = _extract_cwe(report, included_index)
    cvss_score = _extract_cvss(report, included_index)
    reporter = _extract_reporter(report, included_index)
    cve_ids = attrs.get("cve_ids") or attrs.get("cve_id")
    cve_id = None
    if isinstance(cve_ids, list) and cve_ids:
        cve_id = str(cve_ids[0])[:50]
    elif isinstance(cve_ids, str):
        cve_id = cve_ids[:50]

    stats.reports_seen += 1

    # Resolve target asset from structured scope, else fallback.
    asset: Optional[Asset] = None
    scope = _extract_structured_scope(report, included_index)
    if scope:
        ref = _scope_to_asset_ref(scope)
        if ref:
            value, asset_type = ref
            asset = asset_index.get(value)
            if asset is None:
                asset = (
                    db.query(Asset)
                    .filter(Asset.organization_id == org_id, Asset.value == value)
                    .first()
                )
            if asset is None and can_create_assets:
                asset = _upsert_asset(db, org_id, value, asset_type, stats)
                if asset:
                    asset_index[value] = asset

    if asset is None:
        if can_create_assets:
            asset = _fallback_program_asset(db, org_id, program_handle, stats)
            if asset:
                asset_index[asset.value] = asset
        else:
            # Try existing fallback.
            fallback_value = f"hackerone:{program_handle}"
            asset = asset_index.get(fallback_value) or (
                db.query(Asset)
                .filter(Asset.organization_id == org_id, Asset.value == fallback_value)
                .first()
            )

    if asset is None:
        stats.reports_skipped += 1
        return

    # Dedup by HackerOne report id in metadata.
    existing = None
    if report_id:
        existing = (
            db.query(Vulnerability)
            .filter(
                Vulnerability.metadata_["hackerone_report_id"].astext == str(report_id),
            )
            .first()
        )
        # Prefer same-org match when possible (metadata filter is global).
        if existing and existing.asset and existing.asset.organization_id != org_id:
            existing = None
    if existing is None and report_id:
        # Org-scoped fallback via asset join.
        existing = (
            db.query(Vulnerability)
            .join(Asset, Vulnerability.asset_id == Asset.id)
            .filter(
                Asset.organization_id == org_id,
                Vulnerability.metadata_["hackerone_report_id"].astext == str(report_id),
            )
            .first()
        )
    if existing is None:
        existing = (
            db.query(Vulnerability)
            .filter(
                Vulnerability.asset_id == asset.id,
                Vulnerability.title == title[:500],
                Vulnerability.detected_by == DISCOVERY_SOURCE,
            )
            .first()
        )

    report_url = report_url_for(str(report_id)) if report_id else None
    metadata = {
        "hackerone_report_id": str(report_id) if report_id else None,
        "hackerone_state": state,
        "hackerone_program": program_handle,
        "hackerone_reporter": reporter,
        "hackerone_submitted_at": submitted_at,
        "hackerone_report_url": report_url,
        "source": DISCOVERY_SOURCE,
    }

    vuln: Optional[Vulnerability] = None
    if existing:
        existing.severity = severity
        existing.status = status
        existing.last_detected = datetime.utcnow()
        existing.description = description or existing.description
        existing.impact = impact or existing.impact
        if cwe_id:
            existing.cwe_id = cwe_id
        if cvss_score is not None:
            existing.cvss_score = cvss_score
        if cve_id:
            existing.cve_id = cve_id
        if status == VulnerabilityStatus.RESOLVED and not existing.resolved_at:
            existing.resolved_at = datetime.utcnow()
        meta = dict(existing.metadata_ or {})
        meta.update({k: v for k, v in metadata.items() if v is not None})
        existing.metadata_ = meta
        if report_url:
            refs = list(existing.references or [])
            if report_url not in refs:
                refs.append(report_url)
                existing.references = refs
        stats.vulns_updated += 1
        vuln = existing
    else:
        refs = [report_url] if report_url else []
        vuln = Vulnerability(
            title=title[:500],
            description=description,
            impact=impact,
            severity=severity,
            cvss_score=cvss_score,
            cwe_id=cwe_id,
            cve_id=cve_id,
            references=refs,
            asset_id=asset.id,
            detected_by=DISCOVERY_SOURCE,
            status=status,
            resolved_at=datetime.utcnow() if status == VulnerabilityStatus.RESOLVED else None,
            tags=["source:hackerone", f"program:{program_handle}"],
            metadata_=metadata,
        )
        db.add(vuln)
        db.flush()
        stats.vulns_created += 1

    if vuln and report_id:
        upsert_report_link(
            db,
            integration,
            vuln.id,
            report_id=str(report_id),
            report_url=report_url,
            program=program_handle,
            title=title,
            state=state,
            severity=severity.value if severity else None,
            reporter=reporter,
            is_associated=False,
        )


async def sync_integration(
    db: Session, integration: HackerOneIntegration
) -> Dict[str, Any]:
    """Pull programs, scopes, and reports from HackerOne and import them.

    Returns a result dict compatible with :class:`HackerOneSyncResult`.
    """
    org_id = integration.organization_id
    api_identifier = integration.api_identifier
    api_token = integration.get_api_token()
    if not api_identifier or not api_token:
        return {"ok": False, "message": "No HackerOne credentials stored for this connection."}

    client = HackerOneClient(api_identifier, api_token)
    stats = _Stats()
    asset_index: Dict[str, Asset] = {}

    try:
        programs = await client.get_programs()
        # Distinguish auth failure from an empty program list.
        if not programs:
            probe = await client._get(
                "/v1/me/programs", params={"page[size]": 1, "page[number]": 1}
            )
            if probe is None:
                integration.last_sync_at = datetime.utcnow()
                integration.last_sync_ok = False
                integration.last_error = "Authentication failed talking to HackerOne."
                db.commit()
                return {
                    "ok": False,
                    "message": "Authentication failed talking to HackerOne.",
                    **stats.as_dict(),
                }

        stats.programs_seen = len(programs)

        for program in programs:
            program_id = str(program.get("id") or "")
            pattrs = _attrs(program)
            handle = _first(pattrs, "handle", "name") or program_id
            if not handle:
                continue

            if integration.import_scopes and program_id:
                scopes = await client.get_structured_scopes(program_id)
                for scope in scopes:
                    asset = _import_scope(db, org_id, scope, handle, stats)
                    if asset:
                        asset_index[asset.value] = asset
                db.commit()

            if integration.import_vulnerabilities:
                reports, included = await client.get_reports(handle)
                included_index = _index_included(included)
                for report in reports:
                    if not isinstance(report, dict):
                        continue
                    _import_report(
                        db,
                        org_id,
                        report,
                        included_index,
                        handle,
                        asset_index,
                        stats,
                        can_create_assets=integration.import_scopes,
                        integration=integration,
                    )
                db.commit()

            await asyncio.sleep(client.RATE_LIMIT_DELAY)

        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = True
        integration.last_error = None
        integration.last_sync_stats = stats.as_dict()
        db.commit()

        return {
            "ok": True,
            "message": (
                f"Imported {stats.assets_created} new asset(s) and "
                f"{stats.vulns_created} new report(s) from HackerOne "
                f"({stats.programs_seen} program(s))."
            ),
            **stats.as_dict(),
        }
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        logger.exception("HackerOne sync failed for org %s", org_id)
        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = False
        integration.last_error = str(exc)[:1000]
        db.commit()
        return {"ok": False, "message": f"Sync failed: {exc}", **stats.as_dict()}
