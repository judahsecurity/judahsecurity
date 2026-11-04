"""Read-only SecurityScorecard client and security-ratings importer.

Imports every company domain across the account's portfolios as a domain asset,
records its score, grade, risk-factor scores and six months of score history as
asset attributes, and imports each active issue as a vulnerability carrying a
shared issue-type definition plus per-instance evidence.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Set
from urllib.parse import quote

import httpx
from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetStatus, AssetType
from app.models.securityscorecard_integration import SecurityScorecardIntegration
from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus

logger = logging.getLogger(__name__)

DISCOVERY_SOURCE = "securityscorecard"
SOURCE_TAG = f"source:{DISCOVERY_SOURCE}"
TEMPLATE_PREFIX = f"{DISCOVERY_SOURCE}:"
API_BASE_URL = "https://api.securityscorecard.io"
PLATFORM_BASE_URL = "https://platform.securityscorecard.io"

MAX_CONCURRENT_COMPANIES = 10
# Caps in-flight HTTP requests across all companies (issue findings fan out per company).
MAX_CONCURRENT_REQUESTS = 20
SCORE_HISTORY_MONTHS = 6
MAX_FINDINGS_IN_EVIDENCE = 50
MAX_FINDINGS_IN_METADATA = 100
RETRYABLE_STATUS = {429, 500, 502, 503, 504}
MAX_ATTEMPTS = 4

# SecurityScorecard severity -> Judah severity. "positive" issues are healthy
# practices, not risks, and are never imported. Unknown values fall back to INFO.
_SEVERITY_MAP = {
    "high": Severity.CRITICAL,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}
POSITIVE_SEVERITY = "positive"

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$"
)
_FINDING_TIME_KEYS = ("first_seen_time", "last_seen_time", "first_seen", "last_seen")
_FINDING_SKIP_KEYS = set(_FINDING_TIME_KEYS) | {"issue_id", "parent_domain", "count", "group_status"}


class SecurityScorecardApiError(RuntimeError):
    """A safe, user-displayable SecurityScorecard API error."""

    def __init__(self, message: str, status_code: Optional[int] = None) -> None:
        super().__init__(message)
        self.status_code = status_code


# ──────────────────────────────────────────────────────────────────────────────
# API client
# ──────────────────────────────────────────────────────────────────────────────


class SecurityScorecardClient:
    """Minimal token-authenticated client for the SecurityScorecard REST API."""

    def __init__(
        self,
        api_key: str,
        *,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        timeout: float = 30.0,
    ) -> None:
        if not api_key:
            raise SecurityScorecardApiError("A SecurityScorecard API key is required.")
        self._api_key = api_key.strip()
        self._transport = transport
        self._sleep = sleep
        self._timeout = timeout
        self._http: Optional[httpx.AsyncClient] = None
        self._limit = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

    async def __aenter__(self) -> "SecurityScorecardClient":
        self._http = httpx.AsyncClient(
            base_url=API_BASE_URL,
            timeout=self._timeout,
            transport=self._transport,
            headers={
                # Token scheme, not Bearer.
                "Authorization": f"Token {self._api_key}",
                "Accept": "application/json",
            },
        )
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    async def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        if self._http is None:
            raise RuntimeError("SecurityScorecardClient must be used as an async context manager.")
        for attempt in range(MAX_ATTEMPTS):
            last = attempt == MAX_ATTEMPTS - 1
            try:
                async with self._limit:
                    response = await self._http.get(path, params=params)
            except httpx.TransportError as exc:
                # Connection resets, timeouts, DNS hiccups.
                if last:
                    raise SecurityScorecardApiError(
                        f"Could not reach the SecurityScorecard API: {exc.__class__.__name__}"
                    ) from exc
                await self._sleep(2**attempt)
                continue
            if response.status_code in RETRYABLE_STATUS and not last:
                retry_after = response.headers.get("Retry-After", "")
                delay = float(retry_after) if retry_after.isdigit() else 2**attempt
                await self._sleep(min(delay, 30.0))
                continue
            if response.status_code == 401:
                raise SecurityScorecardApiError(
                    "SecurityScorecard rejected the API key (HTTP 401); check that it is valid and not revoked.",
                    401,
                )
            if response.status_code != 200:
                raise SecurityScorecardApiError(
                    f"SecurityScorecard request failed (HTTP {response.status_code}).",
                    response.status_code,
                )
            try:
                return response.json()
            except ValueError as exc:
                raise SecurityScorecardApiError(
                    "SecurityScorecard returned an invalid JSON response."
                ) from exc
        raise SecurityScorecardApiError("SecurityScorecard request failed after retries.")

    @staticmethod
    def _entries(payload: Any) -> List[Dict[str, Any]]:
        if isinstance(payload, dict):
            payload = payload.get("entries")
        if not isinstance(payload, list):
            return []
        return [item for item in payload if isinstance(item, dict)]

    async def list_portfolios(self) -> List[Dict[str, Any]]:
        return self._entries(await self.get("/portfolios"))

    async def list_portfolio_companies(self, portfolio_id: str) -> List[Dict[str, Any]]:
        return self._entries(await self.get(f"/portfolios/{_seg(portfolio_id)}/companies"))

    async def get_factors(self, domain: str) -> List[Dict[str, Any]]:
        return self._entries(await self.get(f"/companies/{_seg(domain)}/factors"))

    async def get_issue_findings(self, domain: str, issue_type: str) -> List[Dict[str, Any]]:
        return self._entries(
            await self.get(f"/companies/{_seg(domain)}/issues/{_seg(issue_type)}/")
        )

    async def get_issue_type(self, issue_type: str) -> Dict[str, Any]:
        payload = await self.get(f"/metadata/issue-types/{_seg(issue_type)}")
        return payload if isinstance(payload, dict) else {}

    async def get_score_history(self, domain: str, start: date, end: date) -> List[Dict[str, Any]]:
        return self._entries(
            await self.get(
                f"/companies/{_seg(domain)}/history/score",
                params={"from": start.isoformat(), "to": end.isoformat(), "timing": "monthly"},
            )
        )


def _seg(value: Any) -> str:
    """Quote one URL path segment so vendor data cannot alter the request path."""
    return quote(str(value), safe="")


# ──────────────────────────────────────────────────────────────────────────────
# Normalization helpers
# ──────────────────────────────────────────────────────────────────────────────


def normalize_domain(value: Any) -> Optional[str]:
    domain = str(value or "").strip().lower().rstrip(".")
    return domain if _DOMAIN_RE.match(domain) else None


def map_severity(value: Any) -> Optional[Severity]:
    """Map a SecurityScorecard severity; returns None for positive (not-a-risk) issues."""
    key = str(value or "").strip().lower()
    if key == POSITIVE_SEVERITY:
        return None
    return _SEVERITY_MAP.get(key, Severity.INFO)


def title_from_slug(issue_type: str) -> str:
    words = [word for word in re.split(r"[_\-\s]+", issue_type or "") if word]
    return " ".join(word.capitalize() for word in words) or "SecurityScorecard Issue"


def platform_issue_url(domain: str, factor: Optional[str], issue_type: str) -> str:
    factor_part = _seg(factor) if factor else "all"
    return (
        f"{PLATFORM_BASE_URL}/#/scorecard/{_seg(domain)}/issues/"
        f"{factor_part}/{_seg(issue_type)}/"
    )


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


def _number(value: Any) -> Optional[float]:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return int(number) if number.is_integer() else round(number, 2)


def score_history_attributes(entries: Iterable[Dict[str, Any]]) -> List[str]:
    """Render history points as ``YYYY-MM-DD:score`` strings, oldest first."""
    points: Dict[str, Any] = {}
    for entry in entries:
        when = _parse_datetime(entry.get("date"))
        score = _number(entry.get("score"))
        if when is None or score is None:
            continue
        points[when.date().isoformat()] = score
    return [f"{day}:{points[day]}" for day in sorted(points)]


def _issue_type(issue: Dict[str, Any]) -> Optional[str]:
    value = issue.get("type") or issue.get("issue_type") or issue.get("key")
    return str(value).strip() if value else None


def definition_fields(definition: Optional[Dict[str, Any]]) -> Dict[str, Optional[str]]:
    definition = definition or {}

    def pick(*keys: str) -> Optional[str]:
        for key in keys:
            value = definition.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None

    return {
        "title": pick("title", "name"),
        "description": pick("long_description", "description", "short_description"),
        "impact": pick("impact", "risk", "why_it_matters"),
        "remediation": pick("recommendation", "remediation", "remediation_guidance"),
    }


def _format_observations(finding: Dict[str, Any]) -> str:
    parts = []
    for key, value in finding.items():
        if key in _FINDING_SKIP_KEYS or value in (None, "", [], {}):
            continue
        if isinstance(value, (list, tuple)):
            value = ", ".join(str(item) for item in value)
        elif isinstance(value, dict):
            value = ", ".join(f"{k}={v}" for k, v in value.items())
        parts.append(f"{key}={value}")
    return "; ".join(parts)


def build_evidence(
    *,
    domain: str,
    issue_type: str,
    factor: Optional[str],
    ssc_severity: str,
    count: Any,
    score_impact: Any,
    findings: Optional[List[Dict[str, Any]]],
    platform_url: str,
) -> str:
    lines = [
        "SecurityScorecard issue overview",
        f"- Domain: {domain}",
        f"- Issue type: {issue_type}",
        f"- Factor: {factor or 'unknown'}",
        f"- Severity: {ssc_severity or 'unknown'}",
        f"- Active findings: {count if count is not None else 'unknown'}",
        f"- Score impact: {score_impact if score_impact is not None else 'unknown'}",
    ]
    if findings:
        lines.append("")
        lines.append(f"Findings ({len(findings)})")
        for finding in findings[:MAX_FINDINGS_IN_EVIDENCE]:
            first = finding.get("first_seen_time") or finding.get("first_seen") or "unknown"
            last = finding.get("last_seen_time") or finding.get("last_seen") or "unknown"
            observations = _format_observations(finding)
            line = f"- first seen {first}, last seen {last}"
            lines.append(f"{line}: {observations}" if observations else line)
        if len(findings) > MAX_FINDINGS_IN_EVIDENCE:
            lines.append(f"- … {len(findings) - MAX_FINDINGS_IN_EVIDENCE} more in SecurityScorecard")
    lines.append("")
    lines.append(f"View in SecurityScorecard: {platform_url}")
    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────────────
# Fetch phase (network only, concurrent)
# ──────────────────────────────────────────────────────────────────────────────


@dataclass
class _Company:
    domain: str
    name: Optional[str] = None
    score: Any = None
    grade: Optional[str] = None
    industry: Optional[str] = None
    portfolios: List[str] = field(default_factory=list)


@dataclass
class _IssueBundle:
    issue_type: str
    factor: Optional[str]
    ssc_severity: str
    severity: Severity
    count: Any
    score_impact: Any
    findings: Optional[List[Dict[str, Any]]]
    definition: Dict[str, Optional[str]]


@dataclass
class _CompanyBundle:
    company: _Company
    factors: Optional[List[Dict[str, Any]]] = None
    factors_error: Optional[str] = None
    history: List[str] = field(default_factory=list)
    issues: List[_IssueBundle] = field(default_factory=list)


class _DefinitionCache:
    """Fetches each issue-type definition at most once per sync, even under concurrency."""

    def __init__(self, client: SecurityScorecardClient) -> None:
        self._client = client
        self._tasks: Dict[str, asyncio.Task] = {}

    async def get(self, issue_type: str) -> Dict[str, Optional[str]]:
        task = self._tasks.get(issue_type)
        if task is None:
            task = asyncio.ensure_future(self._fetch(issue_type))
            self._tasks[issue_type] = task
        return await task

    async def _fetch(self, issue_type: str) -> Dict[str, Optional[str]]:
        try:
            return definition_fields(await self._client.get_issue_type(issue_type))
        except SecurityScorecardApiError as exc:
            logger.info("SecurityScorecard definition unavailable for %s: %s", issue_type, exc)
            return definition_fields(None)

    @property
    def fetched(self) -> int:
        return len(self._tasks)


async def collect_companies(client: SecurityScorecardClient) -> tuple[int, Dict[str, _Company]]:
    portfolios = await client.list_portfolios()
    companies: Dict[str, _Company] = {}
    for portfolio in portfolios:
        portfolio_id = portfolio.get("id")
        if portfolio_id in (None, ""):
            continue
        portfolio_name = str(portfolio.get("name") or portfolio_id)
        for entry in await client.list_portfolio_companies(str(portfolio_id)):
            domain = normalize_domain(entry.get("domain"))
            if not domain:
                continue
            company = companies.get(domain)
            if company is None:
                company = companies[domain] = _Company(
                    domain=domain,
                    name=entry.get("name"),
                    score=_number(entry.get("score")),
                    grade=entry.get("grade"),
                    industry=entry.get("industry"),
                )
            if portfolio_name not in company.portfolios:
                company.portfolios.append(portfolio_name)
    return len(portfolios), companies


async def _fetch_company(
    client: SecurityScorecardClient,
    definitions: _DefinitionCache,
    company: _Company,
    *,
    import_vulnerabilities: bool,
    today: date,
) -> _CompanyBundle:
    bundle = _CompanyBundle(company=company)
    try:
        bundle.factors = await client.get_factors(company.domain)
    except SecurityScorecardApiError as exc:
        # e.g. HTTP 403 for a private custom scorecard not shared with this key.
        if exc.status_code == 401:
            raise
        logger.warning(
            "SecurityScorecard factors unavailable for %s (%s); skipping factors and risks",
            company.domain,
            exc,
        )
        bundle.factors_error = str(exc)

    try:
        start = today - timedelta(days=SCORE_HISTORY_MONTHS * 31)
        bundle.history = score_history_attributes(
            await client.get_score_history(company.domain, start, today)
        )
    except SecurityScorecardApiError as exc:
        if exc.status_code == 401:
            raise
        logger.info("SecurityScorecard score history unavailable for %s: %s", company.domain, exc)

    if not import_vulnerabilities or not bundle.factors:
        return bundle

    pending = []
    for factor in bundle.factors:
        factor_name = factor.get("name")
        for issue in factor.get("issue_summary") or []:
            if not isinstance(issue, dict):
                continue
            issue_type = _issue_type(issue)
            ssc_severity = str(issue.get("severity") or "").strip().lower()
            severity = map_severity(ssc_severity)
            if not issue_type or severity is None:
                continue
            pending.append((factor_name, issue, issue_type, ssc_severity, severity))

    async def build(factor_name, issue, issue_type, ssc_severity, severity) -> _IssueBundle:
        try:
            findings: Optional[List[Dict[str, Any]]] = await client.get_issue_findings(
                company.domain, issue_type
            )
        except SecurityScorecardApiError as exc:
            if exc.status_code == 401:
                raise
            logger.info(
                "SecurityScorecard findings unavailable for %s/%s: %s",
                company.domain,
                issue_type,
                exc,
            )
            findings = None
        return _IssueBundle(
            issue_type=issue_type,
            factor=factor_name,
            ssc_severity=ssc_severity,
            severity=severity,
            count=issue.get("count"),
            score_impact=_number(issue.get("total_score_impact", issue.get("score_impact"))),
            findings=findings,
            definition=await definitions.get(issue_type),
        )

    bundle.issues = list(await asyncio.gather(*(build(*item) for item in pending)))
    return bundle


async def fetch_bundles(
    client: SecurityScorecardClient,
    companies: Iterable[_Company],
    *,
    import_vulnerabilities: bool,
    today: Optional[date] = None,
    concurrency: int = MAX_CONCURRENT_COMPANIES,
) -> tuple[List[_CompanyBundle], int]:
    definitions = _DefinitionCache(client)
    semaphore = asyncio.Semaphore(concurrency)
    today = today or datetime.utcnow().date()

    async def run(company: _Company) -> _CompanyBundle:
        async with semaphore:
            return await _fetch_company(
                client,
                definitions,
                company,
                import_vulnerabilities=import_vulnerabilities,
                today=today,
            )

    bundles = await asyncio.gather(*(run(company) for company in companies))
    return list(bundles), definitions.fetched


# ──────────────────────────────────────────────────────────────────────────────
# Persist phase (DB only, serial)
# ──────────────────────────────────────────────────────────────────────────────


class _Stats:
    def __init__(self) -> None:
        self.portfolios_seen = 0
        self.companies_seen = 0
        self.companies_skipped = 0
        self.factors_unavailable = 0
        self.assets_created = 0
        self.assets_updated = 0
        self.vulns_created = 0
        self.vulns_updated = 0
        self.vulns_resolved = 0
        self.definitions_fetched = 0

    def as_dict(self) -> Dict[str, int]:
        return vars(self).copy()


def _ssc_attributes(bundle: _CompanyBundle) -> Dict[str, Any]:
    company = bundle.company
    factor_scores: Dict[str, Any] = {}
    factor_grades: Dict[str, Any] = {}
    for factor in bundle.factors or []:
        name = factor.get("name")
        if not name:
            continue
        factor_scores[str(name)] = _number(factor.get("score"))
        if factor.get("grade"):
            factor_grades[str(name)] = factor.get("grade")
    attributes: Dict[str, Any] = {
        "score": company.score,
        "grade": company.grade,
        "factors": factor_scores,
        "factor_grades": factor_grades,
        "score_history": bundle.history,
        "company_name": company.name,
        "industry": company.industry,
        "portfolios": company.portfolios,
        "scorecard_url": f"{PLATFORM_BASE_URL}/#/scorecard/{_seg(company.domain)}/",
        "synced_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
    }
    if bundle.factors_error:
        attributes["factors_error"] = bundle.factors_error
    return attributes


def _upsert_asset(
    db: Session, org_id: int, bundle: _CompanyBundle, existing: Optional[Asset], stats: _Stats
) -> Asset:
    domain = bundle.company.domain
    attributes = _ssc_attributes(bundle)
    if existing is not None:
        metadata = dict(existing.metadata_ or {})
        previous = metadata.get(DISCOVERY_SOURCE) or {}
        if bundle.factors is None and previous.get("factors"):
            # Keep the last known factor scores when this run could not read them.
            attributes["factors"] = previous.get("factors")
            attributes["factor_grades"] = previous.get("factor_grades") or {}
        if not attributes["score_history"] and previous.get("score_history"):
            attributes["score_history"] = previous.get("score_history")
        metadata[DISCOVERY_SOURCE] = attributes
        existing.metadata_ = metadata
        existing.last_seen = datetime.utcnow()
        tags = list(existing.tags or [])
        if SOURCE_TAG not in tags:
            tags.append(SOURCE_TAG)
            existing.tags = tags
        stats.assets_updated += 1
        return existing

    asset = Asset(
        name=domain,
        asset_type=AssetType.DOMAIN,
        value=domain,
        root_domain=domain,
        organization_id=org_id,
        status=AssetStatus.DISCOVERED,
        discovery_source=DISCOVERY_SOURCE,
        association_reason="Company domain in a SecurityScorecard portfolio",
        association_confidence=90,
        tags=[SOURCE_TAG],
        metadata_={DISCOVERY_SOURCE: attributes},
    )
    db.add(asset)
    db.flush()
    stats.assets_created += 1
    return asset


def _upsert_vulnerability(
    db: Session, asset: Asset, domain: str, issue: _IssueBundle, stats: _Stats
) -> None:
    template_id = f"{TEMPLATE_PREFIX}{issue.issue_type}"[:255]
    existing = (
        db.query(Vulnerability)
        .filter(
            Vulnerability.asset_id == asset.id,
            Vulnerability.detected_by == DISCOVERY_SOURCE,
            Vulnerability.template_id == template_id,
        )
        .first()
    )
    definition = issue.definition
    url = platform_issue_url(domain, issue.factor, issue.issue_type)
    title = (definition.get("title") or title_from_slug(issue.issue_type))[:500]
    evidence = build_evidence(
        domain=domain,
        issue_type=issue.issue_type,
        factor=issue.factor,
        ssc_severity=issue.ssc_severity,
        count=issue.count,
        score_impact=issue.score_impact,
        findings=issue.findings,
        platform_url=url,
    )
    seen_times = [
        _parse_datetime(f.get("first_seen_time") or f.get("first_seen")) for f in issue.findings or []
    ]
    last_times = [
        _parse_datetime(f.get("last_seen_time") or f.get("last_seen")) for f in issue.findings or []
    ]
    first_detected = min((t for t in seen_times if t), default=None)
    last_detected = max((t for t in last_times if t), default=None) or datetime.utcnow()
    metadata = {
        "source": DISCOVERY_SOURCE,
        "issue_type": issue.issue_type,
        "factor": issue.factor,
        "ssc_severity": issue.ssc_severity,
        "active_findings": issue.count,
        "score_impact": issue.score_impact,
        "platform_url": url,
        "findings_available": issue.findings is not None,
        "findings": (issue.findings or [])[:MAX_FINDINGS_IN_METADATA],
    }

    if existing is not None:
        existing.title = title
        existing.severity = issue.severity
        existing.evidence = evidence
        existing.references = [url]
        existing.last_detected = last_detected
        existing.metadata_ = metadata
        # Shared definition: only overwrite when this run actually fetched it.
        if definition.get("description"):
            existing.description = definition["description"]
        if definition.get("impact"):
            existing.impact = definition["impact"]
        if definition.get("remediation"):
            existing.remediation = definition["remediation"]
        if existing.status == VulnerabilityStatus.RESOLVED:
            existing.status = VulnerabilityStatus.OPEN
            existing.resolved_at = None
        stats.vulns_updated += 1
        return

    db.add(
        Vulnerability(
            title=title,
            description=definition.get("description"),
            impact=definition.get("impact"),
            remediation=definition.get("remediation"),
            evidence=evidence,
            severity=issue.severity,
            references=[url],
            affected_component=domain,
            asset_id=asset.id,
            detected_by=DISCOVERY_SOURCE,
            template_id=template_id,
            status=VulnerabilityStatus.OPEN,
            first_detected=first_detected or datetime.utcnow(),
            last_detected=last_detected,
            tags=[SOURCE_TAG] + ([f"ssc-factor:{issue.factor}"] if issue.factor else []),
            metadata_=metadata,
        )
    )
    stats.vulns_created += 1


def _resolve_missing(db: Session, asset: Asset, active_template_ids: Set[str], stats: _Stats) -> None:
    """Resolve SecurityScorecard issues on this asset that are no longer active."""
    open_vulns = (
        db.query(Vulnerability)
        .filter(
            Vulnerability.asset_id == asset.id,
            Vulnerability.detected_by == DISCOVERY_SOURCE,
            Vulnerability.status == VulnerabilityStatus.OPEN,
        )
        .all()
    )
    now = datetime.utcnow()
    for vuln in open_vulns:
        if vuln.template_id not in active_template_ids:
            vuln.status = VulnerabilityStatus.RESOLVED
            vuln.resolved_at = now
            stats.vulns_resolved += 1


def persist_bundles(
    db: Session,
    integration: SecurityScorecardIntegration,
    bundles: Iterable[_CompanyBundle],
    stats: _Stats,
) -> None:
    org_id = integration.organization_id
    for bundle in bundles:
        domain = bundle.company.domain
        existing = (
            db.query(Asset).filter(Asset.organization_id == org_id, Asset.value == domain).first()
        )
        if existing is None and not integration.import_assets:
            stats.companies_skipped += 1
            continue
        if bundle.factors is None:
            stats.factors_unavailable += 1
        asset = _upsert_asset(db, org_id, bundle, existing, stats)
        # Only reconcile risks when the factors (issue summaries) were read successfully;
        # a refused factors call must not resolve previously imported risks.
        if not integration.import_vulnerabilities or bundle.factors is None:
            continue
        active: Set[str] = set()
        for issue in bundle.issues:
            _upsert_vulnerability(db, asset, domain, issue, stats)
            active.add(f"{TEMPLATE_PREFIX}{issue.issue_type}"[:255])
        _resolve_missing(db, asset, active, stats)


# ──────────────────────────────────────────────────────────────────────────────
# Public entry points
# ──────────────────────────────────────────────────────────────────────────────


async def test_connection(
    api_key: str, *, transport: Optional[httpx.AsyncBaseTransport] = None
) -> Dict[str, Any]:
    try:
        async with SecurityScorecardClient(api_key, transport=transport) as client:
            portfolios = await client.list_portfolios()
        return {
            "ok": True,
            "message": f"Connected to SecurityScorecard; {len(portfolios)} portfolio(s) accessible.",
            "portfolios_accessible": len(portfolios),
        }
    except SecurityScorecardApiError as exc:
        return {"ok": False, "message": str(exc), "portfolios_accessible": 0}


async def sync_integration(
    db: Session,
    integration: SecurityScorecardIntegration,
    *,
    transport: Optional[httpx.AsyncBaseTransport] = None,
) -> Dict[str, Any]:
    stats = _Stats()
    try:
        api_key = integration.get_api_key()
        if not api_key:
            raise SecurityScorecardApiError("No SecurityScorecard API key is stored for this connection.")
        async with SecurityScorecardClient(api_key, transport=transport) as client:
            stats.portfolios_seen, companies = await collect_companies(client)
            stats.companies_seen = len(companies)
            targets = list(companies.values())
            if not integration.import_assets and targets:
                # Enrich-only mode: skip API calls for domains that are not already assets.
                rows = (
                    db.query(Asset.value)
                    .filter(
                        Asset.organization_id == integration.organization_id,
                        Asset.value.in_(list(companies)),
                    )
                    .all()
                )
                known = {value for (value,) in rows}
                stats.companies_skipped = sum(1 for c in targets if c.domain not in known)
                targets = [c for c in targets if c.domain in known]
            bundles, stats.definitions_fetched = await fetch_bundles(
                client, targets, import_vulnerabilities=integration.import_vulnerabilities
            )

        persist_bundles(db, integration, bundles, stats)
        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = True
        integration.last_error = None
        integration.last_sync_stats = stats.as_dict()
        db.commit()
        return {
            "ok": True,
            "message": (
                f"Imported {stats.companies_seen} company domain(s) from {stats.portfolios_seen} "
                f"portfolio(s): {stats.assets_created} new asset(s), {stats.vulns_created} new "
                f"and {stats.vulns_updated} updated risk(s), {stats.vulns_resolved} resolved."
            ),
            **stats.as_dict(),
        }
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        logger.exception(
            "SecurityScorecard sync failed for organization %s", integration.organization_id
        )
        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = False
        integration.last_error = str(exc)[:1000]
        db.commit()
        return {"ok": False, "message": f"Sync failed: {exc}", **stats.as_dict()}
