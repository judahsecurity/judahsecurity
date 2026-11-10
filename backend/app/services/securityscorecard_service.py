"""Read-only SecurityScorecard client and portfolio importer.

Pulls every company domain across the account's portfolios, their overall
score/grade, risk-factor scores, six months of monthly score history, and the
active issues behind each factor. Domains become ``DOMAIN`` assets; issues
become vulnerabilities ("risks") with a shared per-issue-type definition and
per-instance evidence. Nothing is ever written back to SecurityScorecard.

Network work is done concurrently (bounded) up front; database writes happen
afterwards on the calling thread so the SQLAlchemy session is never shared
across tasks.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set
from urllib.parse import quote

import httpx
from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetStatus, AssetType
from app.models.securityscorecard_integration import SecurityScorecardIntegration
from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus

logger = logging.getLogger(__name__)

DISCOVERY_SOURCE = "securityscorecard"
SOURCE_TAG = "source:securityscorecard"
GRADE_TAG_PREFIX = "ssc-grade:"
API_BASE_URL = "https://api.securityscorecard.io"
PLATFORM_BASE_URL = "https://platform.securityscorecard.io"

MAX_CONCURRENT_COMPANIES = 10
MAX_INFLIGHT_REQUESTS = 20
SYNC_TIMEOUT_SECONDS = 120
HISTORY_MONTHS = 6
MAX_FINDINGS_PER_RISK = 50
_MAX_ATTEMPTS = 4
RETRY_BACKOFF_SECONDS = 1.0

# SecurityScorecard severity -> Judah severity. "positive" issues are healthy
# practices and are not imported; anything unrecognised falls back to info.
_SEVERITY_MAP = {
    "high": Severity.CRITICAL,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}
_SKIPPED_SEVERITIES = {"positive"}

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")
_ISSUE_TYPE_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,200}$")
# Finding keys that are bookkeeping rather than useful observations.
_FINDING_SKIP_KEYS = {
    "first_seen_time",
    "last_seen_time",
    "issue_id",
    "parent_domain",
    "count",
    "group_status",
    "detail_url",
}


class SecurityScorecardApiError(RuntimeError):
    """A safe, user-displayable SecurityScorecard API error."""

    def __init__(self, message: str, status_code: Optional[int] = None) -> None:
        super().__init__(message)
        self.status_code = status_code


# ── HTTP client ───────────────────────────────────────────────────────────────


class SecurityScorecardClient:
    """Minimal token-authenticated client for the SecurityScorecard REST API."""

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = API_BASE_URL,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        backoff_base: Optional[float] = None,
    ) -> None:
        if not api_key or not api_key.strip():
            raise SecurityScorecardApiError("A SecurityScorecard API key is required.")
        self._api_key = api_key.strip()
        self._base_url = base_url.rstrip("/")
        self._transport = transport
        self._backoff_base = RETRY_BACKOFF_SECONDS if backoff_base is None else backoff_base
        self._client: Optional[httpx.AsyncClient] = None
        self._inflight = asyncio.Semaphore(MAX_INFLIGHT_REQUESTS)

    async def __aenter__(self) -> "SecurityScorecardClient":
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            timeout=30.0,
            transport=self._transport,
            headers={
                # SecurityScorecard uses "Token", not "Bearer".
                "Authorization": f"Token {self._api_key}",
                "Accept": "application/json",
            },
        )
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if self._client is None:
            raise RuntimeError("SecurityScorecardClient must be used as an async context manager.")
        for attempt in range(_MAX_ATTEMPTS):
            last = attempt == _MAX_ATTEMPTS - 1
            try:
                async with self._inflight:
                    response = await self._client.get(path, params=params)
            except httpx.TransportError as exc:
                # Connection resets, refused connections, read timeouts.
                if last:
                    raise SecurityScorecardApiError(
                        f"Could not reach SecurityScorecard: {exc.__class__.__name__}"
                    ) from exc
                await asyncio.sleep(self._backoff_base * 2**attempt)
                continue
            status = response.status_code
            if (status == 429 or status >= 500) and not last:
                await asyncio.sleep(self._retry_delay(response, attempt))
                continue
            if status == 401:
                raise SecurityScorecardApiError(
                    "SecurityScorecard rejected the API key (HTTP 401). Check that it is valid and not revoked.",
                    status,
                )
            if status != 200:
                raise SecurityScorecardApiError(
                    f"SecurityScorecard request to {path.split('?')[0]} failed (HTTP {status}).", status
                )
            try:
                payload = response.json()
            except ValueError as exc:
                raise SecurityScorecardApiError(
                    "SecurityScorecard returned an invalid JSON response.", status
                ) from exc
            return payload if isinstance(payload, dict) else {"entries": payload}
        raise SecurityScorecardApiError("SecurityScorecard request failed after retries.")

    def _retry_delay(self, response: httpx.Response, attempt: int) -> float:
        retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                return min(float(retry_after), 30.0)
            except ValueError:
                pass
        return self._backoff_base * 2**attempt

    # Endpoints ---------------------------------------------------------------

    async def list_portfolios(self) -> List[Dict[str, Any]]:
        return _entries(await self.get("/portfolios"))

    async def list_portfolio_companies(self, portfolio_id: str) -> List[Dict[str, Any]]:
        return _entries(await self.get(f"/portfolios/{quote(str(portfolio_id), safe='')}/companies"))

    async def get_factors(self, domain: str) -> List[Dict[str, Any]]:
        return _entries(await self.get(f"/companies/{quote(domain, safe='')}/factors"))

    async def get_issue_findings(self, domain: str, issue_type: str) -> List[Dict[str, Any]]:
        return _entries(
            await self.get(f"/companies/{quote(domain, safe='')}/issues/{quote(issue_type, safe='')}/")
        )

    async def get_issue_type(self, issue_type: str) -> Dict[str, Any]:
        return await self.get(f"/metadata/issue-types/{quote(issue_type, safe='')}")

    async def get_score_history(self, domain: str, start: date, end: date) -> List[Dict[str, Any]]:
        return _entries(
            await self.get(
                f"/companies/{quote(domain, safe='')}/history/score",
                params={"from": start.isoformat(), "to": end.isoformat(), "timing": "monthly"},
            )
        )


def _entries(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    entries = payload.get("entries")
    if entries is None:
        entries = payload.get("data") or []
    return [item for item in entries if isinstance(item, dict)] if isinstance(entries, list) else []


# ── Normalisation helpers ─────────────────────────────────────────────────────


def normalize_domain(value: Any) -> Optional[str]:
    domain = str(value or "").strip().lower().rstrip(".")
    if domain.startswith("www."):
        domain = domain[4:]
    return domain if _DOMAIN_RE.match(domain) else None


def map_severity(value: Any) -> Optional[Severity]:
    """Return the Judah severity, or ``None`` for issues that must not be imported."""
    key = str(value or "").strip().lower()
    if key in _SKIPPED_SEVERITIES:
        return None
    return _SEVERITY_MAP.get(key, Severity.INFO)


def title_from_slug(issue_type: str) -> str:
    words = [word for word in re.split(r"[_\-\s]+", issue_type or "") if word]
    return " ".join(word.capitalize() for word in words) or "SecurityScorecard Issue"


def platform_issue_url(domain: str, factor: Optional[str], issue_type: str) -> str:
    segments = [quote(domain, safe=""), "issues"]
    if factor:
        segments.append(quote(factor, safe=""))
    segments.append(quote(issue_type, safe=""))
    return f"{PLATFORM_BASE_URL}/#/scorecard/" + "/".join(segments) + "/"


def _to_number(value: Any) -> Optional[float]:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return int(number) if number.is_integer() else round(number, 2)


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


def history_points(entries: List[Dict[str, Any]]) -> List[str]:
    """Format monthly history as ``YYYY-MM-DD:score`` points, oldest first."""
    points = []
    for entry in entries:
        score = _to_number(entry.get("score"))
        day = str(entry.get("date") or "")[:10]
        if score is None or not re.match(r"^\d{4}-\d{2}-\d{2}$", day):
            continue
        points.append(f"{day}:{score}")
    return sorted(set(points))


def definition_fields(meta: Optional[Dict[str, Any]]) -> Dict[str, Optional[str]]:
    meta = meta or {}

    def pick(*keys: str) -> Optional[str]:
        for key in keys:
            value = meta.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None

    return {
        "title": pick("title", "name"),
        "description": pick("long_description", "description", "short_description"),
        "impact": pick("impact", "risk", "risk_description"),
        "remediation": pick("recommendation", "remediation", "remediation_guidance"),
    }


def _finding_observations(finding: Dict[str, Any]) -> Dict[str, Any]:
    observations: Dict[str, Any] = {}
    for key, value in finding.items():
        if key in _FINDING_SKIP_KEYS or value in (None, "", [], {}):
            continue
        if isinstance(value, (str, int, float, bool)):
            observations[key] = value
        elif isinstance(value, list) and all(isinstance(item, (str, int, float)) for item in value):
            observations[key] = value[:25]
    return observations


def build_evidence(
    *,
    domain: str,
    issue_type: str,
    factor: Optional[str],
    raw_severity: str,
    count: Any,
    score_impact: Any,
    findings: Optional[List[Dict[str, Any]]],
    link: str,
) -> str:
    lines = [
        "SecurityScorecard issue overview",
        f"- Domain: {domain}",
        f"- Issue type: {issue_type}",
        f"- Factor: {factor or 'unknown'}",
        f"- Severity: {raw_severity or 'unknown'}",
        f"- Active findings: {count if count is not None else 'unknown'}",
        f"- Score impact: {score_impact if score_impact is not None else 'unknown'}",
        "",
    ]
    if findings is None:
        lines.append("Individual findings could not be retrieved from SecurityScorecard.")
    elif not findings:
        lines.append("SecurityScorecard returned no individual findings for this issue.")
    else:
        shown = findings[:MAX_FINDINGS_PER_RISK]
        lines.append(f"Findings ({len(shown)} of {len(findings)} shown)")
        for index, finding in enumerate(shown, 1):
            first_seen = finding.get("first_seen_time") or "unknown"
            last_seen = finding.get("last_seen_time") or "unknown"
            lines.append(f"{index}. First seen {first_seen}; last seen {last_seen}")
            for key, value in _finding_observations(finding).items():
                rendered = ", ".join(str(item) for item in value) if isinstance(value, list) else value
                lines.append(f"   - {key}: {rendered}")
    lines.extend(["", f"View in SecurityScorecard: {link}"])
    return "\n".join(lines)


# ── Collection (network) ──────────────────────────────────────────────────────


@dataclass
class IssueRecord:
    issue_type: str
    factor: Optional[str]
    raw_severity: str
    severity: Severity
    count: Any
    score_impact: Any
    findings: Optional[List[Dict[str, Any]]]


@dataclass
class CompanyRecord:
    domain: str
    name: Optional[str] = None
    score: Optional[float] = None
    grade: Optional[str] = None
    industry: Optional[str] = None
    portfolios: List[str] = field(default_factory=list)
    factors: Optional[Dict[str, Any]] = None  # None => factors request refused/failed
    factors_error: Optional[str] = None
    issues: List[IssueRecord] = field(default_factory=list)
    score_history: List[str] = field(default_factory=list)


@dataclass
class CollectedData:
    portfolios_seen: int = 0
    companies: Dict[str, CompanyRecord] = field(default_factory=dict)
    definitions: Dict[str, Optional[Dict[str, Any]]] = field(default_factory=dict)


class _DefinitionCache:
    """Fetches each issue-type definition at most once per run."""

    def __init__(self, client: SecurityScorecardClient) -> None:
        self._client = client
        self._tasks: Dict[str, asyncio.Task] = {}

    async def get(self, issue_type: str) -> Optional[Dict[str, Any]]:
        task = self._tasks.get(issue_type)
        if task is None:
            task = asyncio.ensure_future(self._fetch(issue_type))
            self._tasks[issue_type] = task
        return await task

    async def _fetch(self, issue_type: str) -> Optional[Dict[str, Any]]:
        try:
            return await self._client.get_issue_type(issue_type)
        except SecurityScorecardApiError as exc:
            logger.warning("SecurityScorecard: no definition for issue type %s (%s)", issue_type, exc)
            return None

    def results(self) -> Dict[str, Optional[Dict[str, Any]]]:
        return {key: task.result() for key, task in self._tasks.items() if task.done()}


async def _collect_company(
    client: SecurityScorecardClient,
    company: CompanyRecord,
    definitions: _DefinitionCache,
    *,
    include_risks: bool,
    today: date,
) -> None:
    try:
        factors = await client.get_factors(company.domain)
    except SecurityScorecardApiError as exc:
        if exc.status_code == 401:
            raise
        logger.warning(
            "SecurityScorecard: skipping factors for %s (%s)", company.domain, exc
        )
        company.factors_error = str(exc)
        factors = None

    if factors is not None:
        company.factors = {}
        pending: List[Any] = []
        for factor in factors:
            factor_name = str(factor.get("name") or "").strip()
            if factor_name:
                company.factors[factor_name] = _to_number(factor.get("score"))
            if not include_risks:
                continue
            for summary in factor.get("issue_summary") or []:
                if not isinstance(summary, dict):
                    continue
                issue_type = str(summary.get("type") or "").strip()
                severity = map_severity(summary.get("severity"))
                if not issue_type or severity is None or not _ISSUE_TYPE_RE.match(issue_type):
                    continue
                pending.append((issue_type, factor_name or None, summary, severity))

        async def load_issue(issue_type: str, factor_name: Optional[str], summary: Dict[str, Any], severity: Severity):
            await definitions.get(issue_type)
            try:
                findings: Optional[List[Dict[str, Any]]] = await client.get_issue_findings(
                    company.domain, issue_type
                )
            except SecurityScorecardApiError as exc:
                if exc.status_code == 401:
                    raise
                logger.warning(
                    "SecurityScorecard: findings unavailable for %s/%s (%s)",
                    company.domain,
                    issue_type,
                    exc,
                )
                findings = None
            return IssueRecord(
                issue_type=issue_type,
                factor=factor_name,
                raw_severity=str(summary.get("severity") or ""),
                severity=severity,
                count=summary.get("count"),
                score_impact=_to_number(summary.get("total_score_impact")),
                findings=findings,
            )

        company.issues = list(await asyncio.gather(*(load_issue(*item) for item in pending)))

    start = today - timedelta(days=HISTORY_MONTHS * 31)
    try:
        company.score_history = history_points(
            await client.get_score_history(company.domain, start, today)
        )
    except SecurityScorecardApiError as exc:
        if exc.status_code == 401:
            raise
        logger.warning("SecurityScorecard: score history unavailable for %s (%s)", company.domain, exc)


async def collect(
    client: SecurityScorecardClient,
    *,
    include_risks: bool = True,
    today: Optional[date] = None,
) -> CollectedData:
    """Fetch every portfolio company and its ratings data. ``client`` must be open."""
    data = CollectedData()
    portfolios = await client.list_portfolios()
    data.portfolios_seen = len(portfolios)

    semaphore = asyncio.Semaphore(MAX_CONCURRENT_COMPANIES)

    async def companies_for(portfolio: Dict[str, Any]):
        portfolio_id = portfolio.get("id")
        if portfolio_id in (None, ""):
            return portfolio, []
        async with semaphore:
            return portfolio, await client.list_portfolio_companies(str(portfolio_id))

    for portfolio, companies in await asyncio.gather(*(companies_for(p) for p in portfolios)):
        portfolio_name = str(portfolio.get("name") or portfolio.get("id"))
        for entry in companies:
            domain = normalize_domain(entry.get("domain"))
            if not domain:
                continue
            record = data.companies.get(domain)
            if record is None:
                record = CompanyRecord(
                    domain=domain,
                    name=entry.get("name"),
                    score=_to_number(entry.get("score")),
                    grade=(str(entry.get("grade")).strip().upper() or None) if entry.get("grade") else None,
                    industry=entry.get("industry"),
                )
                data.companies[domain] = record
            if portfolio_name not in record.portfolios:
                record.portfolios.append(portfolio_name)

    definitions = _DefinitionCache(client)
    today = today or datetime.utcnow().date()

    async def bounded(company: CompanyRecord) -> None:
        async with semaphore:
            await _collect_company(client, company, definitions, include_risks=include_risks, today=today)

    await asyncio.gather(*(bounded(company) for company in data.companies.values()))
    data.definitions = definitions.results()
    return data


# ── Persistence (database) ────────────────────────────────────────────────────


class _Stats:
    def __init__(self) -> None:
        self.portfolios_seen = 0
        self.companies_seen = 0
        self.assets_created = 0
        self.assets_updated = 0
        self.risks_created = 0
        self.risks_updated = 0
        self.risks_resolved = 0
        self.companies_without_factors = 0
        self.definitions_missing = 0

    def as_dict(self) -> Dict[str, int]:
        return vars(self).copy()


def _upsert_asset(db: Session, org_id: int, company: CompanyRecord, stats: _Stats) -> Asset:
    asset = (
        db.query(Asset)
        .filter(Asset.organization_id == org_id, Asset.value == company.domain)
        .order_by(Asset.id)
        .first()
    )
    now = datetime.utcnow()
    previous = dict((asset.metadata_ or {}).get("securityscorecard") or {}) if asset else {}
    block: Dict[str, Any] = {
        "company_name": company.name,
        "industry": company.industry,
        "score": company.score,
        "grade": company.grade,
        "portfolios": company.portfolios,
        "score_history": company.score_history or previous.get("score_history") or [],
        "platform_url": f"{PLATFORM_BASE_URL}/#/scorecard/{quote(company.domain, safe='')}/",
        "synced_at": now.isoformat(),
    }
    if company.factors is not None:
        block["factors"] = company.factors
        block["factors_error"] = None
    else:
        # Keep the last known factor scores rather than wiping them on a 403.
        block["factors"] = previous.get("factors") or {}
        block["factors_error"] = company.factors_error

    tags_to_set = [SOURCE_TAG] + ([f"{GRADE_TAG_PREFIX}{company.grade}"] if company.grade else [])

    if asset:
        metadata = dict(asset.metadata_ or {})
        metadata["securityscorecard"] = block
        asset.metadata_ = metadata
        tags = [tag for tag in (asset.tags or []) if not str(tag).startswith(GRADE_TAG_PREFIX)]
        tags.extend(tag for tag in tags_to_set if tag not in tags)
        asset.tags = tags
        asset.last_seen = now
        stats.assets_updated += 1
        return asset

    asset = Asset(
        name=company.domain,
        value=company.domain,
        asset_type=AssetType.DOMAIN,
        root_domain=company.domain,
        organization_id=org_id,
        status=AssetStatus.DISCOVERED,
        discovery_source=DISCOVERY_SOURCE,
        association_reason=(
            "Company domain in SecurityScorecard portfolio(s): " + ", ".join(company.portfolios)
        )[:2000],
        association_confidence=60,
        # SecurityScorecard portfolios frequently track third-party vendors.
        # New domains are imported for visibility but kept out of active
        # scanning scope until an analyst confirms ownership.
        in_scope=False,
        is_owned=False,
        tags=tags_to_set,
        metadata_={"securityscorecard": block},
        first_seen=now,
        last_seen=now,
    )
    db.add(asset)
    db.flush()
    stats.assets_created += 1
    return asset


def _upsert_risks(
    db: Session,
    asset: Asset,
    company: CompanyRecord,
    definitions: Dict[str, Optional[Dict[str, Any]]],
    stats: _Stats,
) -> None:
    existing_rows = (
        db.query(Vulnerability)
        .filter(Vulnerability.asset_id == asset.id, Vulnerability.detected_by == DISCOVERY_SOURCE)
        .all()
    )
    by_template = {row.template_id: row for row in existing_rows}
    seen: Set[str] = set()
    now = datetime.utcnow()

    for issue in company.issues:
        template_id = f"{DISCOVERY_SOURCE}:{issue.issue_type}"[:255]
        if template_id in seen:
            continue  # same issue type surfaced under two factors
        seen.add(template_id)
        definition = definitions.get(issue.issue_type)
        fields = definition_fields(definition)
        title = (fields["title"] or title_from_slug(issue.issue_type))[:500]
        link = platform_issue_url(company.domain, issue.factor, issue.issue_type)
        evidence = build_evidence(
            domain=company.domain,
            issue_type=issue.issue_type,
            factor=issue.factor,
            raw_severity=issue.raw_severity,
            count=issue.count,
            score_impact=issue.score_impact,
            findings=issue.findings,
            link=link,
        )
        first_seen_values = [
            parsed
            for parsed in (_parse_datetime(f.get("first_seen_time")) for f in issue.findings or [])
            if parsed
        ]
        last_seen_values = [
            parsed
            for parsed in (_parse_datetime(f.get("last_seen_time")) for f in issue.findings or [])
            if parsed
        ]
        metadata = {
            "source": DISCOVERY_SOURCE,
            "issue_type": issue.issue_type,
            "factor": issue.factor,
            "ssc_severity": issue.raw_severity,
            "active_findings": issue.count,
            "score_impact": issue.score_impact,
            "definition_available": definition is not None,
            "findings_available": issue.findings is not None,
            "platform_url": link,
        }
        values = {
            "title": title,
            "description": fields["description"],
            "impact": fields["impact"],
            "remediation": fields["remediation"],
            "severity": issue.severity,
            "evidence": evidence,
            "references": [link],
            "affected_component": (issue.factor or None),
            "last_detected": max(last_seen_values) if last_seen_values else now,
            "metadata_": metadata,
        }
        row = by_template.get(template_id)
        if row is not None:
            for key, value in values.items():
                setattr(row, key, value)
            if row.status == VulnerabilityStatus.RESOLVED:
                row.status = VulnerabilityStatus.OPEN
                row.resolved_at = None
            stats.risks_updated += 1
            continue
        db.add(
            Vulnerability(
                **values,
                asset_id=asset.id,
                detected_by=DISCOVERY_SOURCE,
                template_id=template_id,
                status=VulnerabilityStatus.OPEN,
                first_detected=min(first_seen_values) if first_seen_values else now,
                tags=[SOURCE_TAG],
            )
        )
        stats.risks_created += 1

    # Issues SecurityScorecard no longer reports for this domain are resolved.
    for template_id, row in by_template.items():
        if template_id in seen or row.status != VulnerabilityStatus.OPEN:
            continue
        row.status = VulnerabilityStatus.RESOLVED
        row.resolved_at = now
        stats.risks_resolved += 1


def persist(
    db: Session,
    integration: SecurityScorecardIntegration,
    data: CollectedData,
) -> _Stats:
    stats = _Stats()
    stats.portfolios_seen = data.portfolios_seen
    stats.companies_seen = len(data.companies)
    stats.definitions_missing = sum(1 for value in data.definitions.values() if value is None)
    for company in data.companies.values():
        asset = _upsert_asset(db, integration.organization_id, company, stats)
        if company.factors is None:
            stats.companies_without_factors += 1
            continue  # keep previous risks untouched; we could not see current state
        if integration.import_risks:
            _upsert_risks(db, asset, company, data.definitions, stats)
    return stats


# ── Public entry points ───────────────────────────────────────────────────────


async def test_connection(
    api_key: str, *, transport: Optional[httpx.AsyncBaseTransport] = None
) -> Dict[str, Any]:
    try:
        async with SecurityScorecardClient(api_key, transport=transport) as client:
            portfolios = await client.list_portfolios()
    except SecurityScorecardApiError as exc:
        return {"ok": False, "message": str(exc), "portfolio_count": 0}
    return {
        "ok": True,
        "message": f"Connected to SecurityScorecard; {len(portfolios)} portfolio(s) visible.",
        "portfolio_count": len(portfolios),
    }


async def sync_integration(
    db: Session,
    integration: SecurityScorecardIntegration,
    *,
    transport: Optional[httpx.AsyncBaseTransport] = None,
    timeout_seconds: float = SYNC_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    stats = _Stats()
    try:
        api_key = integration.get_api_key()
        if not api_key:
            raise SecurityScorecardApiError("No SecurityScorecard API key is stored for this connection.")
        async with SecurityScorecardClient(api_key, transport=transport) as client:
            try:
                data = await asyncio.wait_for(
                    collect(client, include_risks=integration.import_risks), timeout=timeout_seconds
                )
            except asyncio.TimeoutError as exc:
                raise SecurityScorecardApiError(
                    f"SecurityScorecard import timed out after {int(timeout_seconds)} seconds."
                ) from exc
        stats = persist(db, integration, data)

        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = True
        integration.last_error = None
        integration.last_sync_stats = stats.as_dict()
        db.commit()
        message = (
            f"Imported {stats.companies_seen} domain(s) from {stats.portfolios_seen} portfolio(s): "
            f"{stats.assets_created} new asset(s), {stats.risks_created} new risk(s), "
            f"{stats.risks_resolved} resolved."
        )
        if stats.companies_without_factors:
            message += f" {stats.companies_without_factors} domain(s) had no accessible factors."
        return {"ok": True, "message": message, **stats.as_dict()}
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        logger.exception("SecurityScorecard sync failed for organization %s", integration.organization_id)
        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = False
        integration.last_error = str(exc)[:1000]
        db.commit()
        return {"ok": False, "message": f"Sync failed: {exc}", **stats.as_dict()}
