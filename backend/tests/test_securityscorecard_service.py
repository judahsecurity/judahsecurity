"""SecurityScorecard client, normalisation, and import (mocked REST API)."""

import asyncio
from datetime import date

import pytest

pytest.importorskip("sqlalchemy")
httpx = pytest.importorskip("httpx")

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

import app.models  # noqa: E402,F401
from app.db.database import Base  # noqa: E402
from app.models.asset import Asset, AssetType  # noqa: E402
from app.models.organization import Organization  # noqa: E402
from app.models.securityscorecard_integration import SecurityScorecardIntegration  # noqa: E402
from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus  # noqa: E402
from app.services import securityscorecard_service as ssc  # noqa: E402


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch):
    monkeypatch.setattr(ssc, "RETRY_BACKOFF_SECONDS", 0)


# ── Pure helpers ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("high", Severity.CRITICAL),
        ("HIGH", Severity.CRITICAL),
        ("medium", Severity.MEDIUM),
        ("low", Severity.LOW),
        ("info", Severity.INFO),
        ("weird", Severity.INFO),
        (None, Severity.INFO),
        ("positive", None),
    ],
)
def test_severity_mapping(raw, expected):
    assert ssc.map_severity(raw) == expected


def test_title_from_slug():
    assert ssc.title_from_slug("tlscert_weak_protocol") == "Tlscert Weak Protocol"


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("Example.COM", "example.com"),
        ("www.example.com.", "example.com"),
        ("example.com/../x", None),
        ("", None),
        ("localhost", None),
    ],
)
def test_normalize_domain(raw, expected):
    assert ssc.normalize_domain(raw) == expected


def test_history_points_format_and_order():
    entries = [
        {"date": "2026-10-31T00:00:00.000Z", "score": 88},
        {"date": "2026-09-30T00:00:00.000Z", "score": 85.5},
        {"date": "bad", "score": 1},
        {"date": "2026-08-31", "score": None},
    ]
    assert ssc.history_points(entries) == ["2026-09-30:85.5", "2026-10-31:88"]


def test_evidence_without_findings_keeps_overview_and_link():
    text = ssc.build_evidence(
        domain="example.com",
        issue_type="x",
        factor="dns_health",
        raw_severity="low",
        count=2,
        score_impact=0.4,
        findings=None,
        link="https://platform.securityscorecard.io/#/scorecard/example.com/issues/dns_health/x/",
    )
    assert "Active findings: 2" in text
    assert "could not be retrieved" in text
    assert text.rstrip().endswith("/issues/dns_health/x/")


# ── Client retry behaviour ────────────────────────────────────────────────────


def test_client_sends_token_auth_and_retries_transient_errors():
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(429)
        if len(calls) == 2:
            raise httpx.ConnectError("reset", request=request)
        if len(calls) == 3:
            return httpx.Response(503)
        return httpx.Response(200, json={"entries": [{"id": "p1"}]})

    async def run():
        async with ssc.SecurityScorecardClient(
            "secret-key", transport=httpx.MockTransport(handler), backoff_base=0
        ) as client:
            return await client.list_portfolios()

    assert asyncio.run(run()) == [{"id": "p1"}]
    assert len(calls) == 4
    assert calls[0].headers["Authorization"] == "Token secret-key"
    assert str(calls[0].url) == "https://api.securityscorecard.io/portfolios"


def test_connection_reports_401():
    transport = httpx.MockTransport(lambda request: httpx.Response(401))
    result = asyncio.run(ssc.test_connection("bad", transport=transport))
    assert result["ok"] is False
    assert "401" in result["message"]


# ── End-to-end import ─────────────────────────────────────────────────────────


@pytest.fixture()
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(
        engine,
        tables=[
            Organization.__table__,
            SecurityScorecardIntegration.__table__,
            Asset.__table__,
            Vulnerability.__table__,
        ],
    )
    session = sessionmaker(bind=engine)()
    session.add(Organization(id=1, name="Acme"))
    integration = SecurityScorecardIntegration(id=1, organization_id=1, connection_name="SSC")
    integration.set_api_key("secret-key")
    session.add(integration)
    session.commit()
    yield session
    session.close()


class FakeSSC:
    """In-memory SecurityScorecard API."""

    def __init__(self):
        self.calls = []
        self.forbidden_factors = {"private.example"}
        self.issue_summary = [
            {"type": "tlscert_weak_protocol", "count": 2, "severity": "high", "total_score_impact": 1.25},
            {"type": "spf_record_missing", "count": 1, "severity": "low", "total_score_impact": 0.2},
            {"type": "hsts_enabled", "count": 4, "severity": "positive"},
        ]

    def __call__(self, request):
        path = request.url.path
        self.calls.append(path)
        if path == "/portfolios":
            return httpx.Response(200, json={"entries": [{"id": "p1", "name": "Vendors"}, {"id": "p2", "name": "Mine"}]})
        if path == "/portfolios/p1/companies":
            return httpx.Response(200, json={"entries": [
                {"domain": "example.com", "name": "Example", "score": 81, "grade": "b"},
                {"domain": "private.example", "name": "Private", "score": 60, "grade": "D"},
            ]})
        if path == "/portfolios/p2/companies":
            return httpx.Response(200, json={"entries": [{"domain": "EXAMPLE.com", "score": 81, "grade": "B"}]})
        if path.endswith("/factors"):
            if "private.example" in path:
                return httpx.Response(403)
            return httpx.Response(200, json={"entries": [
                {"name": "network_security", "score": 70, "issue_summary": self.issue_summary[:1] + self.issue_summary[2:]},
                {"name": "dns_health", "score": 95, "issue_summary": self.issue_summary[1:2]},
            ]})
        if path == "/companies/example.com/issues/tlscert_weak_protocol/":
            return httpx.Response(200, json={"entries": [{
                "first_seen_time": "2026-07-01T00:00:00Z",
                "last_seen_time": "2026-11-01T00:00:00Z",
                "ip_addresses": ["192.0.2.10"],
                "protocol": "TLSv1.0",
            }]})
        if "/issues/" in path:
            return httpx.Response(500)
        if path == "/metadata/issue-types/tlscert_weak_protocol":
            return httpx.Response(200, json={
                "title": "SSL/TLS Service Supports Weak Protocol",
                "long_description": "Weak protocols are supported.",
                "impact": "Traffic can be downgraded.",
                "recommendation": "Disable TLS 1.0 and 1.1.",
            })
        if path.startswith("/metadata/issue-types/"):
            return httpx.Response(404)
        if path.endswith("/history/score"):
            assert request.url.params["timing"] == "monthly"
            return httpx.Response(200, json={"entries": [
                {"date": "2026-10-31T00:00:00Z", "score": 81},
                {"date": "2026-09-30T00:00:00Z", "score": 79},
            ]})
        return httpx.Response(404)


def _sync(db, fake):
    integration = db.get(SecurityScorecardIntegration, 1)
    return asyncio.run(
        ssc.sync_integration(db, integration, transport=httpx.MockTransport(fake))
    )


def test_full_import(db):
    fake = FakeSSC()
    result = _sync(db, fake)
    assert result["ok"], result["message"]
    assert result["portfolios_seen"] == 2
    assert result["companies_seen"] == 2  # example.com deduplicated across portfolios
    assert result["assets_created"] == 2
    assert result["risks_created"] == 2  # positive issue skipped
    assert result["companies_without_factors"] == 1
    assert result["definitions_missing"] == 1
    # Definition fetched once per type per run; factors once per domain.
    assert fake.calls.count("/metadata/issue-types/tlscert_weak_protocol") == 1
    assert fake.calls.count("/companies/example.com/factors") == 1

    asset = db.query(Asset).filter(Asset.value == "example.com").one()
    assert asset.asset_type == AssetType.DOMAIN
    assert asset.in_scope is False
    block = asset.metadata_["securityscorecard"]
    assert block["score"] == 81 and block["grade"] == "B"
    assert block["factors"] == {"network_security": 70, "dns_health": 95}
    assert block["score_history"] == ["2026-09-30:79", "2026-10-31:81"]
    assert sorted(block["portfolios"]) == ["Mine", "Vendors"]
    assert "ssc-grade:B" in asset.tags

    private = db.query(Asset).filter(Asset.value == "private.example").one()
    assert private.metadata_["securityscorecard"]["grade"] == "D"
    assert private.vulnerabilities == []

    tls = db.query(Vulnerability).filter(
        Vulnerability.template_id == "securityscorecard:tlscert_weak_protocol"
    ).one()
    assert tls.title == "SSL/TLS Service Supports Weak Protocol"
    assert tls.severity == Severity.CRITICAL
    assert tls.description == "Weak protocols are supported."
    assert tls.impact == "Traffic can be downgraded."
    assert tls.remediation == "Disable TLS 1.0 and 1.1."
    assert "TLSv1.0" in tls.evidence and "192.0.2.10" in tls.evidence
    assert tls.references[0].startswith("https://platform.securityscorecard.io/#/scorecard/example.com/")

    spf = db.query(Vulnerability).filter(
        Vulnerability.template_id == "securityscorecard:spf_record_missing"
    ).one()
    assert spf.title == "Spf Record Missing"
    assert spf.severity == Severity.LOW
    assert spf.description is None
    assert "could not be retrieved" in spf.evidence


def test_resync_updates_and_resolves(db):
    fake = FakeSSC()
    assert _sync(db, fake)["ok"]
    fake.issue_summary = fake.issue_summary[:1]  # SPF issue fixed
    result = _sync(db, fake)
    assert result["ok"], result["message"]
    assert result["assets_created"] == 0 and result["assets_updated"] == 2
    assert result["risks_created"] == 0 and result["risks_updated"] == 1
    assert result["risks_resolved"] == 1
    spf = db.query(Vulnerability).filter(
        Vulnerability.template_id == "securityscorecard:spf_record_missing"
    ).one()
    assert spf.status == VulnerabilityStatus.RESOLVED


def test_invalid_key_marks_sync_failed(db):
    result = _sync(db, lambda request: httpx.Response(401))
    assert result["ok"] is False
    integration = db.get(SecurityScorecardIntegration, 1)
    assert integration.last_sync_ok is False
    assert "401" in integration.last_error


def test_history_window_is_six_months():
    seen = {}

    def handler(request):
        seen.update(request.url.params)
        return httpx.Response(200, json={"entries": []})

    async def run():
        async with ssc.SecurityScorecardClient("k", transport=httpx.MockTransport(handler)) as client:
            company = ssc.CompanyRecord(domain="example.com")
            await ssc._collect_company(
                client, company, ssc._DefinitionCache(client), include_risks=True, today=date(2026, 11, 10)
            )

    asyncio.run(run())
    assert seen["to"] == "2026-11-10"
    assert seen["from"] <= "2026-05-10"
