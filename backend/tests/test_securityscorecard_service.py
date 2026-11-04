"""SecurityScorecard client, normalization, and end-to-end sync (mocked API)."""

import asyncio
from datetime import date

import pytest

pytest.importorskip("sqlalchemy")
httpx = pytest.importorskip("httpx")

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app.db.database import Base  # noqa: E402
import app.models  # noqa: E402,F401
from app.models.asset import Asset, AssetType  # noqa: E402
from app.models.organization import Organization  # noqa: E402
from app.models.securityscorecard_integration import SecurityScorecardIntegration  # noqa: E402
from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus  # noqa: E402
from app.services import securityscorecard_service as ssc  # noqa: E402


async def _no_sleep(_seconds):
    return None


# ── Pure helpers ──────────────────────────────────────────────────────────────


def test_severity_mapping_matches_documented_table():
    assert ssc.map_severity("high") == Severity.CRITICAL
    assert ssc.map_severity("MEDIUM") == Severity.MEDIUM
    assert ssc.map_severity("low") == Severity.LOW
    assert ssc.map_severity("info") == Severity.INFO
    assert ssc.map_severity("positive") is None
    assert ssc.map_severity("something-new") == Severity.INFO
    assert ssc.map_severity(None) == Severity.INFO


def test_title_from_slug():
    assert ssc.title_from_slug("tlscert_weak_protocol") == "Tlscert Weak Protocol"
    assert ssc.title_from_slug("") == "SecurityScorecard Issue"


def test_normalize_domain_rejects_paths_and_garbage():
    assert ssc.normalize_domain(" Example.COM. ") == "example.com"
    assert ssc.normalize_domain("example.com/../portfolios") is None
    assert ssc.normalize_domain("not a domain") is None
    assert ssc.normalize_domain(None) is None


def test_score_history_attributes_sorted_and_formatted():
    entries = [
        {"date": "2026-10-01T00:00:00.000Z", "score": 88},
        {"date": "2026-09-01T00:00:00.000Z", "score": 85.5},
        {"date": None, "score": 1},
    ]
    assert ssc.score_history_attributes(entries) == ["2026-09-01:85.5", "2026-10-01:88"]


def test_definition_fields_prefer_long_description_and_recommendation():
    fields = ssc.definition_fields(
        {
            "title": "SSL/TLS Service Supports Weak Protocol",
            "short_description": "short",
            "long_description": "long",
            "recommendation": "Disable TLS 1.0",
            "impact": "Downgrade attacks",
        }
    )
    assert fields == {
        "title": "SSL/TLS Service Supports Weak Protocol",
        "description": "long",
        "impact": "Downgrade attacks",
        "remediation": "Disable TLS 1.0",
    }
    assert ssc.definition_fields(None)["title"] is None


def test_path_segments_are_quoted():
    assert ssc._seg("a/b?c") == "a%2Fb%3Fc"


# ── Client behaviour ──────────────────────────────────────────────────────────


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
            "key-123", transport=httpx.MockTransport(handler), sleep=_no_sleep
        ) as client:
            return await client.list_portfolios()

    assert asyncio.run(run()) == [{"id": "p1"}]
    assert len(calls) == 4
    assert calls[0].headers["Authorization"] == "Token key-123"
    assert str(calls[0].url) == "https://api.securityscorecard.io/portfolios"


def test_test_connection_reports_401():
    transport = httpx.MockTransport(lambda request: httpx.Response(401))
    result = asyncio.run(ssc.test_connection("bad", transport=transport))
    assert result["ok"] is False
    assert "401" in result["message"]


# ── End-to-end sync ───────────────────────────────────────────────────────────


@pytest.fixture()
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(
        engine,
        tables=[
            Organization.__table__,
            Asset.__table__,
            Vulnerability.__table__,
            SecurityScorecardIntegration.__table__,
        ],
    )
    session = sessionmaker(bind=engine)()
    session.add(Organization(id=1, name="Acme"))
    session.commit()
    yield session
    session.close()


def _integration(db, **overrides):
    integration = SecurityScorecardIntegration(organization_id=1, connection_name="Main", **overrides)
    integration.set_api_key("key-123")
    db.add(integration)
    db.commit()
    return integration


class FakeSSC:
    """Routes mocked SecurityScorecard API requests and records what was called."""

    def __init__(self):
        self.calls = []
        self.forbidden_factors = set()
        self.issues = {
            "tlscert_weak_protocol": {
                "type": "tlscert_weak_protocol",
                "count": 2,
                "severity": "medium",
                "total_score_impact": 0.42,
            },
            "spf_record_missing": {"type": "spf_record_missing", "count": 1, "severity": "high"},
            "hsts_ok": {"type": "hsts_ok", "count": 4, "severity": "positive"},
        }

    def handler(self, request):
        path = request.url.path
        self.calls.append(path)
        if path == "/portfolios":
            return httpx.Response(200, json={"entries": [{"id": "p1", "name": "Vendors"}, {"id": "p2", "name": "Own"}]})
        if path == "/portfolios/p1/companies":
            return httpx.Response(200, json={"entries": [
                {"domain": "example.com", "name": "Example", "score": 81, "grade": "B"},
                {"domain": "private.example", "name": "Private", "score": 70, "grade": "C"},
            ]})
        if path == "/portfolios/p2/companies":
            # Duplicate across portfolios must be processed once.
            return httpx.Response(200, json={"entries": [{"domain": "EXAMPLE.com", "score": 81, "grade": "B"}]})
        if path.endswith("/factors"):
            domain = path.split("/")[2]
            if domain in self.forbidden_factors:
                return httpx.Response(403)
            return httpx.Response(200, json={"entries": [
                {"name": "network_security", "score": 76, "grade": "C",
                 "issue_summary": [self.issues[k] for k in ("tlscert_weak_protocol", "hsts_ok") if k in self.issues]},
                {"name": "dns_health", "score": 90, "grade": "A",
                 "issue_summary": [self.issues[k] for k in ("spf_record_missing",) if k in self.issues]},
            ]})
        if "/issues/" in path:
            if "spf_record_missing" in path:
                return httpx.Response(404)  # findings unavailable -> overview + link only
            return httpx.Response(200, json={"entries": [{
                "first_seen_time": "2026-08-01T00:00:00Z",
                "last_seen_time": "2026-10-30T00:00:00Z",
                "ip": "203.0.113.10",
                "port": 443,
                "protocol": ["TLSv1.0", "TLSv1.1"],
            }]})
        if path == "/metadata/issue-types/tlscert_weak_protocol":
            return httpx.Response(200, json={
                "title": "SSL/TLS Service Supports Weak Protocol",
                "long_description": "Weak protocol versions are enabled.",
                "recommendation": "Disable SSLv3, TLS 1.0 and TLS 1.1.",
                "impact": "Allows downgrade attacks.",
            })
        if path.startswith("/metadata/issue-types/"):
            return httpx.Response(404)
        if path.endswith("/history/score"):
            assert request.url.params["timing"] == "monthly"
            return httpx.Response(200, json={"entries": [
                {"date": "2026-09-01T00:00:00Z", "score": 79},
                {"date": "2026-10-01T00:00:00Z", "score": 81},
            ]})
        return httpx.Response(404)


def _sync(db, integration, fake):
    return asyncio.run(
        ssc.sync_integration(db, integration, transport=httpx.MockTransport(fake.handler))
    )


def test_sync_imports_assets_attributes_and_risks(db):
    integration = _integration(db)
    fake = FakeSSC()
    fake.forbidden_factors.add("private.example")

    result = _sync(db, integration, fake)

    assert result["ok"], result
    assert result["portfolios_seen"] == 2
    assert result["companies_seen"] == 2
    assert result["assets_created"] == 2
    assert result["factors_unavailable"] == 1
    assert result["vulns_created"] == 2  # positive issue not imported
    assert integration.last_sync_ok is True

    # Deduplicated across portfolios; each definition fetched once per run.
    assert fake.calls.count("/companies/example.com/factors") == 1
    assert fake.calls.count("/metadata/issue-types/tlscert_weak_protocol") == 1
    assert not any("hsts_ok" in call for call in fake.calls)

    asset = db.query(Asset).filter(Asset.value == "example.com").one()
    assert asset.asset_type == AssetType.DOMAIN
    attrs = asset.metadata_["securityscorecard"]
    assert attrs["score"] == 81 and attrs["grade"] == "B"
    assert attrs["factors"] == {"network_security": 76, "dns_health": 90}
    assert attrs["score_history"] == ["2026-09-01:79", "2026-10-01:81"]
    assert sorted(attrs["portfolios"]) == ["Own", "Vendors"]

    # 403 on factors: asset + score + grade still imported, no risks.
    private = db.query(Asset).filter(Asset.value == "private.example").one()
    assert private.metadata_["securityscorecard"]["grade"] == "C"
    assert db.query(Vulnerability).filter(Vulnerability.asset_id == private.id).count() == 0

    tls = db.query(Vulnerability).filter(
        Vulnerability.template_id == "securityscorecard:tlscert_weak_protocol"
    ).one()
    assert tls.title == "SSL/TLS Service Supports Weak Protocol"
    assert tls.severity == Severity.MEDIUM
    assert tls.description == "Weak protocol versions are enabled."
    assert tls.impact == "Allows downgrade attacks."
    assert tls.remediation.startswith("Disable SSLv3")
    assert "Active findings: 2" in tls.evidence
    assert "203.0.113.10" in tls.evidence and "TLSv1.0, TLSv1.1" in tls.evidence
    assert "platform.securityscorecard.io" in tls.references[0]
    assert tls.first_detected.isoformat().startswith("2026-08-01")

    spf = db.query(Vulnerability).filter(
        Vulnerability.template_id == "securityscorecard:spf_record_missing"
    ).one()
    assert spf.title == "Spf Record Missing"  # slug fallback, no definition
    assert spf.severity == Severity.CRITICAL  # SSC "high"
    assert spf.description is None
    assert "Findings (" not in spf.evidence  # overview + link only
    assert "View in SecurityScorecard" in spf.evidence


def test_resync_updates_resolves_and_reopens(db):
    integration = _integration(db)
    fake = FakeSSC()
    fake.forbidden_factors.add("private.example")
    assert _sync(db, integration, fake)["vulns_created"] == 2

    removed = fake.issues.pop("spf_record_missing")
    second = _sync(db, integration, fake)
    assert second["vulns_created"] == 0
    assert second["vulns_updated"] == 1
    assert second["vulns_resolved"] == 1
    spf = db.query(Vulnerability).filter(
        Vulnerability.template_id == "securityscorecard:spf_record_missing"
    ).one()
    assert spf.status == VulnerabilityStatus.RESOLVED

    fake.issues["spf_record_missing"] = removed
    third = _sync(db, integration, fake)
    assert third["vulns_created"] == 0
    db.refresh(spf)
    assert spf.status == VulnerabilityStatus.OPEN


def test_refused_factors_do_not_resolve_existing_risks(db):
    integration = _integration(db)
    fake = FakeSSC()
    fake.forbidden_factors.add("private.example")
    _sync(db, integration, fake)

    fake.forbidden_factors.add("example.com")
    result = _sync(db, integration, fake)
    assert result["ok"] and result["vulns_resolved"] == 0
    asset = db.query(Asset).filter(Asset.value == "example.com").one()
    # Last known factor scores are kept when this run could not read them.
    assert asset.metadata_["securityscorecard"]["factors"]["dns_health"] == 90


def test_enrich_only_mode_skips_unknown_domains(db):
    db.add(Asset(name="example.com", value="example.com", asset_type=AssetType.DOMAIN, organization_id=1))
    db.commit()
    integration = _integration(db, import_assets=False)
    fake = FakeSSC()

    result = _sync(db, integration, fake)

    assert result["ok"], result
    assert result["assets_created"] == 0
    assert result["assets_updated"] == 1
    assert result["companies_skipped"] == 1
    assert not any("private.example" in call for call in fake.calls)


def test_sync_records_auth_failure(db):
    integration = _integration(db)
    result = asyncio.run(
        ssc.sync_integration(
            db, integration, transport=httpx.MockTransport(lambda request: httpx.Response(401))
        )
    )
    assert result["ok"] is False
    assert integration.last_sync_ok is False
    assert "401" in integration.last_error


def test_concurrency_is_capped():
    active = 0
    peak = 0

    class SlowClient:
        async def get_factors(self, domain):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.01)
            active -= 1
            return []

        async def get_score_history(self, domain, start, end):
            return []

    companies = [ssc._Company(domain=f"d{i}.example") for i in range(25)]
    bundles, _ = asyncio.run(
        ssc.fetch_bundles(SlowClient(), companies, import_vulnerabilities=True, today=date(2026, 11, 4))
    )
    assert len(bundles) == 25
    assert peak <= ssc.MAX_CONCURRENT_COMPANIES
