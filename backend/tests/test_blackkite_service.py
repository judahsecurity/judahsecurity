"""Black Kite integration: scope resolution, severity mapping and sync (mocked API)."""

import asyncio

import pytest

pytest.importorskip("sqlalchemy")
httpx = pytest.importorskip("httpx")

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app.db.database import Base  # noqa: E402
import app.models  # noqa: E402,F401
from app.models.asset import Asset, AssetType  # noqa: E402
from app.models.blackkite_integration import BlackKiteIntegration  # noqa: E402
from app.models.organization import Organization  # noqa: E402
from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus  # noqa: E402
from app.schemas.blackkite_schemas import BlackKiteIntegrationCreate  # noqa: E402
from app.services import blackkite_service  # noqa: E402
from app.services.blackkite_service import (  # noqa: E402
    BlackKiteClient,
    finding_severity,
    normalize_domain,
    resolve_companies,
    sync_integration,
    test_connection as bk_test_connection,
)

BASE = "https://bk.test/api/v2"

ECOSYSTEMS = [
    {"EcosystemId": 1, "Name": "Our Enterprise"},
    {"EcosystemId": 2, "Name": "Vendors"},
]
COMPANIES = [
    {"CompanyId": 10, "CompanyName": "Acme", "DomainName": "acme.com"},
    {"CompanyId": 11, "CompanyName": "Acme EU", "DomainName": "www.acme.eu"},
    {"CompanyId": 99, "CompanyName": "Vendor Co", "DomainName": "vendor.io"},
]


def _api(routes, calls=None, *, token_status=200):
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path.replace("/api/v2", "")
        if calls is not None:
            calls.append(path)
        if path == "/oauth/token":
            if token_status != 200:
                return httpx.Response(token_status, json={"error": "invalid_client"})
            assert b"grant_type=client_credentials" in request.content
            return httpx.Response(200, json={"access_token": "tok"})
        assert request.headers["Authorization"] == "Bearer tok"
        if path in routes:
            page = int(request.url.params.get("page_number", 1))
            return httpx.Response(200, json=routes[path] if page == 1 else [])
        return httpx.Response(404, json={"message": "not found"})

    return BlackKiteClient("id", "secret", base_url=BASE, transport=httpx.MockTransport(handler))


@pytest.fixture()
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(
        engine,
        tables=[
            Organization.__table__,
            BlackKiteIntegration.__table__,
            Asset.__table__,
            Vulnerability.__table__,
        ],
    )
    session = sessionmaker(bind=engine)()
    session.add(Organization(id=1, name="Acme"))
    session.commit()
    yield session
    session.close()


def _integration(db, **kwargs):
    integration = BlackKiteIntegration(
        organization_id=1,
        client_id_encrypted="x",
        client_secret_encrypted="x",
        ecosystem_names=kwargs.get("ecosystem_names", ["Our Enterprise"]),
        company_domains=kwargs.get("company_domains", []),
    )
    db.add(integration)
    db.commit()
    return integration


def test_schema_requires_scope_and_splits_csv():
    payload = BlackKiteIntegrationCreate(
        client_id="a", client_secret="b", ecosystem_names="Our Enterprise, ,our enterprise", company_domains="acme.com,acme.eu"
    )
    assert payload.ecosystem_names == ["Our Enterprise"]
    assert payload.company_domains == ["acme.com", "acme.eu"]
    with pytest.raises(ValueError):
        BlackKiteIntegrationCreate(client_id="a", client_secret="b")


def test_normalize_domain():
    assert normalize_domain("https://WWW.Acme.com:443/path") == "acme.com"
    assert normalize_domain("*.acme.com") == "acme.com"
    assert normalize_domain("") == ""


def test_severity_prefers_cvss():
    assert finding_severity({"CvssScore": 9.8, "Severity": "Low"}) == (Severity.CRITICAL, 9.8)
    assert finding_severity({"CvssScore": "5.3"}) == (Severity.MEDIUM, 5.3)
    assert finding_severity({"Severity": "High"}) == (Severity.HIGH, None)
    assert finding_severity({"Severity": "???"}) == (Severity.MEDIUM, None)


def test_resolve_companies_only_returns_own_companies():
    client = _api({
        "/ecosystems": ECOSYSTEMS,
        "/ecosystems/1/companies": [COMPANIES[0]],
        "/companies": COMPANIES,
    })
    companies, unmatched = asyncio.run(
        resolve_companies(client, ["our enterprise", "Missing Eco"], ["acme.eu", "nope.com"])
    )
    assert sorted(c["id"] for c in companies) == ["10", "11"]
    assert unmatched == ["Missing Eco", "nope.com"]


def test_test_connection_rejects_bad_credentials_and_empty_scope():
    bad = asyncio.run(bk_test_connection("id", "s", ["x"], [], client=_api({}, token_status=401)))
    assert bad["ok"] is False and "credentials" in bad["message"]

    empty = asyncio.run(bk_test_connection("id", "s", [], ["nope.com"], client=_api({"/companies": COMPANIES})))
    assert empty["ok"] is False and "match" in empty["message"]

    good = asyncio.run(bk_test_connection("id", "s", [], ["acme.com"], client=_api({"/companies": COMPANIES})))
    assert good["ok"] is True
    assert good["matched_companies"] == [{"id": "10", "name": "Acme", "domain": "acme.com"}]


def test_sync_imports_subdomains_findings_and_fraud(db):
    integration = _integration(db)
    calls = []
    routes = {
        "/ecosystems": ECOSYSTEMS,
        "/ecosystems/1/companies": [COMPANIES[0]],
        "/companies/10/subdomains": [
            {"Subdomain": "api.acme.com", "Status": "Active", "IpAddress": "203.0.113.5"},
            {"Subdomain": "old.acme.com", "Status": "Inactive"},
        ],
        "/companies/10/findings/patchmanagement": [
            {"FindingId": 1, "Title": "OpenSSL CVE-2024-1234", "Host": "api.acme.com", "CvssScore": 9.1, "Severity": "Low", "Status": "Active"},
        ],
        "/companies/10/findings/sslhealth": [
            {"FindingId": 2, "Title": "Weak cipher", "Severity": "Medium", "Status": "Active"},
        ],
        "/companies/10/findings/fraudulentdomains": [
            {"FindingId": 3, "Domain": "acme-login.com", "Type": "Look-alike", "Severity": "High"},
        ],
    }
    result = asyncio.run(sync_integration(db, integration, client=_api(routes, calls)))

    assert result["ok"], result["message"]
    # Third-party company 99 is never queried.
    assert not any("/companies/99" in c for c in calls)

    values = {a.value: a.asset_type for a in db.query(Asset).all()}
    assert values == {"acme.com": AssetType.DOMAIN, "api.acme.com": AssetType.SUBDOMAIN}
    assert db.query(Asset).filter_by(value="api.acme.com").one().ip_address == "203.0.113.5"

    vulns = {v.template_id: v for v in db.query(Vulnerability).all()}
    patch = vulns["blackkite:10:patchmanagement:1"]
    assert patch.severity == Severity.CRITICAL and patch.cvss_score == 9.1
    assert patch.cve_id == "CVE-2024-1234"
    assert patch.asset.value == "api.acme.com"
    assert vulns["blackkite:10:sslhealth:2"].asset.value == "acme.com"
    fraud = vulns["blackkite:10:fraudulentdomains:3"]
    assert fraud.title == "[Black Kite] Look-alike domain: acme-login.com"
    assert fraud.severity == Severity.HIGH and fraud.asset.value == "acme.com"
    assert integration.matched_companies == [{"id": "10", "name": "Acme", "domain": "acme.com"}]

    # Re-sync: patch finding gone -> resolved; nothing duplicated.
    routes["/companies/10/findings/patchmanagement"] = []
    result = asyncio.run(sync_integration(db, integration, client=_api(routes)))
    assert result["vulns_created"] == 0 and result["vulns_resolved"] == 1
    assert db.query(Vulnerability).count() == 3
    patch = db.query(Vulnerability).filter_by(template_id="blackkite:10:patchmanagement:1").one()
    assert patch.status == VulnerabilityStatus.RESOLVED


def test_sync_fails_cleanly_when_scope_matches_nothing(db, monkeypatch):
    integration = _integration(db, ecosystem_names=["Ghost"])
    result = asyncio.run(sync_integration(db, integration, client=_api({"/ecosystems": ECOSYSTEMS})))
    assert result["ok"] is False
    assert integration.last_sync_ok is False and "match" in integration.last_error


def test_pagination_follows_pages(monkeypatch):
    monkeypatch.setattr(BlackKiteClient, "PAGE_SIZE", 1)
    monkeypatch.setattr(BlackKiteClient, "RATE_LIMIT_DELAY", 0)
    pages = {1: [{"CompanyId": 1}], 2: [{"CompanyId": 2}], 3: []}

    def handler(request):
        if request.url.path.endswith("/oauth/token"):
            return httpx.Response(200, json={"access_token": "tok"})
        return httpx.Response(200, json=pages[int(request.url.params["page_number"])])

    client = BlackKiteClient("id", "s", base_url=BASE, transport=httpx.MockTransport(handler))
    assert [c["CompanyId"] for c in asyncio.run(client.list_companies())] == [1, 2]


def test_service_constants_are_scoped_categories():
    assert "fraudulentdomains" in blackkite_service.FRAUD_CATEGORIES
    assert "fraudulentdomains" not in blackkite_service.FINDING_CATEGORIES
