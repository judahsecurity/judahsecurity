"""CrowdStrike Falcon Hosts + Spotlight integration (mocked Falcon API)."""

import asyncio
from datetime import datetime, timedelta

import pytest

pytest.importorskip("sqlalchemy")
httpx = pytest.importorskip("httpx")

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app.db.database import Base  # noqa: E402
import app.models  # noqa: E402,F401
from app.models.asset import Asset, AssetType  # noqa: E402
from app.models.crowdstrike_integration import CrowdStrikeIntegration  # noqa: E402
from app.models.organization import Organization  # noqa: E402
from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus  # noqa: E402
from app.services import crowdstrike_service as cs  # noqa: E402


# ── fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture()
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine, tables=[
        Organization.__table__, Asset.__table__, Vulnerability.__table__,
        CrowdStrikeIntegration.__table__,
    ])
    s = sessionmaker(bind=engine)()
    s.add(Organization(id=1, name="Acme"))
    s.add(Organization(id=2, name="Other"))
    s.commit()
    yield s
    s.close()


def _integration(db, **kw):
    integ = CrowdStrikeIntegration(organization_id=1, connection_name="falcon", cloud_region="us-1", **kw)
    integ.set_client_id("cid")
    integ.set_client_secret("secret")
    db.add(integ)
    db.commit()
    return integ


def _device(aid="aid1", hostname="WS01", local_ip="10.1.2.3", **kw):
    return {
        "device_id": aid, "hostname": hostname, "local_ip": local_ip,
        "external_ip": "34.120.10.10", "machine_domain": "corp.acme.com",
        "mac_address": "AA-BB-CC-DD-EE-FF", "platform_name": "Windows",
        "os_version": "Windows 11", "product_type_desc": "Workstation",
        "ou": ["Workstations", "HQ"], "site_name": "HQ-Site", "status": "normal",
        "first_seen": "2026-01-01T00:00:00Z", "last_seen": "2026-11-03T00:00:00Z", **kw,
    }


def _finding(fid="aid1_f1", aid="aid1", status="open", **cve):
    base = {"id": "CVE-2026-1000", "severity": "CRITICAL", "base_score": 9.8,
            "exprt_rating": "CRITICAL", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "description": "RCE", "references": ["https://example.com/a"]}
    base.update(cve)
    return {
        "id": fid, "aid": aid, "status": status,
        "created_timestamp": "2026-10-01T00:00:00Z", "updated_timestamp": "2026-11-02T00:00:00Z",
        "closed_timestamp": "2026-11-03T00:00:00Z" if status == "closed" else None,
        "cve": base, "apps": [{"product_name_version": "OpenSSH 9.1"}],
        "remediation": {"entities": [{"title": "Update OpenSSH", "action": "Upgrade to 9.8"}]},
        "evaluation_logic": {"logic": [{"title": "file version check"}]},
        "host_info": {"hostname": "WS01", "local_ip": "10.1.2.3"},
    }


class FakeClient:
    def __init__(self, devices=(), findings=()):
        self.devices = list(devices)
        self.findings = list(findings)
        self.spotlight_filters = []

    async def list_host_ids(self, *, seen_since, limit=None):
        return [d["device_id"] for d in self.devices]

    async def get_hosts(self, ids):
        return [d for d in self.devices if d["device_id"] in ids]

    async def get_spotlight_findings(self, *, fql_filter, limit=None):
        self.spotlight_filters.append(fql_filter)
        return self.findings


@pytest.fixture()
def fake(monkeypatch):
    holder = {"client": FakeClient(), "graph": []}
    monkeypatch.setattr(cs, "_client_for", lambda integ: holder["client"])
    monkeypatch.setattr(cs, "_sync_graph", lambda org, values: holder["graph"].append((org, sorted(values))) or len(values))
    return holder


# ── pure helpers ─────────────────────────────────────────────────────────────


def test_region_mapping_and_rejection():
    assert cs.base_url_for("eu-1") == "https://api.eu-1.crowdstrike.com"
    assert cs.base_url_for("us-gov-1") == "https://api.laggar.gcw.crowdstrike.com"
    with pytest.raises(cs.CrowdStrikeApiError):
        cs.base_url_for("attacker.example")


def test_normalize_host_requires_correlation_fields():
    host = cs.normalize_host(_device())
    assert host["fqdn"] == "ws01.corp.acme.com"
    assert host["mac_address"] == "aa:bb:cc:dd:ee:ff"
    assert host["external_ip"] == "34.120.10.10"
    assert cs.normalize_host(_device(hostname="")) is None
    assert cs.normalize_host(_device(local_ip="not-an-ip")) is None
    assert cs.normalize_host(_device(aid="")) is None
    # A private "external" IP is not internet egress.
    assert cs.normalize_host(_device(external_ip="10.9.9.9"))["external_ip"] is None


def test_prioritization_filters():
    assert cs.prioritization_reasons({"exprt_rating": "HIGH", "vector": "AV:N/AC:L"}) == ["exprt_high_network"]
    assert cs.prioritization_reasons({"exprt_rating": "CRITICAL", "vector": "AV:L/AC:L"}) == []
    assert cs.prioritization_reasons({"exprt_rating": "LOW", "vector": "AV:L",
                                      "cisa_info": {"is_cisa_kev": True}}) == ["cisa_kev"]
    assert cs.prioritization_reasons({"exprt_rating": "LOW", "is_cisa_kev": True}) == ["cisa_kev"]
    assert cs.prioritization_reasons({"id": "cve-2024-1", "exprt_rating": "LOW"},
                                     ["CVE-2024-1"]) == ["attack_chain_cve"]
    assert cs.map_severity("CRITICAL") == Severity.CRITICAL
    assert cs.map_severity("NONE") == Severity.INFO


def test_spotlight_filter_window():
    now = datetime(2026, 11, 4, 12, 0, 0)
    assert cs.spotlight_filter(None, now) == "status:['open','reopen']"
    assert cs.spotlight_filter(datetime(2026, 11, 3, 12, 0, 0), now) == "updated_timestamp:>'2026-11-02T12:00:00Z'"


# ── HTTP client (mock transport) ─────────────────────────────────────────────


def _patch_transport(monkeypatch, handler):
    real = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real(*args, **kwargs)

    monkeypatch.setattr(cs.httpx, "AsyncClient", factory)


def test_host_scroll_and_spotlight_pagination(monkeypatch):
    calls = []

    def handler(request):
        calls.append((request.method, request.url.path, dict(request.url.params.multi_items())))
        if request.url.path == "/oauth2/token":
            return httpx.Response(201, json={"access_token": "tok"})
        assert request.headers["Authorization"] == "Bearer tok"
        if request.url.path == cs.HOSTS_SCROLL_PATH:
            if "offset" not in request.url.params:
                return httpx.Response(200, json={"resources": ["a", "b"], "meta": {"pagination": {"offset": "o1"}}})
            return httpx.Response(200, json={"resources": ["c"], "meta": {"pagination": {"offset": ""}}})
        if request.url.path == cs.SPOTLIGHT_COMBINED_PATH:
            facets = request.url.params.get_list("facet")
            assert set(facets) == set(cs.SPOTLIGHT_FACETS)
            if "after" not in request.url.params:
                return httpx.Response(200, json={"resources": [{"id": "1"}], "meta": {"pagination": {"after": "n1"}}})
            return httpx.Response(200, json={"resources": [{"id": "2"}], "meta": {"pagination": {}}})
        return httpx.Response(404)

    _patch_transport(monkeypatch, handler)
    client = cs.CrowdStrikeClient("us-1", "cid", "secret")

    async def run():
        ids = await client.list_host_ids(seen_since=datetime(2026, 10, 28))
        findings = await client.get_spotlight_findings(fql_filter="status:'open'")
        return ids, findings

    ids, findings = asyncio.run(run())
    assert ids == ["a", "b", "c"]
    assert [f["id"] for f in findings] == ["1", "2"]
    scroll = [c for c in calls if c[1] == cs.HOSTS_SCROLL_PATH]
    assert scroll[0][2]["filter"] == "last_seen:>='2026-10-28T00:00:00Z'"


def test_connection_reports_unlicensed_module(monkeypatch):
    def handler(request):
        if request.url.path == "/oauth2/token":
            return httpx.Response(201, json={"access_token": "tok"})
        if request.url.path == cs.SPOTLIGHT_QUERY_PATH:
            return httpx.Response(403, json={"errors": [{"message": "access denied"}]})
        return httpx.Response(200, json={"resources": []})

    _patch_transport(monkeypatch, handler)
    result = asyncio.run(cs.test_connection("us-1", "cid", "secret"))
    assert result["ok"] is False
    assert result["modules"]["hosts"]["ok"] is True
    assert "Spotlight module is not licensed" in result["message"]


def test_connection_bad_credentials(monkeypatch):
    _patch_transport(monkeypatch, lambda request: httpx.Response(401, json={}))
    result = asyncio.run(cs.test_connection("us-1", "cid", "secret"))
    assert result["ok"] is False and "authentication failed" in result["message"]


# ── end-to-end sync against SQLite ───────────────────────────────────────────


def test_sync_creates_internal_assets_and_prioritized_vulns(db, fake):
    integ = _integration(db)
    fake["client"] = FakeClient(
        devices=[_device(), _device(aid="aid2", hostname="nohost", local_ip=None)],
        findings=[
            _finding(),
            _finding(fid="aid1_f2", id="CVE-2026-2000", exprt_rating="LOW", vector="AV:L"),  # filtered
            _finding(fid="ghost_f1", aid="ghost"),  # uncorrelated
        ],
    )
    result = asyncio.run(cs.sync_integration(db, integ))
    assert result["ok"], result
    assert result["hosts_seen"] == 2 and result["hosts_skipped"] == 1
    assert result["assets_created"] == 1
    assert result["findings_filtered"] == 1 and result["findings_uncorrelated"] == 1
    assert result["vulns_created"] == 1

    asset = db.query(Asset).one()
    assert asset.value == "ws01.corp.acme.com"
    assert asset.asset_type == AssetType.OTHER
    assert asset.is_public is False and asset.hosting_type == "owned"
    assert asset.ip_address == "10.1.2.3"
    assert asset.device_class == "Workstation"
    assert asset.metadata_["crowdstrike"]["aid"] == "aid1"
    assert asset.metadata_["crowdstrike"]["external_ip"] == "34.120.10.10"

    vuln = db.query(Vulnerability).one()
    assert vuln.cve_id == "CVE-2026-1000"
    assert vuln.template_id == "crowdstrike:aid1_f1"
    assert vuln.severity == Severity.CRITICAL
    assert vuln.detected_by == "crowdstrike"
    assert vuln.metadata_["prioritization_reasons"] == ["exprt_critical_network"]
    assert vuln.metadata_["evaluation_logic"] == {"logic": [{"title": "file version check"}]}
    assert "Update OpenSSH" in vuln.remediation

    assert fake["graph"] == [(1, ["ws01.corp.acme.com"])]
    assert integ.last_spotlight_sync_at is not None
    assert fake["client"].spotlight_filters == ["status:['open','reopen']"]


def test_resync_is_idempotent_and_propagates_closure(db, fake):
    integ = _integration(db)
    fake["client"] = FakeClient(devices=[_device()], findings=[_finding()])
    asyncio.run(cs.sync_integration(db, integ))

    # Second pass: DHCP moved the host, the finding was closed and is now below the filter.
    fake["client"] = FakeClient(
        devices=[_device(local_ip="10.1.2.99")],
        findings=[_finding(status="closed", exprt_rating="LOW", vector="AV:L")],
    )
    result = asyncio.run(cs.sync_integration(db, integ))
    assert result["assets_created"] == 0 and result["assets_updated"] == 1
    assert result["vulns_resolved"] == 1 and result["findings_filtered"] == 0
    assert fake["client"].spotlight_filters[0].startswith("updated_timestamp:>")

    asset = db.query(Asset).one()
    assert asset.ip_addresses == ["10.1.2.99"]
    vuln = db.query(Vulnerability).one()
    assert vuln.status == VulnerabilityStatus.RESOLVED


def test_analyst_status_is_not_overridden(db, fake):
    integ = _integration(db)
    fake["client"] = FakeClient(devices=[_device()], findings=[_finding()])
    asyncio.run(cs.sync_integration(db, integ))
    vuln = db.query(Vulnerability).one()
    vuln.status = VulnerabilityStatus.ACCEPTED
    db.commit()
    asyncio.run(cs.sync_integration(db, integ))
    assert db.query(Vulnerability).one().status == VulnerabilityStatus.ACCEPTED


def test_matches_external_asset_without_reclassifying_it(db, fake):
    external = Asset(name="vpn", asset_type=AssetType.SUBDOMAIN, value="vpn.corp.acme.com",
                     organization_id=1, is_public=True, hosting_type="cloud", discovery_source="subfinder")
    other_org = Asset(name="vpn", asset_type=AssetType.SUBDOMAIN, value="vpn.corp.acme.com",
                      organization_id=2, is_public=True)
    db.add_all([external, other_org])
    db.commit()
    integ = _integration(db)
    fake["client"] = FakeClient(devices=[_device(hostname="VPN", local_ip="10.0.0.5")])
    result = asyncio.run(cs.sync_integration(db, integ))
    assert result["assets_created"] == 0 and result["assets_updated"] == 1
    db.refresh(external)
    db.refresh(other_org)
    assert external.metadata_["crowdstrike"]["aid"] == "aid1"
    assert external.is_public is True and external.hosting_type == "cloud"
    assert "source:crowdstrike" in external.tags
    assert not (other_org.metadata_ or {}).get("crowdstrike")


def test_failed_sync_records_error(db, fake):
    integ = _integration(db)

    class Boom(FakeClient):
        async def list_host_ids(self, **kw):
            raise cs.CrowdStrikeModuleError("Hosts")

    fake["client"] = Boom()
    result = asyncio.run(cs.sync_integration(db, integ))
    assert result["ok"] is False
    assert integ.last_sync_ok is False and "Hosts module" in integ.last_error
    assert integ.last_spotlight_sync_at is None


# ── Neo4j mapping ────────────────────────────────────────────────────────────


class _Session:
    def __init__(self):
        self.calls = []

    def run(self, cypher, params=None):
        self.calls.append((cypher, params or {}))


def test_graph_maps_crowdstrike_host_layer(db, fake):
    pytest.importorskip("neo4j")
    from app.services.graph_service import GraphService, _is_crowdstrike_internal, _is_private_ip

    integ = _integration(db)
    fake["client"] = FakeClient(devices=[_device()])
    asyncio.run(cs.sync_integration(db, integ))
    asset = db.query(Asset).one()

    assert _is_crowdstrike_internal(asset) is True
    assert _is_private_ip("10.1.2.3") and not _is_private_ip("34.120.10.10")

    session = _Session()
    GraphService()._sync_crowdstrike_host(session, asset, 1)
    cypher, params = session.calls[0]
    for fragment in (":HAS_AGENT", ":EDRAgent", ":InternalIP {organization_id: $org_id",
                     ":EGRESSES_VIA", ":MEMBER_OF_DOMAIN", ":IN_OU", ":LOCATED_AT", "DELETE old"):
        assert fragment in cypher
    assert params["aid"] == "aid1"
    assert params["local_ip"] == "10.1.2.3"
    assert params["external_ip"] == "34.120.10.10"
    assert params["machine_domain"] == "corp.acme.com"
    assert params["ou_path"] == "Workstations/HQ"
    # Bridge to same-tenant :IP only.
    assert "organization_id: $org_id" in session.calls[1][0] and ":SAME_AS" in session.calls[1][0]


def test_graph_skips_non_crowdstrike_assets():
    pytest.importorskip("neo4j")
    from app.services.graph_service import GraphService

    session = _Session()
    GraphService()._sync_crowdstrike_host(session, Asset(id=5, value="x", metadata_={}), 1)
    assert session.calls == []
