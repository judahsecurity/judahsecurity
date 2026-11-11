"""CrowdStrike Falcon Exposure Management importer (mocked Falcon API)."""

import asyncio
from unittest.mock import AsyncMock

import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("httpx")

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app.db.database import Base  # noqa: E402
import app.models  # noqa: E402,F401
from app.models.asset import Asset, AssetType  # noqa: E402
from app.models.crowdstrike_integration import CrowdStrikeIntegration  # noqa: E402
from app.models.organization import Organization  # noqa: E402
from app.models.port_service import PortService  # noqa: E402
from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus  # noqa: E402
from app.services import crowdstrike_service as svc  # noqa: E402
from app.services.crowdstrike_service import (  # noqa: E402
    FalconApiError,
    FalconClient,
    FalconScopeError,
    classify_prevention_policy,
    external_asset_identity,
    host_protection,
    is_external_asset_exposed,
)


# ── Client ──────────────────────────────────────────────────────────────────


def test_client_resolves_cloud_and_rejects_unknown():
    assert FalconClient("eu-1", "id", "secret").base_url == "https://api.eu-1.crowdstrike.com"
    with pytest.raises(FalconApiError):
        FalconClient("https://evil.example", "id", "secret")


def test_fem_query_follows_offset_pagination():
    client = FalconClient("us-1", "id", "secret")
    client.get = AsyncMock(side_effect=[
        {"resources": ["a", "b"], "meta": {"pagination": {"total": 3}}},
        {"resources": ["c"], "meta": {"pagination": {"total": 3}}},
    ])
    assert asyncio.run(client.query_external_asset_ids()) == ["a", "b", "c"]
    assert client.get.await_args_list[1].args[1]["offset"] == 2


def test_spotlight_follows_after_token():
    client = FalconClient("us-1", "id", "secret")
    client.get = AsyncMock(side_effect=[
        {"resources": [{"id": "v1"}], "meta": {"pagination": {"after": "tok"}}},
        {"resources": [{"id": "v2"}], "meta": {"pagination": {}}},
    ])
    vulns = asyncio.run(client.get_vulnerabilities("status:'open'"))
    assert [v["id"] for v in vulns] == ["v1", "v2"]
    assert client.get.await_args_list[1].args[1]["after"] == "tok"


# ── Prevention-policy posture ────────────────────────────────────────────────


def _policy(enabled=True, prevention="MODERATE", detection="AGGRESSIVE", toggles=None):
    settings = [{"id": "CloudAntiMalware", "name": "Cloud Anti-malware",
                 "value": {"detection": detection, "prevention": prevention}}]
    for sid, on in (toggles or {}).items():
        settings.append({"id": sid, "name": sid, "value": {"enabled": on}})
    return {"id": "pol-1", "name": "Servers", "platform_name": "Linux", "enabled": enabled,
            "prevention_settings": [{"name": "Machine Learning", "settings": settings}]}


def test_policy_in_prevent_mode():
    result = classify_prevention_policy(_policy())
    assert result["mode"] == "prevent"
    assert "Cloud Anti-malware prevention MODERATE" in result["reason"]


def test_policy_detect_only_when_prevention_off():
    result = classify_prevention_policy(
        _policy(prevention="DISABLED", toggles={"PreventSuspiciousProcesses": False})
    )
    assert result["mode"] == "detect_only"
    assert result["blocking_controls_disabled"] == ["PreventSuspiciousProcesses"]


def test_blocking_toggle_alone_counts_as_prevent():
    result = classify_prevention_policy(
        _policy(prevention="DISABLED", toggles={"PreventSuspiciousProcesses": True})
    )
    assert result["mode"] == "prevent"


def test_disabled_policy_and_missing_policy():
    assert classify_prevention_policy(_policy(enabled=False))["mode"] == "disabled"
    assert classify_prevention_policy(None)["mode"] == "unknown"


def test_reduced_functionality_mode_overrides_policy():
    device = {"device_id": "aid1", "reduced_functionality_mode": "yes",
              "device_policies": {"prevention": {"policy_id": "pol-1", "applied": True}}}
    assert host_protection(device, {"pol-1": _policy()})["mode"] == "degraded"
    assert host_protection(None, {})["mode"] == "unknown"


# ── Normalization ───────────────────────────────────────────────────────────


def test_external_asset_identity_and_exposure():
    assert external_asset_identity({"asset_type": "ip", "ip": {"ip_address": "93.184.216.34"}}) == (
        "93.184.216.34", AssetType.IP_ADDRESS)
    assert external_asset_identity({"asset_type": "dns_domain", "dns_domain": {
        "fqdn": "vpn.acme.com.", "parent_domain": "acme.com"}}) == ("vpn.acme.com", AssetType.SUBDOMAIN)
    assert is_external_asset_exposed({"internet_exposure": "No"}) is False
    assert is_external_asset_exposed({"connectivity_status": "Active"}) is True


# ── End-to-end import ───────────────────────────────────────────────────────


@pytest.fixture()
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine, tables=[
        Organization.__table__, CrowdStrikeIntegration.__table__, Asset.__table__,
        PortService.__table__, Vulnerability.__table__,
    ])
    session = sessionmaker(bind=engine)()
    session.add(Organization(id=1, name="Acme"))
    session.add(CrowdStrikeIntegration(
        id=1, organization_id=1, connection_name="Falcon", cloud="us-1",
        client_id_encrypted="x", client_secret_encrypted="x",
    ))
    session.commit()
    yield session
    session.close()


EXTERNAL = [
    {   # Linked to a sensor by aid.
        "id": "ea-1", "asset_type": "ip", "criticality": "High", "connectivity_status": "Active",
        "ip": {"ip_address": "93.184.216.34", "aid": "aid-web", "services": [
            {"port": 443, "transport": "tcp", "protocol": "HTTPS",
             "applications": [{"vendor": "Apache", "name": "httpd", "version": "2.4.49"}]},
        ]},
    },
    {   # Linked by the sensor's external IP.
        "id": "ea-2", "asset_type": "ip",
        "ip": {"ip_address": "45.33.32.156", "services": [{"port": 3389, "transport": "tcp", "protocol": "RDP"}]},
    },
    {"id": "ea-3", "asset_type": "ip", "internet_exposure": "No", "ip": {"ip_address": "198.51.100.7"}},
]

DEVICES = {
    "aid-web": {"device_id": "aid-web", "hostname": "web01",
                "device_policies": {"prevention": {"policy_id": "pol-prevent", "applied": True}}},
    "aid-rdp": {"device_id": "aid-rdp", "hostname": "jump01", "external_ip": "45.33.32.156",
                "device_policies": {"prevention": {"policy_id": "pol-detect", "applied": True}}},
    "aid-lost": {"device_id": "aid-lost", "hostname": "laptop9",
                 "device_policies": {"prevention": {"policy_id": "pol-prevent", "applied": True}}},
}

POLICIES = {
    "pol-prevent": {**_policy(), "id": "pol-prevent"},
    "pol-detect": {**_policy(prevention="DISABLED"), "id": "pol-detect", "name": "Audit only"},
}


def _vuln(vid, aid, cve, severity="CRITICAL", kev=False):
    return {"id": vid, "aid": aid, "status": "open",
            "cve": {"id": cve, "severity": severity, "base_score": 9.8, "exprt_rating": "HIGH",
                    "is_cisa_kev": kev, "description": "Bad bug."},
            "host_info": {"hostname": DEVICES[aid]["hostname"], "internet_exposure": "Yes"},
            "apps": [{"product_name_version": "Apache httpd 2.4.49"}],
            "remediation": {"entities": [{"title": "Upgrade httpd"}]}}


class FakeFalcon:
    def __init__(self, vulns, *, policies_denied=False):
        self.vulns = vulns
        self.policies_denied = policies_denied

    async def query_external_asset_ids(self, fql=None):
        return [a["id"] for a in EXTERNAL]

    async def get_external_assets(self, ids):
        return [a for a in EXTERNAL if a["id"] in ids]

    async def get_vulnerabilities(self, fql):
        return list(self.vulns)

    async def get_devices(self, aids):
        return [DEVICES[a] for a in aids if a in DEVICES]

    async def get_prevention_policies(self, ids):
        if self.policies_denied:
            raise FalconScopeError("Falcon denied /policy/entities/prevention/v1 (HTTP 403)")
        return [POLICIES[i] for i in ids if i in POLICIES]


def _sync(db, monkeypatch, fake):
    monkeypatch.setattr(svc, "_client_for", lambda integration: fake)
    return asyncio.run(svc.sync_integration(db, db.get(CrowdStrikeIntegration, 1)))


def test_sync_builds_exposure_paths_with_prevention_posture(db, monkeypatch):
    fake = FakeFalcon([
        _vuln("v-web", "aid-web", "CVE-2021-41773", kev=True),
        _vuln("v-rdp", "aid-rdp", "CVE-2019-0708"),
        _vuln("v-lost", "aid-lost", "CVE-2024-0001"),  # no external asset -> unlinked
    ])
    result = _sync(db, monkeypatch, fake)

    assert result["ok"], result["message"]
    assert result["assets_created"] == 2  # ea-3 is explicitly not internet exposed
    assert result["exposure_paths"] == 2 and result["vulns_unlinked"] == 1
    assert result["hosts_prevent"] == 2 and result["hosts_detect_only"] == 1

    web = db.query(Asset).filter_by(value="93.184.216.34").one()
    assert "cs-prevention:prevent" in web.tags
    port = db.query(PortService).filter_by(asset_id=web.id, port=443).one()
    assert port.service_product == "httpd" and port.service_version == "2.4.49"

    web_vuln = db.query(Vulnerability).filter_by(template_id="crowdstrike:v-web").one()
    assert web_vuln.severity == Severity.CRITICAL and web_vuln.cve_id == "CVE-2021-41773"
    assert web_vuln.metadata_["port"] == 443 and web_vuln.metadata_["scanned_ip"] == "93.184.216.34"
    assert web_vuln.metadata_["crowdstrike_protection"]["mode"] == "prevent"
    assert "cisa-kev" in web_vuln.tags

    rdp_vuln = db.query(Vulnerability).filter_by(template_id="crowdstrike:v-rdp").one()
    assert rdp_vuln.metadata_["crowdstrike_protection"]["mode"] == "detect_only"
    assert "cs-prevention:detect_only" in rdp_vuln.tags
    assert rdp_vuln.metadata_["exposure_path"]["exposed_services"][0]["port"] == 3389


def test_resync_resolves_findings_no_longer_reported(db, monkeypatch):
    _sync(db, monkeypatch, FakeFalcon([_vuln("v-web", "aid-web", "CVE-2021-41773")]))
    result = _sync(db, monkeypatch, FakeFalcon([]))
    assert result["vulns_resolved"] == 1
    vuln = db.query(Vulnerability).filter_by(template_id="crowdstrike:v-web").one()
    assert vuln.status == VulnerabilityStatus.RESOLVED


def test_missing_policy_scope_degrades_to_unknown(db, monkeypatch):
    result = _sync(db, monkeypatch, FakeFalcon([_vuln("v-web", "aid-web", "CVE-2021-41773")],
                                               policies_denied=True))
    assert result["ok"] and "prevention" in result["message"]
    vuln = db.query(Vulnerability).filter_by(template_id="crowdstrike:v-web").one()
    assert vuln.metadata_["crowdstrike_protection"]["mode"] == "unknown"
