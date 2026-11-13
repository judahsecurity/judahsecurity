import os

import pytest

from app.services import campaign_mitigations as cm


def _feed():
    return {
        "last_updated": "2026-11-12 15:11",
        "threats": [
            {
                "id": "Able2Shell-N-able-N-central-Zero-Days",
                "name": "Able2Shell N-able N-central Zero-Days",
                "short": "Able2Shell N-central zero-days",
                "category": "Exploitation / MSP RMM",
                "published": "2026-11-09",
                "last_updated": "2026-11-12",
                "headline": "Public N-central RCE chains that still work on HF2",
                "summary": "Attempted chain of Apache Axis CVE-2026-90436 then root.",
                "caveat": "Honeypot data only.",
                "recommended_actions": [
                    "Take on-premises N-central servers off the internet, even on 2026.4 HF2.",
                ],
                "ioas": [
                    {
                        "title": "serverchild files",
                        "artefact": "/var/opt/n-central/tmp/serverchild-<12 hex>.sh",
                        "log_source": "EDR file events on the appliance",
                        "action": "alert",
                        "source_url": "https://www.huntress.com/blog/x",
                        "source_name": "Huntress",
                    },
                    {"artefact": ""},
                    "not-a-dict",
                ],
                "sources": [
                    {"url": "https://www.huntress.com/blog/x", "label": "Huntress"},
                    {"url": "javascript:alert(1)", "label": "bad"},
                ],
                "queries": [{"platform": "Defender XDR", "language": "KQL", "url": "https://raw.example/hunt.kql"}],
                "repo_url": "https://github.com/daniyyell-dev/rapid-threat-intel/tree/main/threats/x",
                "mitre": [{"id": "T1190"}],
                "targets": {"sectors": ["Managed service providers"], "regions": ["Global"]},
            },
            {
                # Malware campaign with no CVE and no product: not a vuln/exposure item.
                "id": "StrikeStub",
                "name": "StrikeStub: ClickFix PowerShell Dropper",
                "recommended_actions": ["Block squidscript.com"],
            },
            {
                # Mentions a product only deep in the summary: not product-linked.
                "id": "Passing-Mention",
                "name": "Some Ransomware Group",
                "summary": "Victims also ran Jenkins servers.",
                "recommended_actions": ["Restore from backup"],
            },
        ],
    }


@pytest.fixture()
def cache(tmp_path, monkeypatch):
    monkeypatch.setenv("DELPHI_CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(cm, "_http_get_json", lambda url, timeout=60: _feed())
    monkeypatch.setattr(cm, "_memo", {"key": None, "index": None})
    status = cm.refresh_campaign_feed(force=True)
    assert status == {"status": "refreshed", "campaigns": 1}
    return tmp_path


def test_normalise_keeps_only_vuln_or_product_campaigns_and_drops_unsafe_links():
    data = cm.normalise_feed(_feed())
    assert [c["id"] for c in data["campaigns"]] == ["Able2Shell-N-able-N-central-Zero-Days"]
    campaign = data["campaigns"][0]
    assert campaign["cves"] == ["CVE-2026-90436"]
    assert campaign["products"] == ["N-able N-central"]
    assert campaign["sources"] == [{"label": "Huntress", "url": "https://www.huntress.com/blog/x"}]
    assert len(campaign["compromise_checks"]) == 1
    assert campaign["compromise_checks"][0]["action"] == "alert"


def test_cves_are_deduplicated_across_fields():
    assert cm._cves("CVE-2026-1111 and cve-2026-1111", ["CVE-2026-1111", "CVE-2026-2222"]) == [
        "CVE-2026-1111",
        "CVE-2026-2222",
    ]


def test_normalise_strips_control_characters_and_bounds_length():
    feed = _feed()
    feed["threats"][0]["recommended_actions"] = ["Patch\x00 now" + "x" * 5000]
    action = cm.normalise_feed(feed)["campaigns"][0]["mitigations"][0]
    assert "\x00" not in action
    assert len(action) <= 1500


def test_cve_match(cache):
    result = cm.campaigns_for_finding(cve_id="cve-2026-90436", title="Apache Axis RCE")
    assert [c["match"] for c in result["campaigns"]] == [{"type": "cve", "value": "CVE-2026-90436"}]
    assert result["campaigns"][0]["mitigations"][0].startswith("Take on-premises N-central")


def test_exposure_finding_matches_on_product(cache):
    result = cm.campaigns_for_finding(title="N-able N-central Login Panel - Detect", template_id="ncentral-panel")
    assert [c["match"] for c in result["campaigns"]] == [{"type": "product", "value": "N-able N-central"}]


def test_unrelated_findings_do_not_match(cache):
    assert cm.campaigns_for_finding(title="Jenkins Login - Detect")["campaigns"] == []
    assert cm.campaigns_for_finding(title="Missing HSTS header", tags=["headers"])["campaigns"] == []
    assert cm.campaigns_for_finding(cve_id="CVE-2026-9043")["campaigns"] == []


def test_failed_refresh_keeps_stale_cache(cache, monkeypatch):
    def boom(url, timeout=60):
        raise OSError("network down")

    monkeypatch.setattr(cm, "_http_get_json", boom)
    assert cm.refresh_campaign_feed(force=True)["status"] == "error"
    assert cm.campaigns_for_finding(cve_id="CVE-2026-90436")["campaigns"]


def test_missing_cache_returns_empty_without_blocking(tmp_path, monkeypatch):
    monkeypatch.setenv("DELPHI_CACHE_DIR", str(tmp_path / "empty"))
    monkeypatch.setattr(cm, "_memo", {"key": None, "index": None})
    started = []
    monkeypatch.setattr(cm, "_start_background_refresh", lambda: started.append(True))
    monkeypatch.setattr(cm, "read_json_cache", lambda name: None)
    assert cm.campaigns_for_finding(cve_id="CVE-2026-90436")["campaigns"] == []
    assert started == [True]


def test_disabled_by_env(monkeypatch):
    monkeypatch.setenv("CAMPAIGN_INTEL_ENABLED", "false")
    assert cm.refresh_campaign_feed(force=True) == {"status": "disabled", "campaigns": 0}


def test_jira_description_includes_interim_mitigations_before_playbook():
    from types import SimpleNamespace as N

    from app.services import jira_service

    vuln = N(
        asset=None, severity=N(value="high"), status=None, detected_by="nuclei",
        cve_id=None, cwe_id=None, cvss_score=None, cvss_vector=None, description=None,
        evidence=None, proof_of_concept=None, steps_to_reproduce=None,
        remediation="Upgrade N-central", metadata_=None, references=[],
    )
    campaign = cm.normalise_feed(_feed())["campaigns"][0]
    campaign["match"] = {"type": "product", "value": "N-able N-central"}
    doc = jira_service._build_description(vuln, True, True, True, True, True, campaigns=[campaign])

    headings = [
        b["content"][0]["text"] for b in doc["content"] if b.get("type") == "heading"
    ]
    assert headings.index("Active Exploitation Campaign: Interim Mitigations") < headings.index("Remediation")
    assert "Check for prior compromise" in headings


# ── Finding sweep ────────────────────────────────────────────────────────────

@pytest.fixture()
def db_factory():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    import app.models  # noqa: F401
    from app.db.database import Base
    from app.models.asset import Asset, AssetType
    from app.models.organization import Organization
    from app.models.vulnerability import Vulnerability

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine, tables=[Organization.__table__, Asset.__table__, Vulnerability.__table__])
    factory = sessionmaker(bind=engine)
    s = factory()
    s.add(Organization(id=1, name="Acme"))
    s.add(Asset(id=1, organization_id=1, name="ncentral.internal", value="ncentral.internal",
                asset_type=AssetType.DOMAIN, is_public=False))
    s.commit()
    s.close()
    return factory


def _vuln(factory, vid, **kw):
    from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus

    s = factory()
    fields = {"title": "x", "severity": Severity.HIGH, "status": VulnerabilityStatus.OPEN, "asset_id": 1}
    fields.update(kw)
    s.add(Vulnerability(id=vid, **fields))
    s.commit()
    s.close()


def _stamps(factory):
    from app.models.vulnerability import Vulnerability

    s = factory()
    try:
        return {v.id: (v.campaign_match, v.campaign_ids) for v in s.query(Vulnerability).all()}
    finally:
        s.close()


def test_sweep_stamps_cve_and_product_matches(cache, db_factory):
    from app.models.vulnerability import Severity, VulnerabilityStatus

    able = "Able2Shell-N-able-N-central-Zero-Days"
    _vuln(db_factory, 1, title="Apache Axis RCE", cve_id="CVE-2026-90436")
    _vuln(db_factory, 2, title="N-able N-central 2026.4 < HF3 Multiple Vulnerabilities")
    _vuln(db_factory, 3, title="N-central Panel - Detect", severity=Severity.INFO)  # inventory only
    _vuln(db_factory, 4, title="Apache Axis RCE", cve_id="CVE-2026-90436", status=VulnerabilityStatus.RESOLVED)
    _vuln(db_factory, 5, title="Central logging misconfigured")  # probe hit, alias miss
    _vuln(db_factory, 6, title="OpenSSL outdated", cve_id="CVE-2026-9043")

    result = cm.sync_campaign_matches(db_factory)

    assert result == {"status": "ok", "matched": 2, "cve": 1, "product": 1, "updated": 2, "cleared": 0}
    stamps = _stamps(db_factory)
    assert stamps[1] == ("cve", [able])
    assert stamps[2] == ("product", [able])
    assert all(stamps[v] == (None, None) for v in (3, 4, 5, 6))


def test_sweep_is_idempotent_and_clears_aged_out_campaigns(cache, db_factory, monkeypatch):
    _vuln(db_factory, 1, title="Apache Axis RCE", cve_id="CVE-2026-90436")
    cm.sync_campaign_matches(db_factory)
    assert cm.sync_campaign_matches(db_factory)["updated"] == 0

    feed = _feed()
    feed["threats"] = feed["threats"][1:]  # the campaign leaves the feed
    monkeypatch.setattr(cm, "_http_get_json", lambda url, timeout=60: feed)
    cm.refresh_campaign_feed(force=True)

    assert cm.sync_campaign_matches(db_factory)["cleared"] == 1
    assert _stamps(db_factory)[1] == (None, None)


def test_sweep_keeps_stamps_when_feed_data_missing(db_factory, monkeypatch):
    monkeypatch.setattr(cm, "_load_index", lambda: None)
    assert cm.sync_campaign_matches(db_factory) == {"status": "no_data"}


def test_findings_list_filters_internal_campaign_findings_and_sorts_them_first(db_factory):
    from types import SimpleNamespace

    from fastapi import HTTPException
    from sqlalchemy import update

    from app.api.routes import vulnerabilities as routes
    from app.db.database import Base
    from app.models.asset import Asset, AssetType
    from app.models.business_application import BusinessApplication
    from app.models.screenshot import Screenshot
    from app.models.vulnerability import Vulnerability

    s = db_factory()
    Base.metadata.create_all(s.get_bind(), tables=[Screenshot.__table__, BusinessApplication.__table__])
    s.add(Asset(id=2, organization_id=1, name="www.acme.com", value="www.acme.com", asset_type=AssetType.DOMAIN, is_public=True))
    s.commit()
    s.close()
    _vuln(db_factory, 1, title="internal, no campaign", sev_score=90.0)
    _vuln(db_factory, 2, title="internal, product match", sev_score=40.0)
    _vuln(db_factory, 3, title="internal, cve match", sev_score=20.0)
    _vuln(db_factory, 4, title="internet, cve match", asset_id=2, sev_score=95.0)
    s = db_factory()
    for vid, match in ((2, "product"), (3, "cve"), (4, "cve")):
        s.execute(update(Vulnerability).where(Vulnerability.id == vid).values(campaign_match=match, campaign_ids=["x"]))
    s.commit()

    user = SimpleNamespace(is_superuser=False, organization_id=1)

    def ids(**kw):
        params = dict(severity=None, opes_category=None, status=None, asset_id=None, cve_id=None,
                      include_out_of_scope=True, skip=0, limit=50, detected_by=None, risk_level=None,
                      triage=None, business_app_id=None, active_campaign=None, exposure=None, sort=None)
        params.update(kw)
        return [v["id"] for v in routes.list_vulnerabilities(db=s, current_user=user, **params)]

    assert ids(exposure="internal", sort="campaign") == [3, 2, 1]
    assert ids(exposure="internal", active_campaign="any", sort="campaign") == [3, 2]
    assert ids(active_campaign="cve", sort="campaign") == [4, 3]
    assert ids(exposure="internet") == [4]
    with pytest.raises(HTTPException):
        ids(active_campaign="bogus")
    s.close()
