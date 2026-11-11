"""Vulnerability response: SLA policy, triage gate, notice rendering, webhook outbox, API."""

import io
import json
import zipfile
from datetime import datetime, timedelta

import pytest

pytest.importorskip("sqlalchemy")
httpx = pytest.importorskip("httpx")
pytest.importorskip("fastapi")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.db.database import Base, get_db  # noqa: E402
import app.models  # noqa: E402,F401
from app.api import deps  # noqa: E402
from app.api.routes import finding_response as routes  # noqa: E402
from app.models.agent_api_key import AgentAPIKey  # noqa: E402
from app.models.asset import Asset, AssetType  # noqa: E402
from app.models.finding_observation import FindingObservation  # noqa: E402
from app.models.finding_response import EventStatus, FindingEvent, FindingResponse, TriageStatus  # noqa: E402
from app.models.organization import Organization  # noqa: E402
from app.models.project_settings import MODULE_FINDING_RESPONSE, ProjectSettings  # noqa: E402
from app.models.user import User, UserRole  # noqa: E402
from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus  # noqa: E402
from app.services import finding_notice, finding_response as fr, sla_policy  # noqa: E402
from app.services.ingestion_service import create_agent_api_key  # noqa: E402

NOW = datetime(2026, 11, 10, 12, 0, 0)


@pytest.fixture()
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine, tables=[
        Organization.__table__, User.__table__, Asset.__table__, Vulnerability.__table__,
        FindingObservation.__table__, FindingResponse.__table__, FindingEvent.__table__,
        ProjectSettings.__table__, AgentAPIKey.__table__,
    ])
    session = sessionmaker(bind=engine)()
    session.add_all([Organization(id=1, name="Acme"), Organization(id=2, name="Other")])
    session.commit()
    yield session
    session.close()


def _finding(db, *, severity=Severity.HIGH, public=True, org=1, value="www.sure-start.com", **kw):
    asset = Asset(organization_id=org, value=value, name=value, asset_type=AssetType.SUBDOMAIN, is_public=public)
    db.add(asset)
    db.flush()
    vuln = Vulnerability(
        title=kw.pop("title", "Expired SSL Certificate"), severity=severity, asset_id=asset.id,
        status=VulnerabilityStatus.OPEN, detected_by="nuclei", first_detected=NOW - timedelta(days=3),
        description="This certificate has expired.", impact="Expired certificate",
        remediation="Replace the certificate.", affected_component="443/tcp", **kw,
    )
    db.add(vuln)
    db.commit()
    return vuln


def _configure(db, org=1, **config):
    ProjectSettings.set_config(db, org, MODULE_FINDING_RESPONSE, config)
    db.commit()


# ── SLA policy ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize("tier,public,days", [
    ("urgent", True, 2), ("critical", True, 14), ("high", True, 30), ("medium", True, 60), ("low", True, 90),
    ("urgent", False, 10), ("critical", False, 30), ("high", False, 60), ("medium", False, 90), ("low", False, 180),
])
def test_default_policy_matches_sla_table(db, tier, public, days):
    vuln = _finding(db, public=public)
    sla = sla_policy.compute_sla(vuln, sla_policy.load_policy(db, 1), tier=tier, now=NOW)
    assert sla.days == days and sla.due_at == NOW + timedelta(days=days)


def test_info_has_no_deadline_and_exposure_defaults_from_asset(db):
    vuln = _finding(db, severity=Severity.INFO, public=False)
    sla = sla_policy.compute_sla(vuln, sla_policy.load_policy(db, 1), now=NOW)
    assert sla.tier == "info" and sla.days is None and sla.due_at is None
    assert sla.internet_accessible is False


def test_kev_critical_promotes_to_urgent(db):
    vuln = _finding(db, severity=Severity.CRITICAL, tags=["kev"])
    assert sla_policy.default_tier(vuln, sla_policy.load_policy(db, 1)) == "urgent"
    vuln.tags = []
    assert sla_policy.default_tier(vuln, sla_policy.load_policy(db, 1)) == "critical"


def test_risk_level_tier_source(db):
    vuln = _finding(db, severity=Severity.HIGH, sev_level="informational")
    policy = {**sla_policy.load_policy(db, 1), "tier_source": "risk_level"}
    assert sla_policy.default_tier(vuln, policy) == "info"


@pytest.mark.parametrize("update", [
    {"internet_accessible": {"high": 0}},
    {"internet_accessible": {"severe": 5}},
    {"tier_source": "cvss"},
    {"reminder_thresholds": [1.5]},
])
def test_policy_validation_rejects_bad_values(db, update):
    with pytest.raises(sla_policy.PolicyError):
        sla_policy.validate_policy(sla_policy.merge_policy(sla_policy.load_policy(db, 1), update))


# ── Triage ───────────────────────────────────────────────────────────────────


def test_approve_sets_deadline_and_routes_notice_to_webhook(db):
    vuln = _finding(db)
    resp = fr.approve(db, vuln, 1, "analyst@acme.com", owner_email="owner@acme.com",
                      edits={"steps_to_reproduce": "Run openssl s_client"}, now=NOW)
    db.commit()
    assert resp.triage_status == TriageStatus.APPROVED and resp.sla_tier == "high"
    assert resp.sla_due_at == NOW + timedelta(days=30) and vuln.remediation_deadline == resp.sla_due_at
    assert vuln.steps_to_reproduce == "Run openssl s_client"
    events = db.query(FindingEvent).order_by(FindingEvent.id).all()
    assert [(e.event_type, e.action, e.status) for e in events] == [
        ("triaged", None, EventStatus.RECORDED),
        ("owner_notice", "notify_owner", EventStatus.PENDING),
    ]
    payload = events[1].payload
    assert payload["finding"]["remediation_due"] == "12/10/2026"
    assert payload["finding"]["owner_email"] == "owner@acme.com"
    assert payload["finding"]["links"]["actions_callback"].endswith(f"/findings/{vuln.id}/actions")


@pytest.mark.parametrize("executor,status", [("judah", EventStatus.QUEUED_NATIVE), ("off", EventStatus.SKIPPED),
                                             ("blink", EventStatus.PENDING)])
def test_executor_routing(db, executor, status):
    _configure(db, executors={"notify_owner": executor})
    vuln = _finding(db)
    fr.approve(db, vuln, 1, "a", now=NOW)
    event = db.query(FindingEvent).filter_by(action="notify_owner").one()
    assert event.status == status


def test_reapproval_keeps_clock_and_does_not_renotify(db):
    vuln = _finding(db)
    fr.approve(db, vuln, 1, "a", now=NOW)
    resp = fr.approve(db, vuln, 1, "b", tier="critical", notify=False, now=NOW + timedelta(days=5))
    assert resp.sla_started_at == NOW and resp.sla_due_at == NOW + timedelta(days=14)
    assert db.query(FindingEvent).filter_by(action="notify_owner").count() == 1
    assert db.query(FindingEvent).filter_by(event_type="triage_updated").count() == 1


def test_reject_as_false_positive_and_queue(db):
    keep = _finding(db, value="a.acme.com")
    drop = _finding(db, value="b.acme.com")
    queue = fr.triage_queue(db, 1)
    assert {i["vulnerability_id"] for i in queue} == {keep.id, drop.id}
    assert queue[0]["proposed_sla"]["days"] == 30
    fr.reject(db, drop, 1, "a", note="dup", false_positive=True)
    db.commit()
    assert drop.status == VulnerabilityStatus.FALSE_POSITIVE
    assert {i["vulnerability_id"] for i in fr.triage_queue(db, 1)} == {keep.id}


def test_closed_finding_cannot_be_approved(db):
    vuln = _finding(db, )
    vuln.status = VulnerabilityStatus.RESOLVED
    with pytest.raises(fr.ResponseError):
        fr.approve(db, vuln, 1, "a")


# ── Webhook delivery ─────────────────────────────────────────────────────────


class Recorder:
    def __init__(self, status_code=200):
        self.status_code = status_code
        self.requests = []

    def __call__(self, request):
        self.requests.append(request)
        return httpx.Response(self.status_code)


def test_delivery_signs_and_sends_api_key(db):
    _configure(db, webhook_url="https://hooks.example.com/judah",
               webhook_secret_encrypted=fr.encrypt_secret("s3cret"),
               webhook_api_key_header="BLINK-API-KEY", webhook_api_key_encrypted=fr.encrypt_secret("k1"))
    vuln = _finding(db)
    fr.approve(db, vuln, 1, "a", now=NOW)
    rec = Recorder()
    stats = fr.deliver_pending(db, client=httpx.Client(transport=httpx.MockTransport(rec)))
    assert stats == {"delivered": 1, "retrying": 0, "failed": 0}
    req = rec.requests[0]
    assert req.headers["BLINK-API-KEY"] == "k1"
    assert req.headers["X-Judah-Event"] == "owner_notice"
    expected = fr.sign("s3cret", req.headers["X-Judah-Timestamp"], req.content)
    assert req.headers["X-Judah-Signature"] == expected
    assert json.loads(req.content)["action"] == "notify_owner"
    assert db.query(FindingEvent).filter_by(action="notify_owner").one().status == EventStatus.DELIVERED


def test_delivery_retries_then_fails(db):
    _configure(db, webhook_url="https://hooks.example.com/judah")
    vuln = _finding(db)
    fr.approve(db, vuln, 1, "a", now=NOW)
    event = db.query(FindingEvent).filter_by(action="notify_owner").one()
    client = httpx.Client(transport=httpx.MockTransport(Recorder(500)))
    stats = fr.deliver_pending(db, client=client)
    assert stats["retrying"] == 1 and event.attempts == 1 and "HTTP 500" in event.last_error
    assert event.next_attempt_at > datetime.utcnow()
    event.attempts = fr.MAX_DELIVERY_ATTEMPTS - 1
    event.next_attempt_at = datetime.utcnow() - timedelta(seconds=1)
    assert fr.deliver_pending(db, client=client)["failed"] == 1
    assert event.status == EventStatus.FAILED


def test_delivery_without_url_records_error(db):
    vuln = _finding(db)
    fr.approve(db, vuln, 1, "a", now=NOW)
    fr.deliver_pending(db, client=httpx.Client(transport=httpx.MockTransport(Recorder())))
    event = db.query(FindingEvent).filter_by(action="notify_owner").one()
    assert event.status == EventStatus.PENDING and "No webhook URL" in event.last_error


@pytest.mark.parametrize("url", ["http://hooks.example.com", "https://127.0.0.1/x", "https://10.0.0.5/x",
                                 "https://user:pw@hooks.example.com", "https://localhost/x"])
def test_webhook_url_validation(url):
    with pytest.raises(fr.ResponseError):
        fr.validate_webhook_url(url)


# ── Callback + SLA sweep ─────────────────────────────────────────────────────


def test_callback_marks_notified(db):
    vuln = _finding(db)
    resp = fr.approve(db, vuln, 1, "a", now=NOW)
    event = db.query(FindingEvent).filter_by(action="notify_owner").one()
    fr.record_action_result(db, vuln, 1, action="notify_owner", outcome="done", actor="blink",
                            event_id=event.id, details={"channel": "email", "owner_email": "o@acme.com"})
    assert event.status == EventStatus.DONE and resp.notified_via == "email" and resp.owner_email == "o@acme.com"
    with pytest.raises(fr.ResponseError):
        fr.record_action_result(db, vuln, 1, action="open_ticket", outcome="done", actor="x", event_id=event.id)


def test_sweep_reminds_breaches_and_closes_out(db):
    vuln = _finding(db)  # high, internet: 30 days
    fr.approve(db, vuln, 1, "a", now=NOW)

    def sweep(days):
        return fr.run_sla_sweep(db, 1, now=NOW + timedelta(days=days))

    assert sweep(10)["reminders"] == 0
    assert sweep(16)["reminders"] == 1          # 50%
    assert sweep(17)["reminders"] == 0          # already sent
    assert sweep(28)["reminders"] == 1          # 90%
    assert sweep(31)["breaches"] == 1
    assert sweep(40)["breaches"] == 0           # breach fires once
    vuln.status = VulnerabilityStatus.RESOLVED
    assert sweep(41)["closed_out"] == 1
    assert sweep(42)["closed_out"] == 0
    types = [e.event_type for e in db.query(FindingEvent).order_by(FindingEvent.id)]
    assert types == ["triaged", "owner_notice", "sla_warning", "sla_warning", "sla_breached", "resolved"]


def test_sweep_sends_one_reminder_when_thresholds_skipped(db):
    vuln = _finding(db)
    fr.approve(db, vuln, 1, "a", now=NOW)
    assert fr.run_sla_sweep(db, 1, now=NOW + timedelta(days=29))["reminders"] == 1
    assert fr.get_response(db, vuln).reminders_sent == [0.5, 0.9]


# ── Notice ───────────────────────────────────────────────────────────────────


def test_notice_fields_html_and_docx(db):
    vuln = _finding(db, title="Expired <b>cert</b>", evidence="Serial: 01AB")
    resp = fr.approve(db, vuln, 1, "a", now=NOW)
    fields = finding_notice.build_fields(vuln, resp, fr.load_settings(db, 1))
    assert fields["severity"] == "High" and fields["color"] == "FF0000"
    assert fields["remediation_date"] == "12/10/2026"
    assert fields["affected_asset_url"] == "https://www.sure-start.com"
    assert fields["missing_fields"] == ["steps_to_reproduce"]
    assert fields["subject"] == "[High] Expired <b>cert</b> - remediate by 12/10/2026"
    html = finding_notice.render_html(fields)
    assert "Expired &lt;b&gt;cert&lt;/b&gt;" in html and "<b>cert</b>" not in html
    assert "Key Evidence" in html and "color:#FF0000" in html
    docx = zipfile.ZipFile(io.BytesIO(finding_notice.render_docx(fields)))
    document = docx.read("word/document.xml").decode()
    assert "Expired &lt;b&gt;cert&lt;/b&gt;" in document and 'w:val="FF0000"' in document
    assert "https://www.sure-start.com" in docx.read("word/_rels/document.xml.rels").decode()


def test_notice_urgent_color_and_no_link_for_ip(db):
    vuln = _finding(db, severity=Severity.CRITICAL, value="93.184.216.34", tags=["kev"])
    resp = fr.approve(db, vuln, 1, "a", now=NOW)
    fields = finding_notice.build_fields(vuln, resp, fr.load_settings(db, 1))
    assert fields["severity"] == "Urgent" and fields["color"] == "7030A0"
    assert fields["affected_asset_url"] is None and fields["remediation_date"] == "11/12/2026"


# ── API ──────────────────────────────────────────────────────────────────────


@pytest.fixture()
def api(db):
    app = FastAPI()
    app.include_router(routes.router, prefix="/api/v1")
    state = {"user": None}
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[deps.get_current_user_optional] = lambda: state["user"]
    client = TestClient(app)
    client.state = state
    return client


def _user(db, role=UserRole.ANALYST, org=1):
    user = User(email=f"{role.value}@acme.com", username=role.value, hashed_password="x", role=role,
                organization_id=org, is_active=True)
    db.add(user)
    db.commit()
    return user


def test_api_requires_auth(api):
    assert api.get("/api/v1/finding-response/triage-queue").status_code == 401


def test_api_analyst_triage_and_notice(api, db):
    api.state["user"] = _user(db)
    vuln = _finding(db)
    r = api.post(f"/api/v1/finding-response/findings/{vuln.id}/triage",
                 json={"sla_tier": "critical", "owner_email": "owner@acme.com",
                       "edits": {"steps_to_reproduce": "openssl s_client -connect host:443"}})
    assert r.status_code == 200, r.text
    assert r.json()["response"]["sla_days"] == 14
    notice = api.get(f"/api/v1/finding-response/findings/{vuln.id}/notice").json()
    assert notice["to"] == "owner@acme.com" and notice["fields"]["severity"] == "Critical"
    docx = api.get(f"/api/v1/finding-response/findings/{vuln.id}/notice?format=docx")
    assert docx.status_code == 200 and docx.headers["content-type"].startswith("application/vnd.openxmlformats")
    assert api.get(f"/api/v1/finding-response/findings/{vuln.id}/notice?format=text").text.startswith(
        "External Exposure\nExpired SSL Certificate")


def test_api_viewer_cannot_triage_or_change_policy(api, db):
    api.state["user"] = _user(db, role=UserRole.VIEWER)
    vuln = _finding(db)
    assert api.post(f"/api/v1/finding-response/findings/{vuln.id}/triage", json={}).status_code == 403
    assert api.put("/api/v1/finding-response/settings/sla-policy",
                   json={"internet_accessible": {"high": 21}}).status_code == 403


def test_api_admin_updates_policy_and_webhook(api, db):
    api.state["user"] = _user(db, role=UserRole.ADMIN)
    r = api.put("/api/v1/finding-response/settings/sla-policy", json={"internet_accessible": {"high": 21}})
    assert r.status_code == 200 and r.json()["internet_accessible"]["high"] == 21
    assert r.json()["internet_accessible"]["critical"] == 14
    bad = api.put("/api/v1/finding-response/settings/sla-policy", json={"non_internet_accessible": {"low": -1}})
    assert bad.status_code == 400
    r = api.put("/api/v1/finding-response/settings/webhook",
                json={"url": "https://hooks.example.com/x", "secret": "s", "api_key_header": "BLINK-API-KEY",
                      "api_key": "k"})
    assert r.status_code == 200
    body = r.json()
    assert body["webhook_secret_set"] and body["webhook_api_key_set"]
    assert "webhook_secret_encrypted" not in body
    assert api.put("/api/v1/finding-response/settings/response",
                   json={"executors": {"notify_owner": "smoke-signal"}}).status_code == 400


def test_api_key_can_read_and_report_but_not_triage(api, db):
    _, key = create_agent_api_key(db, 1, "blink", agent_type="blink", scopes=["findings:respond"])
    db.commit()
    vuln = _finding(db)
    fr.approve(db, vuln, 1, "a", now=NOW)
    db.commit()
    headers = {"X-API-Key": key}
    assert api.get(f"/api/v1/finding-response/findings/{vuln.id}/notice", headers=headers).status_code == 200
    assert api.post(f"/api/v1/finding-response/findings/{vuln.id}/triage", json={},
                    headers=headers).status_code == 403
    event = db.query(FindingEvent).filter_by(action="notify_owner").one()
    r = api.post(f"/api/v1/finding-response/findings/{vuln.id}/actions", headers=headers,
                 json={"action": "notify_owner", "event_id": event.id, "details": {"channel": "outlook"}})
    assert r.status_code == 200 and r.json()["status"] == EventStatus.DONE
    assert fr.get_response(db, vuln).notified_via == "outlook"


def test_api_key_with_triage_scope_and_org_isolation(api, db):
    _, key = create_agent_api_key(db, 1, "blink-triage", agent_type="blink",
                                  scopes=["findings:respond", "findings:triage"])
    db.commit()
    mine = _finding(db)
    theirs = _finding(db, org=2, value="other.example.com")
    headers = {"X-API-Key": key}
    assert api.post(f"/api/v1/finding-response/findings/{mine.id}/triage", json={},
                    headers=headers).status_code == 200
    assert api.get(f"/api/v1/finding-response/findings/{theirs.id}/notice",
                   headers=headers).status_code == 404


def test_run_cycle_covers_orgs_on_default_settings(db):
    vuln = _finding(db)
    fr.approve(db, vuln, 1, "a", now=datetime.utcnow() - timedelta(days=40))
    db.commit()
    assert fr.active_org_ids(db) == [1]
    totals = fr.run_cycle(lambda: db)
    assert totals["breaches"] == 1


def test_exposure_letter_layout(db):
    """Reproduces the earlier "External Exposure" owner notification."""
    _configure(db, notice={
        "date_format": "%B %d, %Y",
        "labels": {"severity": "Criticality", "asset": "Impacted Asset"},
        "contact_email": "vm-team@example.com",
    })
    vuln = _finding(db, severity=Severity.CRITICAL, value="159.180.134.3",
                    title="Port Exposure Detected - SNMP Service Exposed - Port 161 TCP on 159.180.134.3")
    vuln.detected_by = "tenable_vm"
    vuln.first_detected = datetime(2023, 8, 23)
    vuln.impact = "Exposed ports are vulnerable to compromise"
    vuln.steps_to_reproduce = "Tenable and NMAP scans"
    db.commit()
    resp = fr.approve(db, vuln, 1, "a", owner_team="IAI BISO & Compliance Team", now=datetime(2023, 8, 24))
    resp.ticket_key = "213940"
    fields = finding_notice.build_fields(vuln, resp, fr.load_settings(db, 1))
    assert fields["header"] == "External Exposure"
    assert fields["finding_type"] == "Service or Interface Exposure"
    assert fields["recipient"] == "IAI BISO & Compliance Team"
    assert fields["reporter"] == "Tenable" and fields["ticket_number"] == "213940"
    assert fields["remediation_date"] == "September 07, 2023"
    intro = finding_notice.plain(fields["intro"])
    assert intro.startswith("On August 23, 2023, an external vulnerability") and "within 14 days" in intro
    assert fields["closing"][0][1] == {"text": "Vulnerability Management", "href": "mailto:vm-team@example.com"}
    html = finding_notice.render_html(fields)
    assert "Criticality:" in html and "Impacted Asset:" in html and 'href="mailto:vm-team@example.com"' in html
    assert "IAI BISO &amp; Compliance Team" in html
    text = finding_notice.render_text(fields)
    assert "Ticket Number: 213940" in text and "(vm-team@example.com)" in text
    docx = zipfile.ZipFile(io.BytesIO(finding_notice.render_docx(fields)))
    assert "mailto:vm-team@example.com" in docx.read("word/_rels/document.xml.rels").decode()


def test_internal_finding_header_and_no_sla_intro(db):
    vuln = _finding(db, severity=Severity.INFO, public=False)
    resp = fr.approve(db, vuln, 1, "a", finding_type="Informational", now=NOW)
    fields = finding_notice.build_fields(vuln, resp, fr.load_settings(db, 1))
    assert fields["header"] == "Internal Exposure" and fields["finding_type"] == "Informational"
    assert "days" not in finding_notice.plain(fields["intro"])
    assert fields["remediation_date"] == ""


def test_api_rejects_bad_notice_settings(api, db):
    api.state["user"] = _user(db, role=UserRole.ADMIN)
    url = "/api/v1/finding-response/settings/response"
    assert api.put(url, json={"notice": {"closing_templates": "not a list"}}).status_code == 400
    assert api.put(url, json={"notice": {"labels": {"severity": 5}}}).status_code == 400
    ok = api.put(url, json={"notice": {"labels": {"severity": "Criticality"}, "contact_email": "vm@x.com"}})
    assert ok.status_code == 200
    labels = ok.json()["response"]["notice"]["labels"]
    assert labels["severity"] == "Criticality" and labels["asset"] == "Affected Asset"
