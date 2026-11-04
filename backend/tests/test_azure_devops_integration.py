"""Azure DevOps Boards integration (mocked REST API)."""

import asyncio
import base64
import json

import pytest

pytest.importorskip("sqlalchemy")
httpx = pytest.importorskip("httpx")

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app.db.database import Base  # noqa: E402
import app.models  # noqa: E402,F401
from app.models.asset import Asset, AssetType  # noqa: E402
from app.models.azure_devops_integration import (  # noqa: E402
    AzureDevOpsIntegration,
    AzureDevOpsTemplate,
    AzureDevOpsWorkItem,
)
from app.models.organization import Organization  # noqa: E402
from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus  # noqa: E402
from app.services import azure_devops_service as ado  # noqa: E402

ORG = "https://dev.azure.com/acme"


# ── fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture()
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine, tables=[
        Organization.__table__, Asset.__table__, Vulnerability.__table__,
        AzureDevOpsIntegration.__table__, AzureDevOpsTemplate.__table__, AzureDevOpsWorkItem.__table__,
    ])
    s = sessionmaker(bind=engine)()
    s.add(Organization(id=1, name="Acme"))
    s.add(Asset(id=1, name="www", asset_type=AssetType.SUBDOMAIN, value="www.acme.com",
                root_domain="acme.com", organization_id=1))
    s.add(Vulnerability(id=10, title="Exposed <admin> panel", severity=Severity.HIGH,
                        status=VulnerabilityStatus.OPEN, asset_id=1, description="Admin UI reachable",
                        evidence="HTTP/1.1 200 OK", proof_of_concept="curl https://www.acme.com/admin",
                        references=["https://example.com/ref"]))
    integ = AzureDevOpsIntegration(id=1, organization_id=1, organization_url=ORG, auth_method="pat")
    integ.set_pat("secret-pat")
    s.add(integ)
    s.commit()
    yield s
    s.close()


class FakeADO:
    """Minimal in-memory Azure DevOps REST server for httpx.MockTransport."""

    def __init__(self):
        self.calls = []
        self.items = {}
        self.next_id = 100
        self.reject_severity = False
        self.throttle_once = False

    def __call__(self, request: httpx.Request) -> httpx.Response:
        is_json = "json" in request.headers.get("content-type", "")
        body = json.loads(request.content) if request.content and is_json else None
        self.calls.append((request.method, request.url.path, body, dict(request.headers)))
        path = request.url.path
        if self.throttle_once:
            self.throttle_once = False
            return httpx.Response(429, headers={"Retry-After": "0"}, json={"message": "slow down"})
        if path.endswith("/oauth2/v2.0/token"):
            return httpx.Response(200, json={"access_token": "entra-token", "expires_in": 3600})
        if path == "/acme/_apis/projects":
            return httpx.Response(200, json={"value": [{"id": "p1", "name": "Security"}]})
        if "/_apis/wit/workitems/$" in path and request.method == "POST":
            fields = {op["path"].split("/fields/")[1]: op["value"] for op in body}
            if self.reject_severity and ado.SEVERITY_FIELD in fields:
                return httpx.Response(400, json={"message": f"TF51535: Cannot find field {ado.SEVERITY_FIELD}."})
            wid = self.next_id
            self.next_id += 1
            project = path.split("/")[2]
            wit = path.rsplit("$", 1)[1]
            item = {"id": wid, "fields": {**fields, "System.State": "New", "System.TeamProject": project,
                                          "System.WorkItemType": wit},
                    "_links": {"html": {"href": f"{ORG}/{project}/_workitems/edit/{wid}"}}}
            self.items[wid] = item
            return httpx.Response(200, json=item)
        if path == "/acme/_apis/wit/workitemsbatch":
            return httpx.Response(200, json={"value": [self.items[i] for i in body["ids"] if i in self.items]})
        if path.startswith("/acme/_apis/wit/workitems/"):
            wid = int(path.rsplit("/", 1)[1])
            if wid not in self.items:
                return httpx.Response(404, json={"message": f"TF401232: Work item {wid} does not exist."})
            if request.method == "PATCH":
                for op in body:
                    self.items[wid]["fields"][op["path"].split("/fields/")[1]] = op["value"]
            return httpx.Response(200, json=self.items[wid])
        if path.endswith("/comments"):
            return httpx.Response(200, json={"id": 1})
        return httpx.Response(404, json={"message": f"unhandled {path}"})


@pytest.fixture()
def fake(monkeypatch):
    f = FakeADO()
    monkeypatch.setattr(ado, "_transport", httpx.MockTransport(f))
    ado._token_cache.clear()

    async def no_sleep(_):
        return None
    monkeypatch.setattr(ado.asyncio, "sleep", no_sleep)
    return f


# ── pure helpers ─────────────────────────────────────────────────────────────

def test_normalize_organization_url():
    assert ado.normalize_organization_url("https://dev.azure.com/acme/") == ORG
    assert ado.normalize_organization_url("dev.azure.com/acme") == ORG
    with pytest.raises(ValueError, match="visualstudio.com"):
        ado.normalize_organization_url("https://acme.visualstudio.com")
    with pytest.raises(ValueError):
        ado.normalize_organization_url("https://example.com/acme")
    with pytest.raises(ValueError):
        ado.normalize_organization_url("http://dev.azure.com/acme")


def test_severity_mapping():
    assert ado.map_severity("critical") == "1 - Critical"
    assert ado.map_severity("HIGH") == "2 - High"
    assert ado.map_severity("medium") == "3 - Medium"
    assert ado.map_severity("low") == "4 - Low"
    assert ado.map_severity("info") == "4 - Low"


def test_closed_states():
    assert ado.is_closed_state("Done")
    assert ado.is_closed_state("resolved")
    assert not ado.is_closed_state("Active")
    assert ado.is_closed_state("Removed", ["Removed"])


def test_description_html_escapes_and_lists_assets(db, monkeypatch):
    monkeypatch.setattr(ado.settings, "PUBLIC_APP_URL", "https://asm.example.com/")
    vuln = db.get(Vulnerability, 10)
    body = ado.build_description_html(vuln)
    assert 'href="https://asm.example.com/findings?id=10"' in body
    assert "<td>acme.com</td><td>www.acme.com</td>" in body
    assert "2 - High" in body
    assert "<h3>Proof</h3>" in body and "curl https://www.acme.com/admin" in body
    assert "<admin>" not in ado.build_description_html(
        Vulnerability(id=11, title="t", description="<admin>", severity=Severity.LOW)
    )


# ── client behaviour ─────────────────────────────────────────────────────────

def test_pat_auth_header_and_projects(db, fake):
    client = ado.AzureDevOpsClient.from_integration(db.get(AzureDevOpsIntegration, 1))
    result = asyncio.run(client.test_connection())
    assert result == {"ok": True, "message": "Connected — 1 project(s) visible.", "project_count": 1}
    auth = fake.calls[0][3]["authorization"]
    assert auth == "Basic " + base64.b64encode(b":secret-pat").decode()


def test_entra_token_is_fetched_once_and_used(fake):
    client = ado.AzureDevOpsClient(ORG, "entra_id", tenant_id="t1", client_id="c1", client_secret="s1")
    asyncio.run(client.list_projects())
    asyncio.run(client.list_projects())
    token_calls = [c for c in fake.calls if c[1].endswith("/token")]
    assert len(token_calls) == 1
    assert fake.calls[-1][3]["authorization"] == "Bearer entra-token"


def test_retries_on_429(db, fake):
    fake.throttle_once = True
    client = ado.AzureDevOpsClient.from_integration(db.get(AzureDevOpsIntegration, 1))
    assert asyncio.run(client.list_projects())[0]["name"] == "Security"
    assert len(fake.calls) == 2


def test_auth_failure_is_reported(db, monkeypatch):
    monkeypatch.setattr(ado, "_transport", httpx.MockTransport(lambda r: httpx.Response(401)))
    client = ado.AzureDevOpsClient.from_integration(db.get(AzureDevOpsIntegration, 1))
    result = asyncio.run(client.test_connection())
    assert result["ok"] is False and "authentication failed" in result["message"]


# ── create / sync flows ──────────────────────────────────────────────────────

def test_create_bug_sets_severity_repro_steps_and_tags(db, fake):
    integ = db.get(AzureDevOpsIntegration, 1)
    vuln = db.get(Vulnerability, 10)
    link = asyncio.run(ado.create_for_vulnerability(db, integ, vuln, "Security", "Bug"))
    assert link.work_item_id == 100 and link.state == "New" and link.project == "Security"
    fields = fake.items[100]["fields"]
    assert fields["System.Title"] == "Exposed <admin> panel"
    assert fields[ado.SEVERITY_FIELD] == "2 - High"
    assert fields[ado.REPRO_STEPS_FIELD] == fields["System.Description"]
    assert fields["System.Tags"] == "judah-security; asm-high"
    method, path, _, headers = [c for c in fake.calls if c[0] == "POST"][0]
    assert path == "/acme/Security/_apis/wit/workitems/$Bug"
    assert headers["content-type"] == "application/json-patch+json"


def test_create_retries_without_severity_for_types_lacking_it(db, fake):
    fake.reject_severity = True
    integ = db.get(AzureDevOpsIntegration, 1)
    link = asyncio.run(ado.create_for_vulnerability(db, integ, db.get(Vulnerability, 10), "Security", "Task"))
    assert ado.SEVERITY_FIELD not in fake.items[link.work_item_id]["fields"]


def test_pull_closes_finding_when_work_item_done(db, fake):
    integ = db.get(AzureDevOpsIntegration, 1)
    link = asyncio.run(ado.create_for_vulnerability(db, integ, db.get(Vulnerability, 10), "Security", "Bug"))
    fake.items[link.work_item_id]["fields"]["System.State"] = "Done"

    result = asyncio.run(ado.pull_integration(db, integ))
    assert result["ok"] and result["refreshed"] == 1 and result["closed_in_asm"] == 1
    vuln = db.get(Vulnerability, 10)
    assert vuln.status == VulnerabilityStatus.RESOLVED and vuln.resolved_at is not None
    assert db.get(AzureDevOpsWorkItem, link.id).state == "Done"

    # Second pull: already closed, nothing more to do.
    assert asyncio.run(ado.pull_integration(db, integ))["closed_in_asm"] == 0


def test_pull_respects_sync_disabled(db, fake):
    integ = db.get(AzureDevOpsIntegration, 1)
    integ.sync_enabled = False
    link = asyncio.run(ado.create_for_vulnerability(db, integ, db.get(Vulnerability, 10), "Security", "Bug"))
    fake.items[link.work_item_id]["fields"]["System.State"] = "Closed"
    asyncio.run(ado.pull_integration(db, integ))
    assert db.get(Vulnerability, 10).status == VulnerabilityStatus.OPEN


def test_status_change_comments_and_sets_close_state(db, fake):
    integ = db.get(AzureDevOpsIntegration, 1)
    integ.close_state = "Closed"
    link = asyncio.run(ado.create_for_vulnerability(db, integ, db.get(Vulnerability, 10), "Security", "Bug"))
    asyncio.run(ado.notify_status_change(integ, link, "open", "false_positive", "ana@acme.com"))
    comment = [c for c in fake.calls if c[1].endswith("/comments")][0]
    assert comment[1] == f"/acme/Security/_apis/wit/workItems/{link.work_item_id}/comments"
    assert "False Positive" in comment[2]["text"]
    assert fake.items[link.work_item_id]["fields"]["System.State"] == "Closed"


def test_severity_change_mentions_assignee(db, fake):
    integ = db.get(AzureDevOpsIntegration, 1)
    link = asyncio.run(ado.create_for_vulnerability(db, integ, db.get(Vulnerability, 10), "Security", "Bug"))
    fake.items[link.work_item_id]["fields"]["System.AssignedTo"] = {"id": "u-1", "displayName": "Dana Dev"}
    asyncio.run(ado.notify_severity_change(integ, link, "high", "critical"))
    text = [c for c in fake.calls if c[1].endswith("/comments")][0][2]["text"]
    assert 'data-vss-mention="version:2.0,u-1"' in text and "@Dana Dev" in text
    assert "HIGH" in text and "CRITICAL" in text and "1 - Critical" in text


def test_matching_auto_templates(db):
    integ = db.get(AzureDevOpsIntegration, 1)
    db.add_all([
        AzureDevOpsTemplate(integration_id=1, name="crit", project="Sec", work_item_type="Bug",
                            auto_create_enabled=True, auto_create_min_severity="high"),
        AzureDevOpsTemplate(integration_id=1, name="med", project="Backlog", work_item_type="Task",
                            auto_create_enabled=True, auto_create_min_severity="medium"),
        AzureDevOpsTemplate(integration_id=1, name="manual", project="X", work_item_type="Bug",
                            auto_create_enabled=False),
    ])
    db.commit()
    db.refresh(integ)
    assert {t.name for t in ado.matching_auto_templates(integ, "critical")} == {"crit", "med"}
    assert {t.name for t in ado.matching_auto_templates(integ, "medium")} == {"med"}
    assert ado.matching_auto_templates(integ, "low") == []
