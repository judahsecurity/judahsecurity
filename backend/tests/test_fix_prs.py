"""Fix PRs: verified-only, constrained patches, draft PR, evidence-gated closure."""

import asyncio
import base64
import json
import time
from datetime import datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest

from app.models.vulnerability import Severity, VulnerabilityStatus
from app.services.fix_pr_service import (
    FixError,
    apply_fix_verdict,
    candidate_paths,
    check_fix_evidence,
    is_eligible,
    open_fix_pr,
    parse_patch,
)
from app.services.github_client import GitHubClient, GitHubError, validate_repository

VULNERABLE = "def get(cur, item_id):\n    cur.execute(f'SELECT * FROM items WHERE id={item_id}')\n"
FIXED = "def get(cur, item_id):\n    cur.execute('SELECT * FROM items WHERE id=%s', (item_id,))\n"


def _vuln(**overrides):
    base = dict(id=9, title="SQL injection in /items", cwe_id="CWE-89",
                severity=Severity.HIGH, status=VulnerabilityStatus.OPEN,
                verification_level="exploit_verified", description="",
                affected_component="GET /items/{item_id}", steps_to_reproduce="",
                proof_of_concept="https://app.example.test/items/1", remediation="",
                metadata_={})
    base.update(overrides)
    return SimpleNamespace(**base)


def test_only_exploit_verified_open_findings_are_eligible():
    assert is_eligible(_vuln()) is None
    assert "exploit_verified" in is_eligible(_vuln(verification_level="source_verified"))
    assert "resolved" in is_eligible(_vuln(status=VulnerabilityStatus.RESOLVED))


def test_candidate_paths_prefer_explicit_then_linked_pr_check_files():
    assert candidate_paths(_vuln(), [], ["app/items.py"]) == ["app/items.py"]
    with pytest.raises(FixError):
        candidate_paths(_vuln(), [], ["../etc/passwd"])
    check = SimpleNamespace(
        findings=[{"file": "app/other.py", "cwe": "CWE-79"},
                  {"file": "app/items.py", "cwe": "CWE-89",
                   "route": {"method": "GET", "path": "/items/{item_id}"}}],
        routes=[])
    assert candidate_paths(_vuln(), [check])[0] == "app/items.py"


@pytest.mark.parametrize("path", [".github/workflows/ci.yml", "package.json", "requirements.txt",
                                  "Dockerfile", "app/new_module.py", ".env"])
def test_patch_rejects_paths_outside_the_contract(path):
    raw = json.dumps({"summary": "s", "files": [
        {"path": "app/items.py", "content": FIXED}, {"path": path, "content": "x"}]})
    with pytest.raises(FixError):
        parse_patch(raw, ["app/items.py"], {"app/items.py": VULNERABLE})


def test_patch_accepts_source_edit_plus_one_test_in_a_fence():
    raw = "```json\n" + json.dumps({"summary": "Parameterize", "test_plan": "pytest", "files": [
        {"path": "app/items.py", "content": FIXED},
        {"path": "tests/test_items_sqli.py", "content": "def test_x():\n    pass\n"}]}) + "\n```"
    patch = parse_patch(raw, ["app/items.py"], {"app/items.py": VULNERABLE})
    assert [f["path"] for f in patch.files] == ["app/items.py", "tests/test_items_sqli.py"]
    with pytest.raises(FixError):  # unchanged source = no fix
        parse_patch(json.dumps({"files": [{"path": "app/items.py", "content": VULNERABLE}]}),
                    ["app/items.py"], {"app/items.py": VULNERABLE})


def test_repository_names_are_validated():
    assert validate_repository("acme/app") == "acme/app"
    for bad in ("acme", "acme/app/../x", "https://github.com/acme/app", "acme/app?x=1"):
        with pytest.raises(GitHubError):
            validate_repository(bad)


class _FakeLLM:
    def __init__(self, content):
        self.content, self.messages = content, None

    async def ainvoke(self, messages):
        self.messages = messages
        return SimpleNamespace(content=self.content)


class _DB:
    def __init__(self):
        self.added, self.commits = [], 0

    def add(self, row):
        self.added.append(row)

    def commit(self):
        self.commits += 1


def _github_transport(calls):
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path, json.loads(request.content or b"{}")))
        assert request.headers["Authorization"] == "Bearer ghp_test"
        path = request.url.path
        if request.method == "GET" and path == "/repos/acme/app":
            return httpx.Response(200, json={"default_branch": "main"})
        if request.method == "GET" and path == "/repos/acme/app/contents/app/items.py":
            return httpx.Response(200, json={
                "type": "file", "encoding": "base64", "sha": "blob1",
                "content": base64.b64encode(VULNERABLE.encode()).decode()})
        if request.method == "GET" and path == "/repos/acme/app/git/ref/heads/main":
            return httpx.Response(200, json={"object": {"sha": "head1"}})
        if request.method == "POST" and path == "/repos/acme/app/git/refs":
            return httpx.Response(201, json={})
        if request.method == "PUT" and path.startswith("/repos/acme/app/contents/"):
            return httpx.Response(201, json={})
        if request.method == "POST" and path == "/repos/acme/app/pulls":
            return httpx.Response(201, json={"number": 77, "html_url": "https://github.com/acme/app/pull/77"})
        return httpx.Response(404, json={"message": "Not Found"})
    return httpx.MockTransport(handler)


def test_open_fix_pr_end_to_end_with_mocked_github():
    calls = []
    llm = _FakeLLM(json.dumps({"summary": "Use a bound parameter.", "test_plan": "Run pytest.",
                               "files": [{"path": "app/items.py", "content": FIXED}]}))
    vuln, db = _vuln(), _DB()

    async def run():
        async with GitHubClient("ghp_test", transport=_github_transport(calls)) as github:
            return await open_fix_pr(db=db, vulnerability=vuln, organization_id=3, user_id=1,
                                     repository="acme/app", llm=llm, github=github,
                                     file_paths=["app/items.py"])

    fix = asyncio.run(run())
    assert fix.pr_number == 77 and fix.status == "pr_open" and fix.files == ["app/items.py"]
    assert fix.branch.startswith("judah/fix-9-")
    assert vuln.status == VulnerabilityStatus.IN_PROGRESS
    assert vuln.metadata_["fix_requests"] == [fix.id] and db.commits == 1
    put = next(c for c in calls if c[0] == "PUT")
    assert base64.b64decode(put[2]["content"]).decode() == FIXED and put[2]["sha"] == "blob1"
    pull = next(c for c in calls if c[1].endswith("/pulls"))
    assert pull[2]["draft"] is True and pull[2]["base"] == "main"
    assert "<file path=\"app/items.py\">" in llm.messages[1].content


def test_unverified_finding_never_reaches_github():
    calls = []

    async def run():
        async with GitHubClient("ghp_test", transport=_github_transport(calls)) as github:
            await open_fix_pr(db=_DB(), vulnerability=_vuln(verification_level=None),
                              organization_id=3, user_id=1, repository="acme/app",
                              llm=_FakeLLM("{}"), github=github, file_paths=["app/items.py"])

    with pytest.raises(FixError):
        asyncio.run(run())
    assert calls == []


def test_fix_evidence_must_be_fresh_on_the_preview_and_a_proof_exchange():
    created = datetime.utcnow() - timedelta(minutes=5)
    now = time.time()
    records = {
        "good": {"kind": "scoped_numeric_sqli", "target": "https://pr-77.preview.test/items/1", "created_at": now},
        "prod": {"kind": "http_exchange", "target": "https://app.example.test/items/1", "created_at": now},
        "old": {"kind": "http_exchange", "target": "https://pr-77.preview.test/", "created_at": now - 3600},
        "talk": {"kind": "tool_output", "target": "https://pr-77.preview.test/", "created_at": now},
    }
    kwargs = dict(preview_origin="https://pr-77.preview.test", not_before=created)
    assert check_fix_evidence(records, ["good"], **kwargs) is None
    assert "preview" in check_fix_evidence(records, ["good", "prod"], **kwargs)
    assert "predates" in check_fix_evidence(records, ["old"], **kwargs)
    assert "proof exchange" in check_fix_evidence(records, ["talk"], **kwargs)
    assert "fresh" in check_fix_evidence(records, ["missing"], **kwargs)
    assert "fresh" in check_fix_evidence(records, ["good"], historical={"good"}, **kwargs)
    assert check_fix_evidence(records, [], **kwargs)


def test_verdict_updates_fix_and_finding_metadata():
    fix = SimpleNamespace(id="f" * 32, preview_origin="https://pr-77.preview.test",
                          status="pr_open", verification={})
    vuln = _vuln()
    apply_fix_verdict(fix, vuln, verdict="fixed", evidence_ids=["good"])
    assert fix.status == "verified_fixed"
    assert vuln.metadata_["fix_verification"]["verdict"] == "fixed"
    assert vuln.status == VulnerabilityStatus.OPEN  # production status is not changed here
    with pytest.raises(FixError):
        apply_fix_verdict(fix, vuln, verdict="probably", evidence_ids=["good"])


def test_record_fix_verification_tool_requires_preview_session(monkeypatch):
    from app.db import database
    from app.models.fix_request import FixRequest
    from app.services.agent import tools as tools_module
    from app.services.agent.evidence_store import evidence_store
    from app.services.agent.tools import ASMToolsManager

    fix = FixRequest(id="f" * 32, organization_id=3, vulnerability_id=9, repository="acme/app",
                     preview_origin="https://pr-77.preview.test", status="pr_open",
                     created_at=datetime.utcnow() - timedelta(minutes=1))
    vuln = _vuln()

    class Query:
        def __init__(self, row):
            self.row = row

        def filter(self, *_a):
            return self

        def first(self):
            return self.row

    class DB:
        commits = 0

        def query(self, model):
            return Query(fix if model.__name__ == "FixRequest" else vuln)

        def commit(self):
            DB.commits += 1

        def close(self):
            pass

    monkeypatch.setattr(database, "SessionLocal", DB)
    monkeypatch.setattr(tools_module, "get_tenant_context", lambda: (1, 3))
    manager = ASMToolsManager.__new__(ASMToolsManager)
    manager._engagement_brain = {"target": "https://app.example.test"}
    manager._capability_map = {"target": "https://app.example.test"}
    with pytest.raises(ValueError, match="preview origin"):
        asyncio.run(manager.verify_fix("f" * 32))

    manager._engagement_brain = {"target": "https://pr-77.preview.test"}
    manager._capability_map = {"target": "https://pr-77.preview.test"}
    plan = json.loads(asyncio.run(manager.verify_fix("f" * 32)))
    assert plan["finding"]["cwe"] == "CWE-89"
    evidence_id = evidence_store(manager).record(
        "http_exchange", {"request": {"method": "GET"}, "response": {"status": 200}},
        target="https://pr-77.preview.test/items/1")
    out = json.loads(asyncio.run(manager.record_fix_verification(
        "f" * 32, "fixed", [evidence_id])))
    assert out["recorded"] is True and fix.status == "verified_fixed" and DB.commits == 1
    out = json.loads(asyncio.run(manager.record_fix_verification("f" * 32, "fixed", ["nope"])))
    assert out["recorded"] is False
