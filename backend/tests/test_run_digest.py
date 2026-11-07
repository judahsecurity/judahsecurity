import asyncio
import json
from types import SimpleNamespace

from app.services.agent import fireteam_service
from app.services.agent.evidence_store import EvidenceStore
from app.services.agent.run_digest import (
    RunDigest,
    current_specialist,
    record_specialist_outcome,
    record_tool_attempt,
    run_digest,
    target_from_args,
)
from app.services.agent.tools import ASMToolsManager


def _manager():
    return SimpleNamespace(_evidence_store=EvidenceStore(), _engagement_brain=None)


def test_target_drops_query_strings():
    assert target_from_args({"url": "https://app.example.com/api/orders?id=1&token=x"}) == \
        "https://app.example.com/api/orders"
    assert target_from_args({"host": "app.example.com"}) == "https://app.example.com/"
    assert target_from_args({"cmd": "ls"}) == ""


def test_attempts_outside_a_specialist_are_not_recorded():
    manager = _manager()
    record_tool_attempt(manager, "execute_curl", {"url": "https://a.example.com/"}, success=True)
    assert len(run_digest(manager)) == 0


def test_http_attempt_line_and_redaction():
    manager = _manager()
    eid = manager._evidence_store.record("http_exchange", {
        "request": {"method": "GET", "url": "https://app.example.com/api/orders/7?sig=abc", "identity": "alice"},
        "response": {"status": 403, "length": 12, "body": "denied"},
    }, target="https://app.example.com/")
    token = current_specialist.set("authz")
    try:
        record_tool_attempt(manager, "http_request", {"url": "https://app.example.com/api/orders/7",
                                                     "hypothesis_id": "h1"},
                            success=True, evidence_ids=[eid])
        record_tool_attempt(manager, "execute_curl",
                            {"url": "https://app.example.com/", "headers": "Authorization: Bearer s3cr3t"},
                            success=False, error="Authorization: Bearer s3cr3t rejected")
        record_tool_attempt(manager, "read_evidence", {"evidence_id": eid}, success=True)
    finally:
        current_specialist.reset(token)
    entries = run_digest(manager).search()
    assert len(entries) == 2  # read-only tools are not logged
    failed, http = entries
    assert http["summary"] == "GET https://app.example.com/api/orders/7 -> 403 (12 B, alice)"
    assert http["hypothesis_ids"] == ["h1"] and http["evidence_ids"] == [eid]
    assert "sig=abc" not in json.dumps(entries)
    assert "s3cr3t" not in failed["summary"]


def test_search_filters_and_excludes_own_lines():
    digest = RunDigest()
    digest.add(kind="tried", specialist="xss", summary="GET /search -> 200", target="https://a.example.com/search")
    digest.add(kind="outcome", specialist="sqli", summary="no injection in id", verdict="killed")
    digest.add(kind="tried", specialist="sqli", summary="GET /orders -> 500")
    assert [e["specialist"] for e in digest.search(exclude_specialist="sqli")] == ["xss"]
    assert [e["kind"] for e in digest.search(kind="outcome")] == ["outcome"]
    assert [e["summary"] for e in digest.search(query="orders")] == ["GET /orders -> 500"]
    assert digest.search()[0]["seq"] == 3  # newest first


def test_digest_is_bounded():
    digest = RunDigest(max_entries=5)
    for i in range(12):
        digest.add(kind="tried", specialist="x", summary=str(i))
    assert len(digest) == 5
    assert digest.search(limit=10)[-1]["summary"] == "7"


def test_outcome_line_uses_key_findings_only():
    manager = _manager()
    report = SimpleNamespace(
        specialist="authz", verdict="proven", hypothesis_ids=["h1"], error=None,
        key_findings=["IDOR on /api/orders/{id}", "tenant id not checked", "third", "fourth"],
        evidence="", tool_calls=[SimpleNamespace(evidence_ids=["e1"]), SimpleNamespace(evidence_ids=[])],
        summary="long narrative that should not be shared " * 20,
    )
    record_specialist_outcome(manager, report, ["https://app.example.com"])
    (entry,) = run_digest(manager).search()
    assert entry["verdict"] == "proven"
    assert entry["summary"] == "IDOR on /api/orders/{id}; tenant id not checked; third"
    assert entry["evidence_ids"] == ["e1"]


def test_parallel_specialists_see_only_siblings():
    manager = _manager()

    async def specialist(name, url):
        current_specialist.set(name)  # task-local, as in fireteam._run_specialist
        record_tool_attempt(manager, "execute_curl", {"url": url}, success=True)
        await asyncio.sleep(0)
        return json.loads(await ASMToolsManager.search_run_digest(manager))["entries"]

    async def main():
        return await asyncio.gather(
            asyncio.create_task(specialist("xss", "https://a.example.com/search")),
            asyncio.create_task(specialist("sqli", "https://a.example.com/orders")),
        )

    xss_view, sqli_view = asyncio.run(main())
    assert [e["specialist"] for e in xss_view] == ["sqli"]
    assert [e["specialist"] for e in sqli_view] == ["xss"]
    assert current_specialist.get() == ""


def test_safe_invoke_records_specialist_attempts():
    class Tools:
        _evidence_store = EvidenceStore()

        async def execute(self, name, args):
            return {"success": True, "output": "ok"}

    tools = Tools()

    async def run():
        current_specialist.set("ssrf")
        return await fireteam_service._safe_invoke(tools, "execute_curl", {"url": "https://a.example.com/x"})

    invocation = asyncio.run(run())
    assert invocation.success
    (entry,) = run_digest(tools).search()
    assert (entry["specialist"], entry["tool"], entry["target"]) == ("ssrf", "execute_curl", "https://a.example.com/x")


def test_tool_includes_recon_observations():
    manager = _manager()
    manager._engagement_brain = {"recon_observations": [
        {"id": "o1", "kind": "api_endpoint", "target": "https://app.example.com/api/v2/users", "value": "/api/v2/users",
         "source": "js"},
    ]}
    out = json.loads(asyncio.run(ASMToolsManager.search_run_digest(manager, query="users")))
    assert out["observations"][0]["observation_kind"] == "api_endpoint"
    assert out["entries"] == []
    assert "Not evidence" in out["note"]

