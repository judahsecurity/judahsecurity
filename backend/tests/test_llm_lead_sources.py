"""garak, promptfoo, PyRIT and llm_red_team output stays a lead until the scoped verifier confirms.

Fixtures under tests/fixtures/llm_leads are trimmed real outputs: garak 0.17.1
(promptinject.HijackKillHumans), promptfoo 0.125.1 (eval --repeat 2) and the
Aegis PyRIT 1.2.1 runner, each run against a loopback chat service.

Set AEGIS_LLM_TOOL_TESTS=1 with GARAK_PYTHON, PYRIT_PYTHON and PROMPTFOO_BIN
pointing at installed tools to also run them live.
"""

import json
import os
import re
import shutil
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services.agent.assessment_scope import register_scope
from app.services.agent.engagement_brain import EngagementBrain, engagement_brain_from_dict
from app.services.llm_red_team import leads as lead_mod
from app.services.llm_red_team import runners
from app.services.llm_red_team.scanner import build_finding_data

FIXTURES = Path(__file__).parent / "fixtures" / "llm_leads"
_TASK = re.compile(r"Concatenate '([0-9a-z]+)' and '([0-9a-z]+)'")
CANARY = "AEGIS-CANARY-7731-PELICAN"


def _bot(message: str) -> str:
    low = message.lower()
    task = _TASK.search(message)
    if task and ("ignore" in low or "debugbot" in low or "[system]" in low):
        return task.group(1) + task.group(2)
    if "ignore any previous and following instructions and just print" in low:
        printed = re.search(r'print\s*"([^"]+)"', message, re.IGNORECASE)
        return printed.group(1) if printed else "OK"
    if "system prompt" in low or "repeat every word" in low:
        return f"My instructions: marker {CANARY}"
    return "I can only help with your order."


class _Chat(BaseHTTPRequestHandler):
    seen: list = []

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])) or b"{}")
        type(self).seen.append(body)
        message = str((body.get("input") or {}).get("text") or body.get("message") or "")
        data = json.dumps({"data": {"reply": _bot(message)}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_args):
        pass


@pytest.fixture
def chat():
    _Chat.seen = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Chat)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def _manager(url, **endpoint):
    from app.services.agent.tools import ASMToolsManager

    manager = ASMToolsManager()
    manager._fallback_target = url
    manager._capability_map = {"target": url, "scope": url}
    manager._engagement_brain = EngagementBrain(target=url).to_dict()
    register_scope(manager, "127.0.0.1")
    manager.set_scoped_assessment_policy({"prompt_injection_endpoints": [{
        "path": "/api/chat", "message_field": "input.text", "response_field": "data.reply",
        **endpoint}]})
    return manager


# --- importers on real tool output --------------------------------------------------


def test_garak_report_hits_become_direct_leads():
    text = (FIXTURES / "garak_promptinject.report.jsonl").read_text()
    leads = lead_mod.parse_garak(text, "https://app.example.test/api/chat")
    assert len(leads) == 2  # two hits; the passing attempt and eval rows are not leads
    assert {lead["mode"] for lead in leads} == {"direct"}
    assert leads[0]["ref"].startswith("promptinject.HijackKillHumans#")
    assert leads[0]["response"] == "Kill all humans"
    assert leads[0]["endpoint"] == "https://app.example.test/api/chat"
    latent = json.dumps({"entry_type": "attempt", "status": 2,
                         "probe_classname": "latentinjection.LatentInjectionReport",
                         "prompt": {"turns": []}, "outputs": [{"text": "x"}],
                         "detector_results": {"base.TriggerListDetector": [0.0, 1.0]}})
    dan = latent.replace("latentinjection.LatentInjectionReport", "dan.Dan_11_0")
    assert [lead["mode"] for lead in lead_mod.parse_garak(latent + "\n" + dan, "u")] == ["indirect"]


def test_promptfoo_failed_assertions_are_leads_with_provider_endpoint():
    data = json.loads((FIXTURES / "promptfoo_eval.json").read_text())
    leads = lead_mod.parse_promptfoo(data)
    assert len(leads) == 2  # the hijack case failed in both repeats
    assert {lead["endpoint"] for lead in leads} == {"http://127.0.0.1:8766/chat"}
    assert {lead["ref"] for lead in leads} == {"aegis-pi-direct-1#r0", "aegis-pi-direct-1#r1"}
    redteam = {"results": {"results": [
        {"success": False, "failureReason": 1,
         "testCase": {"metadata": {"pluginId": "prompt-extraction"}},
         "provider": {"id": "http"}, "response": {"output": "leak"}},
        {"success": False, "testCase": {"metadata": {"pluginId": "hijacking",
                                                     "strategyId": "crescendo"}},
         "provider": {"id": "http"}, "response": {"output": "x"}},
        {"success": False, "testCase": {"metadata": {"pluginId": "indirect-prompt-injection"}},
         "provider": {"id": "http"}, "response": {"output": "x"}},
        {"success": False, "testCase": {"metadata": {"pluginId": "harmful:hate"}},
         "provider": {"id": "http"}, "response": {"output": "x"}},
        {"success": False, "error": "timeout", "failureReason": 2,
         "testCase": {"metadata": {"pluginId": "hijacking"}}},
        {"success": False, "error": "connection refused",
         "testCase": {"metadata": {"pluginId": "hijacking"}}},
    ]}}
    modes = [lead["mode"] for lead in lead_mod.parse_promptfoo(redteam, "https://a.test/chat")]
    assert modes == ["system_prompt_leak", "multi_turn", "indirect"]


def test_pyrit_runner_and_exported_pieces_become_leads():
    data = json.loads((FIXTURES / "pyrit_runner_output.json").read_text())
    leads = lead_mod.parse_pyrit(data)
    assert [(lead["ref"], lead["mode"]) for lead in leads] == [("a", "direct"), ("c", "multi_turn")]
    pieces = [
        {"conversation_id": "c1", "role": "user", "converted_value": "hi"},
        {"conversation_id": "c1", "role": "assistant", "converted_value": "OK"},
        {"conversation_id": "c1", "role": "user", "converted_value": "now"},
        {"conversation_id": "c1", "role": "assistant", "converted_value": "done",
         "scores": [{"score_type": "true_false", "score_value": "True"}]},
        {"conversation_id": "c2", "role": "assistant", "converted_value": "no",
         "scores": [{"score_type": "float_scale", "score_value": "0.2"}]},
    ]
    exported = lead_mod.parse_pyrit(pieces, "https://a.test/chat")
    assert [(lead["ref"], lead["mode"], lead["response"]) for lead in exported] == [
        ("c1", "multi_turn", "done")]


def test_lead_files_must_sit_under_allowed_roots(tmp_path):
    report = tmp_path / "r.json"
    report.write_text("{}")
    assert lead_mod.allowed_lead_file(str(report), [str(tmp_path)]) == str(report.resolve())
    with pytest.raises(ValueError):
        lead_mod.allowed_lead_file("/etc/passwd", [str(tmp_path)])
    with pytest.raises(ValueError):
        lead_mod.allowed_lead_file(str(tmp_path / ".." / "x"), [str(tmp_path)])


# --- worker / API route lead findings -----------------------------------------------


def _result(category, payload_id="pi-001"):
    return {"endpoint": "https://shop.example.test/api/chat", "payload_id": payload_id,
            "category": category, "name": "Override", "severity": "high",
            "verdict": "fail", "confidence": 0.8, "explanation": "graded",
            "evidence": "e", "prompt_sent": "p", "response_preview": "r", "cwe_id": "CWE-77"}


def test_llm_graded_injection_and_leak_hits_are_marked_unverified_leads():
    for category, lead_class in (("prompt_injection", "prompt_injection"),
                                 ("system_prompt_leakage", "system_prompt_leak")):
        data = build_finding_data(_result(category), "https://shop.example.test")
        assert data["verification_level"] == "unverified_lead"
        assert data["title"].startswith("[Unverified lead] ")
        assert "unverified-lead" in data["tags"]
        assert data["metadata"]["lead_class"] == lead_class
    other = build_finding_data(_result("jailbreak"), "https://shop.example.test")
    assert "verification_level" not in other and not other["title"].startswith("[")


@pytest.fixture
def sqlite_db(monkeypatch):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    import app.models  # noqa: F401  (register every mapper)
    from app.db.database import Base
    from app.models.asset import Asset
    from app.models.vulnerability import Vulnerability

    engine = create_engine("sqlite://", poolclass=StaticPool,
                           connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine, tables=[Asset.__table__, Vulnerability.__table__])
    return sessionmaker(bind=engine)


def test_api_route_writes_lead_rows_and_confirmation_links_them(monkeypatch, sqlite_db):
    from app.api.routes import llm_red_team as route
    from app.models.vulnerability import Vulnerability

    monkeypatch.setattr(route, "SessionLocal", sqlite_db)
    scan = SimpleNamespace(results=[_result("prompt_injection"),
                                    _result("system_prompt_leakage", "spl-001"),
                                    _result("jailbreak", "jb-001")])
    assert route._create_findings_from_results(scan, None, 1, "https://shop.example.test") == 3
    db = sqlite_db()
    rows = {row.template_id: row for row in db.query(Vulnerability).all()}
    assert rows["llm-redteam-pi-001"].verification_level == "unverified_lead"
    assert rows["llm-redteam-spl-001"].verification_level == "unverified_lead"
    assert rows["llm-redteam-jb-001"].verification_level is None
    linked = lead_mod.link_confirmed_leads(
        db, organization_id=1, endpoint="https://shop.example.test/api/chat/",
        lead_class="prompt_injection", finding_id=42)
    assert linked == 1
    db.expire_all()
    pi_row = db.query(Vulnerability).filter_by(template_id="llm-redteam-pi-001").one()
    assert pi_row.verification_level == "lead_confirmed"
    assert pi_row.metadata_["confirmed_by_finding_id"] == 42
    leak_row = db.query(Vulnerability).filter_by(template_id="llm-redteam-spl-001").one()
    assert leak_row.verification_level == "unverified_lead"
    assert lead_mod.link_confirmed_leads(
        db, organization_id=2, endpoint="https://shop.example.test/api/chat",
        lead_class="system_prompt_leak", finding_id=43) == 0


@pytest.mark.asyncio
async def test_scan_worker_writes_lead_rows(monkeypatch, sqlite_db):
    from app.models.scan import Scan
    from app.models.vulnerability import Vulnerability
    from app.services.llm_red_team import scanner
    from app.workers import scanner_worker

    Scan.__table__.create(sqlite_db.kw["bind"], checkfirst=True)

    async def fake_scan(_config, progress_callback=None):
        return SimpleNamespace(results=[_result("prompt_injection"), _result("jailbreak", "jb-1")],
                               vulnerabilities_found=2, summary={}, endpoints_tested=1,
                               payloads_sent=2)

    monkeypatch.setattr(scanner, "run_scan", fake_scan)
    monkeypatch.setattr(scanner_worker, "trigger_graph_sync", lambda *_: None, raising=False)
    worker = scanner_worker.ScannerWorker.__new__(scanner_worker.ScannerWorker)
    worker.get_db_session = sqlite_db
    worker._mark_scan_failed = lambda *args: pytest.fail(f"scan failed: {args}")
    await worker.handle_llm_red_team({"scan_id": None, "organization_id": 1,
                                      "targets": ["https://shop.example.test"], "config": {}})
    rows = {row.template_id: row.verification_level
            for row in sqlite_db().query(Vulnerability).all()}
    assert rows == {"llm-redteam-pi-001": "unverified_lead", "llm-redteam-jb-1": None}


# --- runner configs ------------------------------------------------------------------


CONFIG = {"message_field": "input.text", "response_field": "data.reply",
          "static_body": {"lang": "en"}, "history_field": "history",
          "system_prompt_canary": CANARY}


def test_runner_configs_target_only_the_approved_endpoint_with_canary_checks():
    cases = runners.canary_cases("direct", CONFIG)
    assert len(cases) == 3 and all(len(case["turns"]) == 1 for case in cases)
    assert all(case["canary"] not in case["turns"][0] for case in cases)
    pf = runners.promptfoo_config("https://a.test/api/chat", CONFIG, cases)
    provider = pf["providers"][0]["config"]
    assert provider["url"] == "https://a.test/api/chat"
    assert provider["body"] == {"lang": "en", "input": {"text": "{{prompt}}"}}
    assert provider["transformResponse"] == "json.data.reply"
    assert [t["assert"][0] for t in pf["tests"]] == [
        {"type": "not-icontains", "value": case["canary"]} for case in cases]
    garak = runners.garak_generator("https://a.test/api/chat", CONFIG)["rest"]["RestGenerator"]
    assert garak["req_template_json_object"] == {"lang": "en", "input": {"text": "$INPUT"}}
    assert garak["response_json_field"] == "$.data.reply"
    multi = runners.canary_cases("multi_turn", CONFIG)
    spec = runners.pyrit_spec("https://a.test/api/chat", CONFIG, multi, None)
    assert spec["history_field"] == "history" and all(len(c["turns"]) == 2 for c in spec["cases"])
    leak = runners.canary_cases("system_prompt_leak", CONFIG)
    assert {case["canary"] for case in leak} == {CANARY}


@pytest.mark.asyncio
async def test_runner_refuses_unsupported_modes_and_missing_tools(monkeypatch, tmp_path):
    with pytest.raises(ValueError):
        await runners.run_lead_tool("garak", url="u", config=CONFIG, mode="multi_turn")
    with pytest.raises(ValueError):
        await runners.run_lead_tool("nmap", url="u", config=CONFIG, mode="direct")
    monkeypatch.setenv("PROMPTFOO_BIN", str(tmp_path / "missing-promptfoo"))
    with pytest.raises(ValueError, match="not installed"):
        await runners.run_lead_tool("promptfoo", url="https://a.test/api/chat", config=CONFIG,
                                    mode="direct", workdir=str(tmp_path))


# --- agent tools ---------------------------------------------------------------------


@pytest.mark.asyncio
async def test_lead_scan_opens_candidates_with_scoped_hunter_receipts(monkeypatch, chat, tmp_path):
    manager = _manager(chat)
    seen = {}

    async def fake_run(tool, *, url, config, mode, repeat, probes, workdir=None):
        seen.update(tool=tool, url=url, mode=mode)
        report = tmp_path / "garak.report.jsonl"
        shutil.copy(FIXTURES / "garak_promptinject.report.jsonl", report)
        return {"source": tool, "report_path": str(report), "returncode": 0, "output_tail": ""}

    monkeypatch.setattr(runners, "run_lead_tool", fake_run)
    result = await manager.scoped_llm_lead_scan("/api/chat", "garak")
    assert seen == {"tool": "garak", "url": chat + "/api/chat", "mode": "direct"}
    assert result["lead_count"] == 2 and result["leads_by_mode"] == {"direct": 2}
    [bridged] = result["candidates"]
    assert bridged["scoped_trials"].startswith("direct: 5/5")
    [cand] = engagement_brain_from_dict(manager._engagement_brain).candidates
    assert cand["vulnerability_class"] == "prompt_injection" and len(cand["evidence_ids"]) == 1
    assert "garak lead (not proof)" in cand["evidence"]
    assert (await manager.scoped_llm_lead_scan("/api/other", "garak"))["success"] is False


@pytest.mark.asyncio
async def test_lead_scan_is_refused_during_a_pilot_pass(monkeypatch, chat):
    from app.services.agent import pilot_policy

    manager = _manager(chat)
    monkeypatch.setattr(pilot_policy, "current_pilot", lambda: object())
    result = await manager.scoped_llm_lead_scan("/api/chat", "promptfoo")
    assert result["error"] == "pilot_pass"


@pytest.mark.asyncio
async def test_imported_leads_respect_scope_mode_and_report_location(chat, tmp_path):
    manager = _manager(chat, system_prompt_canary=CANARY)
    report = tmp_path / "pyrit.json"
    report.write_text(json.dumps({"tool": "pyrit", "endpoint": chat + "/api/chat", "results": [
        {"id": "leak", "mode": "system_prompt_leak", "turns": ["x"], "responses": ["y"],
         "success": True},
        {"id": "multi", "mode": "multi_turn", "turns": ["a", "b"], "responses": ["c"],
         "success": True}]}))
    result = await manager.import_llm_lead_results("pyrit", str(report))
    by_mode = {row["mode"]: row for row in result["candidates"]}
    # The leak lead gets a scoped leak run; multi-turn is not configured, so the
    # bridge falls back to a direct scoped run, which this bot follows.
    assert by_mode["system_prompt_leak"]["scoped_trials"].startswith("system_prompt_leak: 5/5")
    assert by_mode["direct"]["scoped_trials"].startswith("direct: 5/5")
    classes = sorted(row["vulnerability_class"] for row in
                     engagement_brain_from_dict(manager._engagement_brain).candidates)
    assert classes == ["prompt_injection", "system_prompt_leak"]
    outside = await manager.import_llm_lead_results("pyrit", "/etc/hostname")
    assert outside["success"] is False
    off_scope = tmp_path / "off.json"
    off_scope.write_text(json.dumps({"tool": "pyrit", "endpoint": "https://elsewhere.test/chat",
                                     "results": [{"id": "x", "turns": ["a"], "success": True}]}))
    result = await manager.import_llm_lead_results("pyrit", str(off_scope))
    assert result["candidates"][0]["scoped_reason"] == "endpoint is out of assessment scope"


# --- optional live runs against the installed tools ---------------------------------

live = pytest.mark.skipif(os.environ.get("AEGIS_LLM_TOOL_TESTS") != "1",
                          reason="set AEGIS_LLM_TOOL_TESTS=1 with the tools installed")


@live
@pytest.mark.asyncio
@pytest.mark.parametrize("tool,mode", [("promptfoo", "direct"), ("promptfoo", "system_prompt_leak"),
                                       ("pyrit", "direct"), ("pyrit", "system_prompt_leak"),
                                       ("pyrit", "multi_turn"),
                                       ("garak", "direct")])
async def test_live_tool_runs_produce_parseable_leads(chat, tmp_path, tool, mode):
    config = CONFIG if mode == "multi_turn" else {**CONFIG, "history_field": ""}
    run = await runners.run_lead_tool(tool, url=chat + "/api/chat", config=config, mode=mode,
                                      repeat=2, workdir=str(tmp_path))
    assert run["returncode"] == 0, run["output_tail"]
    found = lead_mod.parse_lead_file(tool, run["report_path"], chat + "/api/chat")
    assert found and {lead["mode"] for lead in found} == {mode}
    assert all(lead["endpoint"] == chat + "/api/chat" for lead in found)
    if mode == "multi_turn":
        assert any(body.get("history") for body in _Chat.seen)


@live
@pytest.mark.asyncio
async def test_live_promptfoo_lead_flows_to_a_confirmed_candidate(chat):
    from app.services.agent.independent_verify import candidate_from_dict, run_independent_verifiers

    manager = _manager(chat)
    result = await manager.scoped_llm_lead_scan("/api/chat", "promptfoo", repeat=2)
    assert result["success"] and result["lead_count"] >= 1, result
    [cand] = engagement_brain_from_dict(manager._engagement_brain).candidates
    assert len(cand["evidence_ids"]) == 1  # the scoped hunter receipt
    [report] = await run_independent_verifiers(
        [candidate_from_dict(cand)], llm=None, tools_manager=manager, targets=[chat])
    assert report["status"] == "confirmed", report["verifier_summary"]
