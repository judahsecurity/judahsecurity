"""Parsed scanner summaries on MCP tool results, and their attack-graph facts."""

import os
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.core.config import settings
from app.services.agent.attack_graph import FACT_KINDS
from app.services.agent.engagement_brain import EngagementBrain, engagement_brain_from_dict
from app.services.agent.parser_facts import record_parser_facts, with_parsed_summary
from app.services.mcp.server import MCPServer

FIXTURES = Path(__file__).resolve().parents[1] / "packages" / "asm_scanner_core" / "tests" / "fixtures"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


@pytest.fixture
def server(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_CENSOR_ENABLED", False, raising=False)
    monkeypatch.setattr(settings, "AGENT_LICTOR_ENABLED", False, raising=False)
    srv = MCPServer()
    srv._tool_availability_cache = {name: True for name in srv._HANDLER_BINARY}
    return srv


def _stub(server, name, result):
    async def handler(**_kwargs):
        return dict(result)
    server.registry.get(name).handler = handler


@pytest.mark.asyncio
async def test_call_tool_attaches_parsed_summary_and_keeps_raw_output(server):
    raw = fixture("nikto.json")
    _stub(server, "execute_nikto", {"success": True, "output": raw, "error": None, "exit_code": 0})
    result = await server.call_tool("execute_nikto", {"args": "-h https://shop.example.test -Format json"})
    assert result["output"] == raw
    parsed = result["parsed"]
    assert parsed["tool"] == "nikto" and parsed["status"] == "ok"
    assert parsed["by_severity"]["high"] == 1
    assert "not findings" in parsed["note"]


@pytest.mark.asyncio
async def test_timed_out_xsstrike_is_partial(server):
    _stub(server, "execute_xsstrike", {
        "success": False, "output": fixture("xsstrike_partial.txt"),
        "error": "Command timed out after 300 seconds (process killed)",
        "exit_code": -1, "timed_out": True,
    })
    result = await server.call_tool("execute_xsstrike", {"args": "-u https://app.example.test/?name=x"})
    assert result["parsed"]["status"] == "partial"
    assert result["parsed"]["observations"][0]["target"] == "https://app.example.test/?name=x"


@pytest.mark.asyncio
async def test_wpscan_exit_5_parses_ok(server):
    _stub(server, "execute_wpscan", {"success": True, "output": fixture("wpscan.json"),
                                     "error": None, "exit_code": 5})
    result = await server.call_tool("execute_wpscan", {"args": "--url https://blog.example.test --format json"})
    assert result["parsed"]["status"] == "ok"
    assert result["parsed"]["counts"]["vulnerabilities"] == 2


@pytest.mark.asyncio
async def test_unparsed_tool_gets_no_summary(server):
    _stub(server, "execute_nmap", {"success": True, "output": "Nmap done", "error": None, "exit_code": 0})
    result = await server.call_tool("execute_nmap", {"args": "-p 80 scanme.example.test"})
    assert "parsed" not in result


def test_testssl_json_file_written_by_the_run_is_read(server, tmp_path):
    path = tmp_path / "out.json"
    path.write_text(fixture("testssl_flat.json"), encoding="utf-8")
    summary = server._parsed_scanner_summary(
        "execute_testssl", {"args": f"--jsonfile {path} https://tls.example.test"},
        {"success": True, "output": "Testing protocols ...", "exit_code": 0}, time.time() - 5,
    )
    assert summary["status"] == "ok" and summary["counts"]["critical"] == 1
    old = time.time() - 3600
    os.utime(path, (old, old))
    stale = server._parsed_scanner_summary(
        "execute_testssl", {"args": f"--jsonfile={path} https://tls.example.test"},
        {"success": True, "output": "Testing protocols ...", "exit_code": 0}, time.time() - 5,
    )
    assert stale["status"] == "inconclusive"  # a pre-existing file is never read


def test_truncated_output_is_never_ok(server):
    output = fixture("katana.jsonl") + "\n\n... (truncated, 9999999 bytes total)"
    summary = server._parsed_scanner_summary(
        "execute_katana", {"args": "-u https://app.example.test -jc -fx -json"},
        {"success": True, "output": output, "exit_code": 0}, time.time(),
    )
    assert summary["status"] == "partial"


def _manager(target="https://app.example.test", scope=("app.example.test",)):
    brain = EngagementBrain(target=target)
    return SimpleNamespace(_engagement_brain=brain.to_dict(), _fallback_target=target,
                           _assessment_scope=set(scope), _identity_registry=None)


def test_parser_observations_become_parser_facts_not_findings():
    assert "parser" in FACT_KINDS
    manager = _manager()
    parsed = {
        "tool": "katana", "status": "ok", "counts": {"observations": 2},
        "observations": [
            {"kind": "form", "title": "POST form -> /login", "severity": "info",
             "target": "https://app.example.test/login", "attributes": {"inputs": ["username"]}},
            {"kind": "form", "title": "POST form -> /x", "severity": "info",
             "target": "https://elsewhere.example.org/x"},
        ],
    }
    ids = record_parser_facts(manager, "execute_katana", parsed)
    brain = engagement_brain_from_dict(manager._engagement_brain)
    facts = [f for f in brain.facts if f["kind"] == "parser"]
    assert [f["id"] for f in facts] == ids and len(ids) == 1  # out-of-scope location skipped
    assert facts[0]["target"] == "https://app.example.test/login"
    assert facts[0]["data"]["planning_only"] is True
    assert facts[0]["parents"] == [next(f["id"] for f in brain.facts if f["kind"] == "origin")]
    assert not brain.candidates
    # Re-recording the same observation is idempotent.
    assert record_parser_facts(manager, "execute_katana", parsed) == ids


def test_with_parsed_summary_prefixes_text_and_records_facts():
    manager = _manager(target="https://shop.example.test", scope=("shop.example.test",))
    from asm_scanner_core.parsers import parse_tool_output

    parsed = parse_tool_output("nikto", fixture("nikto.json"), 0).to_dict()
    payload = with_parsed_summary(manager, "execute_nikto", {"parsed": parsed},
                                  {"success": True, "output": "RAW"})
    assert payload["output"].startswith("[parsed nikto] status=ok observations=5")
    assert payload["output"].endswith("\n\nRAW")
    assert payload["parsed"] is parsed
    assert len(payload["parser_fact_ids"]) == 5
    failed = with_parsed_summary(manager, "execute_nikto", {"parsed": parsed},
                                 {"success": False, "output": "Error: boom"}, prefix=False)
    assert failed["output"].startswith("Error: boom")


def test_without_engagement_target_no_facts_are_recorded():
    manager = SimpleNamespace(_engagement_brain={}, _fallback_target="")
    parsed = {"tool": "nikto", "status": "ok", "observations": [{"kind": "x", "title": "t"}]}
    assert record_parser_facts(manager, "execute_nikto", parsed) == []
    assert manager._engagement_brain == {}
