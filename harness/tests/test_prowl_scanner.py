import asyncio
import json
from types import SimpleNamespace

import pytest
from local_harness import prowl_scanner
from local_harness.product_agent import assess, benchmark_flag_diagnostics


@pytest.fixture
def tenant(monkeypatch):
    monkeypatch.setenv("AEGIS_PROWL_ORG_ID", "7")
    monkeypatch.setenv("AEGIS_PROWL_USER_ID", "9")
    monkeypatch.setenv("AEGIS_PROWL_LOOPBACK_ALIAS", "172.17.0.1")


def test_requires_assessment_tenant(monkeypatch):
    monkeypatch.delenv("AEGIS_PROWL_ORG_ID", raising=False)
    monkeypatch.delenv("AEGIS_PROWL_USER_ID", raising=False)
    with pytest.raises(SystemExit, match="AEGIS_PROWL_ORG_ID"):
        prowl_scanner.build_args(["--target", "https://app.test"])


def test_loopback_target_and_scope_move_to_a_reachable_alias(tenant, monkeypatch):
    monkeypatch.setenv("AEGIS_PROWL_MODE", "deep")
    monkeypatch.setenv("AEGIS_PROWL_MAX_ITERATIONS", "120")
    args = prowl_scanner.build_args([
        "--target", "http://localhost:52490/", "--scope", "localhost:52490",
        "--benchmark-proof", "--fast",
    ])
    assert args.target == "http://172.17.0.1:52490/"
    assert args.scope == "172.17.0.1:52490"
    assert args.benchmark_proof is True
    assert args.assessment_mode == "deep"
    assert args.max_iterations == 120
    assert (args.organization_id, args.user_id) == (7, 9)


def test_external_targets_and_lookalike_hosts_are_unchanged(tenant):
    args = prowl_scanner.build_args([
        "--target", "https://mylocalhost.example/", "--scope", "mylocalhost.example",
    ])
    assert args.target == "https://mylocalhost.example/"
    assert args.scope == "mylocalhost.example"


def test_loopback_alias_is_never_loopback(monkeypatch):
    monkeypatch.setenv("AEGIS_PROWL_LOOPBACK_ALIAS", "127.0.0.1")
    monkeypatch.setattr(prowl_scanner, "_docker_bridge_address", lambda: "")
    monkeypatch.setattr(prowl_scanner, "_primary_address", lambda: "10.0.0.5")
    assert prowl_scanner.loopback_alias() == "10.0.0.5"
    monkeypatch.setattr(prowl_scanner, "_primary_address", lambda: "")
    with pytest.raises(SystemExit):
        prowl_scanner.loopback_alias()


def test_budget_stop_is_a_valid_result_but_a_missing_summary_is_not(tmp_path):
    assert prowl_scanner.scanner_exit_code(tmp_path) == 1
    (tmp_path / "product_assessment.json").write_text(json.dumps({"complete": False}))
    assert prowl_scanner.scanner_exit_code(tmp_path) == 0
    (tmp_path / "product_assessment.json").write_text(
        json.dumps({"ledger_export_error": "RuntimeError: no ledger"}))
    assert prowl_scanner.scanner_exit_code(tmp_path) == 1


def test_main_accepts_the_runner_precreated_empty_sink(tenant, monkeypatch, tmp_path):
    sink = tmp_path / "findings.jsonl"
    sink.touch()
    monkeypatch.setenv("AEGIS_FINDINGS_SINK", str(sink))
    seen = {}

    async def fake_assess(args):
        seen["exists"] = sink.exists()
        sink.touch(exist_ok=False)
        (tmp_path / "product_assessment.json").write_text(json.dumps({"complete": True}))
        return 0

    monkeypatch.setattr("local_harness.product_agent.assess", fake_assess)
    assert prowl_scanner.main(["--target", "https://app.test"]) == 0
    assert seen["exists"] is False


def test_benchmark_proof_prompt_and_flag_diagnostics(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_FINDINGS_SINK", str(tmp_path / "findings.jsonl"))
    calls = []

    async def invoke(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(task_complete=True, error=None,
                               awaiting_question=False, awaiting_approval=False)

    from app.services.agent.evidence_store import evidence_store

    manager = SimpleNamespace()
    store = evidence_store(manager)
    store.record("http_exchange", {"body": "ok FLAG{seen-and-published}"}, target="https://app.test")
    store.record("http_exchange", {"body": "FLAG{seen-only}"}, target="https://app.test")
    args = SimpleNamespace(
        target="https://app.test", scope="app.test", user_id=1, organization_id=2,
        identities=None, max_turns=1, max_iterations=4, price_limit_usd=1.0,
        benchmark_proof=True,
    )

    async def run():
        result = await assess(args, SimpleNamespace(tool_manager=manager, invoke=invoke))
        (tmp_path / "findings.jsonl").write_text(
            json.dumps({"raw_data": {"poc": {"response_snippet": "FLAG{seen-and-published}"}}}) + "\n")
        return result

    asyncio.run(run())
    assert "FLAG{...}" in calls[0]["question"]
    flags = benchmark_flag_diagnostics(manager, tmp_path / "findings.jsonl")
    assert flags == {"observed_in_evidence": 2, "published": 1, "observed_not_published": 1}
    summary = json.loads((tmp_path / "product_assessment.json").read_text())
    assert summary["benchmark_flags"]["observed_in_evidence"] == 2
    assert "FLAG{" not in json.dumps(summary)
