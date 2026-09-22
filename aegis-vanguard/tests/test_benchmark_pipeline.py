import inspect
import json
from types import SimpleNamespace

import run_pentest


def test_parallel_pipeline_receives_benchmark_proof_explicitly():
    signature = inspect.signature(run_pentest._run_parallel_pipeline)
    pipeline_source = inspect.getsource(run_pentest._run_parallel_pipeline)
    main_source = inspect.getsource(run_pentest.main)

    assert "benchmark_proof" in signature.parameters
    assert "args.benchmark_proof" not in pipeline_source
    assert "benchmark_proof=args.benchmark_proof" in main_source


def test_parallel_pipeline_completes_every_phase_in_benchmark_mode(monkeypatch):
    class FakeAgent:
        def __init__(self, name):
            self.name = name
            self.tool_names = ["janus_dast_full"]
            self.handoffs = ["legacy_report"]
            self.max_turns = 30

    class FakeRunner:
        def __init__(self):
            self.tasks = {}

        def execute_tool(self, agent, tool_name, arguments):
            if tool_name == "discover_input_surface":
                return json.dumps({
                    "success": True,
                    "forms_discovered": 1,
                    "eligible_parameters": 1,
                    "forms": [],
                })
            assert tool_name == "establish_identity_session"
            return json.dumps({
                "label": arguments["identity_label"],
                "state": "ready_unverified",
            })

        def run(self, agent, task, context):
            self.tasks[agent.name] = task
            final_text = f"{agent.name} complete"
            if agent.name == "validator_agent":
                import re
                ids = list(dict.fromkeys(re.findall(r'"finding_id":\s*"(F-[a-f0-9]+)"', task)))
                final_text = json.dumps({"decisions": [
                    {"finding_id": fid, "decision": "pass", "reason": "PoC"}
                    for fid in ids
                ]})
            return SimpleNamespace(
                final_text=final_text,
                turns_used=1,
                tool_calls_made=1,
                messages=[],
            )

    class FakePhaseResult:
        merged_findings = [
            {"title": "SQL Injection", "vuln_type": "sqli", "endpoint": "/send.php", "severity": "critical"},
            {"title": "SQL Injection duplicate", "vuln_type": "sqli", "endpoint": "/send.php", "severity": "critical"},
        ]
        finding_count = 2
        cross_validated_count = 1
        total_turns = 1
        total_tool_calls = 1
        total_elapsed_sec = 0.1
        serial_elapsed_sec = 0.1
        speedup = 1.0

        @staticmethod
        def summary():
            return {"findings_total": 2}

    class FakePhase:
        def __init__(self, runner, hunters):
            assert hunters

        def run(self, task, shared_ctx, recon_brief):
            return FakePhaseResult()

    class FakeBrain:
        def __init__(self):
            self.confirmed = []

        def to_context_summary(self):
            return "empty brain"

        def add_confirmed_vuln(self, **finding):
            self.confirmed.append(finding)

        def record_run_end(self, finding_count):
            self.finding_count = finding_count

        def save(self):
            pass

    agents = {
        "recon_agent": FakeAgent("recon_agent"),
        "exploit_agent": FakeAgent("exploit_agent"),
        "report_agent": FakeAgent("report_agent"),
    }
    runner = FakeRunner()
    brain = FakeBrain()

    monkeypatch.setattr(run_pentest, "create_app_mapper_agent", lambda: FakeAgent("app_mapper"))
    monkeypatch.setattr(run_pentest, "create_validator_agent", lambda: FakeAgent("validator_agent"))
    monkeypatch.setattr(run_pentest, "create_exploit_chain_agent", lambda: FakeAgent("chain_agent"))
    monkeypatch.setattr(
        run_pentest,
        "create_hunters_for_engagement",
        lambda **kwargs: [FakeAgent("injection_hunter")],
    )
    monkeypatch.setattr(
        run_pentest,
        "detect_surface_signals",
        lambda *args: {
            "api_framework": {"graphql": False},
            "enterprise": {"m365_entra": False},
        },
    )
    monkeypatch.setattr(run_pentest, "ParallelVulnPhase", FakePhase)

    result = run_pentest._run_parallel_pipeline(
        runner=runner,
        agents=agents,
        task="authorized local benchmark",
        target="http://localhost:8080",
        scope_domain="localhost:8080",
        hunter_turns=10,
        identities=[{
            "label": "benchmark-user",
            "username": "alice",
            "password": "private-benchmark-password",
            "role": "member",
            "tenant": "default",
            "headers": {},
            "login": {},
        }],
        brain=brain,
        benchmark_proof=True,
    )

    assert result.agent_name == "pipeline(parallel)"
    assert "synthetic" in runner.tasks["exploit_agent"]
    assert runner.tasks["report_agent"].startswith("Phase: REPORT")
    assert brain.finding_count == 2
    assert len(brain.confirmed) == 2
    assert "private-benchmark-password" not in str(result.context)
