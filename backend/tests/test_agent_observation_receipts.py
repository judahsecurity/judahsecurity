import pytest

from app.services.agent.fireteam_service import (
    SpecialistReport,
    ToolInvocation,
    _merge_reports,
    _safe_invoke,
)
from app.services.agent.observation_pack import project_observation


def test_long_observation_keeps_head_tail_and_exact_recall_handle():
    artifact = "b" * 32
    output = "HEAD" + ("m" * 9000) + "TAIL"
    shown = project_observation(output, artifact_id=artifact, max_chars=600)
    assert len(shown) <= 600
    assert shown.startswith("HEAD")
    assert shown.endswith("TAIL")
    assert "read_evidence(evidence_id='" + artifact in shown
    assert project_observation(output, artifact_id="", max_chars=600) == output[:600]


def test_fireteam_debrief_distinguishes_receipts_from_analyst_claims():
    artifact = "c" * 32
    receipt = "d" * 32
    report = SpecialistReport(
        specialist="xss", role="XSS", mission="Check search input",
        summary="Search is exploitable", key_findings=["Claimed XSS"],
        verdict="proven", hypothesis_results=[
            {"hypothesis_id": "search-xss", "verdict": "killed",
             "evidence_ids": [receipt], "evidence": "Canary did not execute"},
        ],
        tool_calls=[ToolInvocation(
            tool="compare_requests", args={"hypothesis_id": "search-xss"},
            success=True, summary="No execution", evidence_ids=[receipt],
            artifact_id=artifact,
        )],
    )
    debrief = _merge_reports("Check search input", [report])
    assert "receipt: compare_requests completed" in debrief
    assert artifact in debrief and receipt in debrief
    assert "grounded hypothesis: search-xss killed" in debrief
    assert "analyst note (unverified): Search is exploitable" in debrief

    report.hypothesis_results[0]["evidence_ids"] = ["invented"]
    assert "grounded hypothesis" not in _merge_reports("Check search input", [report])


@pytest.mark.asyncio
async def test_specialist_tool_feedback_projects_only_when_artifact_is_saved():
    class Manager:
        async def execute(self, _tool, _args):
            return {"success": True, "output": "HEAD" + "x" * 9000 + "TAIL",
                    "artifact_id": "e" * 32}

    invocation = await _safe_invoke(Manager(), "bounded_probe", {})
    assert invocation.artifact_id == "e" * 32
    assert len(invocation.summary) < 6000
    assert "HEAD" in invocation.summary and "TAIL" in invocation.summary
    assert "read_evidence(evidence_id='" in invocation.summary
