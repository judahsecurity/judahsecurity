"""The first-pass queue must reach each observed input without replay loops."""

import asyncio
import json
from types import SimpleNamespace

import pytest

from app.services.agent.assessment_scope import prepare_browser_scope
from app.services.agent.coverage_cells import (
    claim_coverage_cell_leases, parameter_test_funnel,
    seed_parameter_coverage_cells,
)
from app.services.agent.engagement_brain import EngagementBrain
from app.services.agent.observed_input_batch import (
    pending_first_pass_cells, run_observed_input_batch,
)
from app.services.agent.prompts import is_tool_allowed_in_phase
from app.services.agent.tester_loop import forced_next_step, tester_loop_progress as loop_progress


def _brain():
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [
        {"method": "GET", "host": "app.test", "path": "/catalog",
         "name": name, "location": "query", "identity": "anonymous",
         "source": "browser_link", "testable": True}
        for name in ("searchTerm", "category")
    ])
    return brain


def test_batch_tool_is_allowed_during_active_assessment():
    assert is_tool_allowed_in_phase("probe_observed_input_batch", "exploitation")
    assert not is_tool_allowed_in_phase("probe_observed_input_batch", "informational")


def test_first_pass_queue_includes_link_inputs_and_skips_recorded_outcomes():
    brain = _brain()
    assert len(pending_first_pass_cells(brain)) == 4
    first = pending_first_pass_cells(brain)[0]
    first["first_pass_outcome"] = "inconclusive"
    assert len(pending_first_pass_cells(brain)) == 3
    first["first_pass_outcome"] = ""
    first["status"] = "leased"
    first["lease_deadline"] = 1
    assert len(pending_first_pass_cells(brain)) == 4


def test_first_pass_lease_prefers_untried_input_over_repeating_lead():
    brain = _brain()
    sqli = [cell for cell in brain.coverage_cells if cell["specialist"] == "sqli"]
    sqli[0].update(status="inconclusive", attempts=1, priority_rank=0)
    sqli[1].update(status="untested", attempts=0, priority_rank=3)
    claimed = claim_coverage_cell_leases(
        brain, ["sqli"], first_pass_only=True, now=100,
    )["sqli"]
    assert claimed.coverage_cell_id == sqli[1]["id"]


def test_leasing_without_probe_does_not_count_as_attempted():
    brain = _brain()
    claim_coverage_cell_leases(brain, ["sqli"], now=100)
    funnel = parameter_test_funnel(brain)
    assert funnel["by_class"]["sqli"]["checks"] == 2
    assert funnel["by_class"]["xss"]["checks"] == 2
    assert funnel["attempted"] == 0
    assert funnel["unattempted"] == funnel["checks"]


def test_sql_xss_batch_does_not_consume_xxe_work():
    brain = _brain()
    seed_parameter_coverage_cells(brain, [{
        "method": "POST", "host": "app.test", "path": "/stock",
        "name": "document", "location": "body_xml", "identity": "anonymous",
        "source": "captured_api", "testable": True,
    }])
    assert len(pending_first_pass_cells(brain)) == 4
    assert {cell["test_type"] for cell in pending_first_pass_cells(brain)} == {"sqli", "xss"}


def test_relative_browser_action_stays_on_registered_assessment_origin():
    manager = SimpleNamespace(
        _assessment_scope={"app.test"}, _fallback_target="https://app.test/",
        _identity_registry=SimpleNamespace(identities={}),
    )
    spec = {"actions": [{"action": "navigate", "url": "/catalog?searchTerm=canary"}]}
    bounded = prepare_browser_scope(manager, spec, fallback_target="https://app.test/")
    assert bounded["actions"][0]["url"] == "https://app.test/catalog?searchTerm=canary"
    assert spec["actions"][0]["url"] == "/catalog?searchTerm=canary"
    try:
        prepare_browser_scope(manager, {"actions": [
            {"action": "navigate", "url": "https://elsewhere.test/"},
        ]}, fallback_target="https://app.test/")
    except ValueError as exc:
        assert "Out-of-scope" in str(exc)
    else:
        raise AssertionError("Browser scope accepted another host")


def test_batch_reaches_all_link_inputs_once_with_live_receipts():
    class Manager:
        def __init__(self):
            self._engagement_brain = _brain().to_dict()
            self._capability_map = {"target": "https://app.test"}
            self.calls = []

        async def scoped_input_probe_assigned(self, coverage_cell_id, coverage_lease_id, technique):
            cell = next(row for row in self._engagement_brain["coverage_cells"]
                        if row["id"] == coverage_cell_id)
            assert cell["lease_id"] == coverage_lease_id
            self.calls.append(coverage_cell_id)
            return {"success": True, "evidence_id": "receipt-" + coverage_cell_id,
                    "proof_confirmed": False}

        async def record_surface_coverage(self, **_kwargs):
            # An incomplete negative is not allowed to close a SQLi cell.
            return json.dumps({"error": "controls incomplete"})

    manager = Manager()
    first = asyncio.run(run_observed_input_batch(manager, max_checks=4))
    assert first["processed"] == 4 and first["remaining"] == 0
    assert len(set(manager.calls)) == 4
    assert {row["first_pass_outcome"] for row in manager._engagement_brain["coverage_cells"]
            if row["source"] == "parameter_inventory"
            and row["test_type"] in {"sqli", "xss"}} == {"inconclusive"}
    second = asyncio.run(run_observed_input_batch(manager, max_checks=4))
    assert second["processed"] == 0 and second["remaining"] == 0
    assert len(manager.calls) == 4


def test_numeric_link_reaches_bounded_first_pass():
    class Manager:
        def __init__(self):
            brain = EngagementBrain(target="https://app.test")
            seed_parameter_coverage_cells(brain, [{
                "method": "GET", "host": "app.test", "path": "/catalog",
                "name": "productId", "location": "query", "identity": "anonymous",
                "source": "browser_link", "value_type": "positive_integer",
                "testable": True,
            }])
            self._engagement_brain = brain.to_dict()
            self._capability_map = {"target": "https://app.test"}

        async def scoped_input_probe_assigned(self, coverage_cell_id, **_kwargs):
            cell = next(row for row in self._engagement_brain["coverage_cells"]
                        if row["id"] == coverage_cell_id)
            return {"success": True, "evidence_id": "check-" + cell["test_type"],
                    "proof_confirmed": False,
                    "probe_result": {"proof_recipe": "numeric_and_boolean_v1"}}

    manager = Manager()
    result = asyncio.run(run_observed_input_batch(manager, max_checks=2))
    assert result["processed"] == 2 and result["remaining"] == 0
    sqli = next(row for row in manager._engagement_brain["coverage_cells"]
                if row["test_type"] == "sqli")
    assert sqli["first_pass_outcome"] == "inconclusive"
    assert sqli["status"] == "inconclusive"
    assert sqli["first_pass_evidence_id"] == "check-sqli"


def test_transient_first_pass_handoff_gets_one_delayed_retry():
    class Manager:
        def __init__(self):
            brain = _brain()
            for cell in brain.coverage_cells:
                if cell["test_type"] != "xss" or cell["parameter"] != "query:searchTerm":
                    cell["status"] = "skipped"
            self._engagement_brain = brain.to_dict()
            self._capability_map = {"target": "https://app.test"}
            self.calls = 0

        async def scoped_input_probe_assigned(self, **_kwargs):
            self.calls += 1
            if self.calls <= 2:
                return {"success": False, "error": "invalid_coverage_lease",
                        "reason": "lease_changed"}
            return {"success": True, "evidence_id": "browser-receipt",
                    "proof_confirmed": False}

    manager = Manager()
    first = asyncio.run(run_observed_input_batch(manager, max_checks=1))
    assert first["results"][0]["outcome"] == "unattempted"
    cell = next(row for row in manager._engagement_brain["coverage_cells"]
                if row["test_type"] == "xss" and row["parameter"] == "query:searchTerm")
    assert cell["first_pass_attempts"] == 1
    assert pending_first_pass_cells(manager._engagement_brain) == []
    cell["first_pass_retry_at"] = 0
    assert len(pending_first_pass_cells(manager._engagement_brain)) == 1
    second = asyncio.run(run_observed_input_batch(manager, max_checks=1))
    assert second["results"][0]["outcome"] == "inconclusive"
    assert manager.calls == 3
    cell = next(row for row in manager._engagement_brain["coverage_cells"]
                if row["test_type"] == "xss" and row["parameter"] == "query:searchTerm")
    assert cell["first_pass_attempts"] == 2
    assert pending_first_pass_cells(manager._engagement_brain) == []


def test_positive_first_pass_submits_candidate_for_fresh_verification():
    class Manager:
        def __init__(self):
            brain = EngagementBrain(target="https://app.test")
            seed_parameter_coverage_cells(brain, [{
                "method": "GET", "host": "app.test", "path": "/catalog",
                "name": "category", "location": "query", "identity": "anonymous",
                "source": "browser_link", "testable": True,
            }])
            for cell in brain.coverage_cells:
                if cell["test_type"] == "xss":
                    cell["status"] = "skipped"
            self._engagement_brain = brain.to_dict()
            self._capability_map = {"target": "https://app.test"}

        async def scoped_input_probe_assigned(self, coverage_cell_id, coverage_lease_id, technique):
            return {"success": True, "evidence_id": "proof-1", "proof_confirmed": True}

        async def submit_finding_candidate(self, **kwargs):
            assert kwargs["vulnerability_class"] == "sql_injection"
            assert kwargs["evidence_ids"] == ["proof-1"]
            self._engagement_brain["candidates"] = [{
                "id": "candidate-1", "status": "pending",
                "coverage_cell_id": kwargs["coverage_cell_id"],
                "evidence_ids": kwargs["evidence_ids"],
            }]
            return "truncated output is allowed"

    manager = Manager()
    result = asyncio.run(run_observed_input_batch(manager, max_checks=1))
    assert result["results"][0]["outcome"] == "proof_signal"
    assert result["results"][0]["candidate_id"] == "candidate-1"
    assert manager._engagement_brain["candidates"][0]["status"] == "pending"


def test_batch_honors_nested_tool_policy_denial():
    class Manager:
        def __init__(self):
            self._engagement_brain = _brain().to_dict()
            self._capability_map = {"target": "https://app.test"}
            self.invocations = []

        async def execute(self, name, kwargs):
            self.invocations.append((name, kwargs))
            return {"success": False, "error": "policy_denied", "output": "Denied by policy"}

        async def scoped_input_probe_assigned(self, **_kwargs):
            raise AssertionError("Direct probe bypassed the policy gate")

    manager = Manager()
    result = asyncio.run(run_observed_input_batch(manager, max_checks=1))
    assert result["processed"] == 1
    assert result["results"][0]["outcome"] == "unattempted"
    assert result["results"][0]["reason"] == "policy_denied"
    assert manager.invocations[0][0] == "scoped_input_probe_assigned"
    denied = next(cell for cell in manager._engagement_brain["coverage_cells"]
                  if cell["id"] == result["results"][0]["coverage_cell_id"])
    assert denied["status"] == "blocked"


def test_cancelled_probe_releases_lease_for_fresh_retry():
    class Manager:
        def __init__(self):
            self._engagement_brain = _brain().to_dict()
            self._capability_map = {"target": "https://app.test"}

        async def scoped_input_probe_assigned(self, **_kwargs):
            raise asyncio.CancelledError

    manager = Manager()
    try:
        asyncio.run(run_observed_input_batch(manager, max_checks=1))
    except asyncio.CancelledError:
        pass
    else:
        raise AssertionError("Cancellation was swallowed")
    leased = [cell for cell in manager._engagement_brain["coverage_cells"]
              if cell.get("lease_id")]
    assert not leased
    assert len(pending_first_pass_cells(manager._engagement_brain)) == 4


def test_stale_lease_is_reclaimed_once_before_recording_probe_receipt():
    class Manager:
        def __init__(self):
            brain = EngagementBrain(target="https://app.test")
            seed_parameter_coverage_cells(brain, [{
                "method": "GET", "host": "app.test", "path": "/catalog",
                "name": "category", "location": "query", "identity": "anonymous",
                "source": "browser_link", "testable": True,
            }])
            for cell in brain.coverage_cells:
                if cell["test_type"] == "xss":
                    cell["status"] = "skipped"
            self._engagement_brain = brain.to_dict()
            self._capability_map = {"target": "https://app.test"}
            self.lease_ids = []

        async def scoped_input_probe_assigned(self, coverage_lease_id, **_kwargs):
            self.lease_ids.append(coverage_lease_id)
            if len(self.lease_ids) == 1:
                return {"success": False, "error": "invalid_coverage_lease",
                        "reason": "lease_expired"}
            return {"success": True, "evidence_id": "boolean-receipt",
                    "proof_confirmed": False,
                    "probe_result": {"proof_recipe": "string_and_boolean_v1"}}

    manager = Manager()
    result = asyncio.run(run_observed_input_batch(manager, max_checks=1))
    assert len(manager.lease_ids) == 2
    assert manager.lease_ids[0] != manager.lease_ids[1]
    assert result["results"][0]["outcome"] == "inconclusive"
    assert result["results"][0]["evidence_id"] == "boolean-receipt"
    assert result["handoff_failures"] == 0
    assert not any(cell.get("lease_id") for cell in manager._engagement_brain["coverage_cells"])


def test_unrepaired_mapping_handoff_is_visible_and_not_counted_as_a_probe():
    class Manager:
        def __init__(self):
            self._engagement_brain = _brain().to_dict()
            self._capability_map = {"target": "https://app.test"}
            self.calls = 0

        async def scoped_input_probe_assigned(self, **_kwargs):
            self.calls += 1
            return {"success": False, "error": "invalid_coverage_lease",
                    "reason": "not_observed_input"}

    manager = Manager()
    result = asyncio.run(run_observed_input_batch(manager, max_checks=1))
    assert manager.calls == 1
    assert result["handoff_failures"] == 1
    assert result["results"][0]["handoff_failed"] is True
    assert result["results"][0]["evidence_id"] == ""
    cell = next(row for row in manager._engagement_brain["coverage_cells"]
                if row["id"] == result["results"][0]["coverage_cell_id"])
    assert cell["first_pass_outcome"] == "unattempted"
    assert cell["first_pass_handoff_error"] == "invalid_coverage_lease: not_observed_input"
    progress = loop_progress({
        "mode": "agent", "assessment_resume": True,
        "target_info": {"primary_target": "https://app.test"},
        "engagement_brain": manager._engagement_brain,
        "execution_trace": [],
    })
    assert any(item["id"] == "first_pass_handoff" for item in progress["missing"])
    assert progress["ready_to_complete"] is False


def test_stale_handoff_does_not_overwrite_another_executors_lease():
    class Manager:
        def __init__(self):
            self._engagement_brain = _brain().to_dict()
            self._capability_map = {"target": "https://app.test"}

        async def scoped_input_probe_assigned(self, coverage_cell_id, **_kwargs):
            current = next(row for row in self._engagement_brain["coverage_cells"]
                           if row["id"] == coverage_cell_id)
            current["lease_id"] = "another-executor"
            return {"success": False, "error": "invalid_coverage_lease",
                    "reason": "lease_mismatch"}

    manager = Manager()
    result = asyncio.run(run_observed_input_batch(manager, max_checks=1))
    assert result["handoff_failures"] == 1
    cell = next(row for row in manager._engagement_brain["coverage_cells"]
                if row["id"] == result["results"][0]["coverage_cell_id"])
    assert cell["lease_id"] == "another-executor"
    assert not cell.get("first_pass_outcome")


@pytest.mark.parametrize("raises", [False, True])
def test_positive_probe_survives_failed_candidate_submission_for_scheduler_retry(raises):
    class Manager:
        def __init__(self):
            brain = EngagementBrain(target="https://app.test")
            seed_parameter_coverage_cells(brain, [{
                "method": "GET", "host": "app.test", "path": "/catalog",
                "name": "category", "location": "query", "identity": "anonymous",
                "source": "browser_link", "testable": True,
            }])
            for cell in brain.coverage_cells:
                if cell["test_type"] == "xss":
                    cell["status"] = "skipped"
            self._engagement_brain = brain.to_dict()
            self._capability_map = {"target": "https://app.test"}

        async def scoped_input_probe_assigned(self, **_kwargs):
            return {"success": True, "evidence_id": "positive-sql-receipt",
                    "proof_confirmed": True}

        async def submit_finding_candidate(self, **_kwargs):
            if raises:
                raise RuntimeError("temporary_candidate_failure")
            return {"success": False, "error": "temporary_candidate_failure"}

    manager = Manager()
    result = asyncio.run(run_observed_input_batch(manager, max_checks=1))
    assert result["handoff_failures"] == 0
    assert result["candidate_handoffs_pending"] == 1
    cell = next(row for row in manager._engagement_brain["coverage_cells"]
                if row["test_type"] == "sqli")
    assert cell["first_pass_outcome"] == "proof_signal"
    assert cell["first_pass_evidence_id"] == "positive-sql-receipt"
    state = {
        "mode": "agent", "assessment_resume": True,
        "target_info": {"primary_target": "https://app.test"},
        "capability_map": manager._capability_map,
        "engagement_brain": manager._engagement_brain,
        "execution_trace": [],
    }
    next_step = forced_next_step(state)
    assert next_step["tool_name"] == "submit_finding_candidate"
    assert next_step["tool_args"]["evidence_ids"] == ["positive-sql-receipt"]


def test_xss_first_pass_uses_reflection_context_before_proof_candidate():
    class Manager:
        def __init__(self):
            brain = EngagementBrain(target="https://app.test")
            seed_parameter_coverage_cells(brain, [{
                "method": "GET", "host": "app.test", "path": "/catalog",
                "name": "searchTerm", "location": "query", "identity": "anonymous",
                "source": "browser_link", "testable": True,
            }])
            for cell in brain.coverage_cells:
                if cell["test_type"] == "sqli":
                    cell["status"] = "skipped"
            self._engagement_brain = brain.to_dict()
            self._capability_map = {"target": "https://app.test"}
            self.techniques = []

        async def scoped_input_probe_assigned(self, coverage_cell_id, coverage_lease_id, technique):
            self.techniques.append(technique)
            if technique == "html_body":
                return {"success": True, "evidence_id": "body-1", "proof_confirmed": False,
                        "probe_result": {"reflection_contexts": ["html_attribute"]}}
            return {"success": True, "evidence_id": "attribute-1", "proof_confirmed": True}

        async def submit_finding_candidate(self, **kwargs):
            self._engagement_brain["candidates"] = [{
                "id": "xss-candidate", "status": "pending",
                "coverage_cell_id": kwargs["coverage_cell_id"],
                "evidence_ids": kwargs["evidence_ids"],
            }]
            return "candidate queued"

    manager = Manager()
    result = asyncio.run(run_observed_input_batch(manager, max_checks=1))
    assert manager.techniques == ["html_body", "html_attribute"]
    assert result["results"][0]["outcome"] == "proof_signal"
    assert result["results"][0]["candidate_id"] == "xss-candidate"


def test_clean_sqli_requires_coverage_validator_to_close_cell():
    class Manager:
        def __init__(self):
            brain = _brain()
            for cell in brain.coverage_cells:
                if cell["test_type"] == "xss":
                    cell["status"] = "skipped"
            self._engagement_brain = brain.to_dict()
            self._capability_map = {"target": "https://app.test"}

        async def scoped_input_probe_assigned(self, **_kwargs):
            return {"success": True, "evidence_id": "complete-controls", "proof_confirmed": False}

        async def record_surface_coverage(self, **kwargs):
            row = next(cell for cell in self._engagement_brain["coverage_cells"]
                       if cell["id"] == kwargs["coverage_cell_id"])
            row["status"] = "tested_clean"
            row["lease_id"] = ""
            return "truncated output is allowed"

    manager = Manager()
    result = asyncio.run(run_observed_input_batch(manager, max_checks=1))
    assert result["results"][0]["outcome"] == "tested_clean"
    assert result["funnel"]["tested_clean"] == 1


def test_negative_boolean_receipt_keeps_input_inconclusive():
    class Manager:
        def __init__(self):
            brain = EngagementBrain(target="https://app.test")
            seed_parameter_coverage_cells(brain, [{
                "method": "GET", "host": "app.test", "path": "/catalog",
                "name": "category", "location": "query", "identity": "anonymous",
                "source": "browser_link", "testable": True,
            }])
            for cell in brain.coverage_cells:
                if cell["test_type"] == "xss":
                    cell["status"] = "skipped"
            self._engagement_brain = brain.to_dict()
            self._capability_map = {"target": "https://app.test"}

        async def scoped_input_probe_assigned(self, **_kwargs):
            return {"success": True, "evidence_id": "negative-boolean",
                    "proof_confirmed": False,
                    "probe_result": {"proof_recipe": "string_and_boolean_v1"}}

        async def record_surface_coverage(self, **_kwargs):
            raise AssertionError("One negative Boolean recipe is not a clean verdict")

    manager = Manager()
    result = asyncio.run(run_observed_input_batch(manager, max_checks=1))
    assert result["results"][0]["outcome"] == "inconclusive"
    cell = next(row for row in manager._engagement_brain["coverage_cells"]
                if row["test_type"] == "sqli")
    assert cell["first_pass_evidence_id"] == "negative-boolean"
    assert cell["status"] == "inconclusive"


def test_eighteen_inputs_receive_both_class_first_pass_outcomes():
    class Manager:
        def __init__(self):
            brain = EngagementBrain(target="https://app.test")
            seed_parameter_coverage_cells(brain, [{
                "method": "GET", "host": "app.test", "path": "/catalog",
                "name": f"field{index}", "location": "query", "identity": "anonymous",
                "source": "browser_link", "testable": True,
            } for index in range(18)])
            self._engagement_brain = brain.to_dict()
            self._capability_map = {"target": "https://app.test"}
            self.calls = []

        async def scoped_input_probe_assigned(self, coverage_cell_id, **_kwargs):
            self.calls.append(coverage_cell_id)
            return {"success": True, "evidence_id": "proof-" + coverage_cell_id,
                    "proof_confirmed": False}

        async def record_surface_coverage(self, **_kwargs):
            return json.dumps({"error": "controls inconclusive"})

    manager = Manager()
    for _ in range(9):
        asyncio.run(run_observed_input_batch(manager, max_checks=4))
    funnel = parameter_test_funnel(manager._engagement_brain)
    assert len(set(manager.calls)) == len(manager.calls) == 36
    assert funnel["inputs"] == 18 and funnel["checks"] == 54
    assert funnel["attempted"] == funnel["probed"] == 36
    assert not pending_first_pass_cells(manager._engagement_brain)
    assert funnel["by_class"]["sqli"]["probed"] == 18
    assert funnel["by_class"]["xss"]["probed"] == 18
    assert funnel["by_class"]["crlf"]["unattempted"] == 18


def test_batch_probes_only_the_active_assessment_target():
    class Manager:
        def __init__(self):
            brain = EngagementBrain(target="https://ginandjuice.shop")
            seed_parameter_coverage_cells(brain, [
                {"method": "GET", "host": host, "path": "/catalog",
                 "name": "searchTerm", "location": "query", "identity": "anonymous",
                 "source": "browser_link", "testable": True}
                for host in ("ginandjuice.shop", "old.example.com")
            ])
            self._engagement_brain = brain.to_dict()
            self._capability_map = {"target": "https://ginandjuice.shop"}
            self.calls = []

        async def scoped_input_probe_assigned(self, coverage_cell_id, **_kwargs):
            cell = next(row for row in self._engagement_brain["coverage_cells"]
                        if row["id"] == coverage_cell_id)
            self.calls.append(cell["host"])
            return {"success": True, "evidence_id": "receipt-" + coverage_cell_id,
                    "proof_confirmed": False}

        async def record_surface_coverage(self, **_kwargs):
            return json.dumps({"error": "controls inconclusive"})

    manager = Manager()
    result = asyncio.run(run_observed_input_batch(
        manager, target="https://ginandjuice.shop", max_checks=8,
    ))
    assert result["processed"] == 2 and result["remaining"] == 0
    assert manager.calls == ["ginandjuice.shop", "ginandjuice.shop"]
    assert len(pending_first_pass_cells(manager._engagement_brain)) == 2


def test_batch_refuses_stale_map_for_current_target():
    class Manager:
        def __init__(self):
            self._engagement_brain = _brain().to_dict()
            self._capability_map = {"target": "https://app.test"}
            self.calls = 0

        async def scoped_input_probe_assigned(self, **_kwargs):
            self.calls += 1
            raise AssertionError("Stale map must not trigger a probe")

    manager = Manager()
    result = asyncio.run(run_observed_input_batch(
        manager, target="https://ginandjuice.shop", max_checks=8,
    ))
    assert result["processed"] == 0
    assert result["error"] == "assessment_target_mismatch"
    assert manager.calls == 0
