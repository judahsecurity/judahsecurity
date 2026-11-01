"""The first-pass queue must reach each observed input without replay loops."""

import asyncio
import json
from types import SimpleNamespace

import pytest
from app.services.agent.assessment_scope import prepare_browser_scope
from app.services.agent.coverage_cells import (
    claim_coverage_cell_leases,
    parameter_test_funnel,
    seed_parameter_coverage_cells,
)
from app.services.agent.engagement_brain import EngagementBrain
from app.services.agent.observed_input_batch import (
    pending_first_pass_cells,
    run_observed_input_batch,
)
from app.services.agent.prompts import is_tool_allowed_in_phase
from app.services.agent.scoped_assessment_tools import HUNTER_GET_BUDGET
from app.services.agent.tester_loop import forced_next_step
from app.services.agent.tester_loop import tester_loop_progress as loop_progress
from app.services.agent.tools import ASMToolsManager


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


def test_xss_batch_touches_distinct_inputs_before_sweeping_variants():
    class Manager:
        def __init__(self):
            brain = _brain()
            for cell in brain.coverage_cells:
                if cell["test_type"] == "sqli":
                    cell["status"] = "skipped"
            self._engagement_brain = brain.to_dict()
            self._capability_map = {"target": "https://app.test"}
            self.calls = []

        async def scoped_input_probe_assigned(self, coverage_cell_id, coverage_lease_id, technique):
            self.calls.append((coverage_cell_id, technique))
            return {"success": True, "evidence_id": f"receipt-{len(self.calls)}",
                    "proof_confirmed": False, "probe_result": {"reflection_contexts": []}}

    manager = Manager()
    first = asyncio.run(run_observed_input_batch(manager, max_checks=1))
    second = asyncio.run(run_observed_input_batch(manager, max_checks=1))
    assert first["results"][0]["coverage_cell_id"] != second["results"][0]["coverage_cell_id"]
    assert [technique for _, technique in manager.calls] == ["html_body", "html_body"]
    assert all(cell["xss_pending_techniques"] for cell in manager._engagement_brain["coverage_cells"]
               if cell["test_type"] == "xss")


def test_exhausted_get_budget_blocks_sqli_without_preventing_xss():
    class Manager:
        def __init__(self):
            self._engagement_brain = _brain().to_dict()
            self._capability_map = {"target": "https://app.test"}
            self._scoped_get_count = HUNTER_GET_BUDGET
            self.calls = []

        async def scoped_input_probe_assigned(self, coverage_cell_id, coverage_lease_id, technique):
            self.calls.append(technique)
            return {"success": True, "evidence_id": f"receipt-{len(self.calls)}",
                    "proof_confirmed": False, "probe_result": {"reflection_contexts": []}}

    manager = Manager()
    result = asyncio.run(run_observed_input_batch(manager, max_checks=4))
    assert result["processed"] == 4
    assert all(cell["status"] == "blocked" and
               cell["first_pass_blocked_reason"] == "get_budget_exhausted"
               for cell in manager._engagement_brain["coverage_cells"]
               if cell["test_type"] == "sqli")
    assert manager.calls
    assert all(name in {"html_body", "html_body_svg", "html_attribute",
                        "html_attribute_single", "js_single", "js_double"}
               for name in manager.calls)


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
    assert first["processed"] == 4 and first["remaining"] == 2
    assert len(set(manager.calls)) == 4
    assert {row["first_pass_outcome"] for row in manager._engagement_brain["coverage_cells"]
            if row["source"] == "parameter_inventory"
            and row["test_type"] in {"sqli", "xss"}} == {"inconclusive"}
    calls_after_first = list(manager.calls)
    second = asyncio.run(run_observed_input_batch(manager, max_checks=4))
    assert second["processed"] == 2 and second["remaining"] == 0
    assert manager.calls[:len(calls_after_first)] == calls_after_first
    assert len(manager.calls) == 2 + 2 * 6


def test_unavailable_identity_is_blocked_without_probe_and_reopens_after_login():
    class Manager:
        def __init__(self):
            brain = EngagementBrain(target="https://app.test")
            seed_parameter_coverage_cells(brain, [{
                "method": "GET", "host": "app.test", "path": "/catalog",
                "name": "category", "location": "query", "identity": "legacy",
                "source": "browser_traffic", "artifact_id": "capture-1",
                "testable": True,
            }])
            self._engagement_brain = brain.to_dict()
            self._capability_map = {"target": "https://app.test"}
            self.logged_in = False
            self.calls = []

        def _scoped_state(self, identity, url):
            assert identity == "legacy" and url == "https://app.test/catalog"
            if not self.logged_in:
                raise ValueError("no authenticated session")
            return {"cookies": []}

        async def scoped_input_probe_assigned(self, coverage_cell_id, **_kwargs):
            self.calls.append(coverage_cell_id)
            return {"success": True, "evidence_id": "receipt-" + coverage_cell_id,
                    "proof_confirmed": False}

        async def scoped_assessment_probe_assigned(self, coverage_cell_id, **_kwargs):
            return await self.scoped_input_probe_assigned(coverage_cell_id)

    manager = Manager()
    blocked = asyncio.run(run_observed_input_batch(manager, max_checks=2))
    assert blocked["processed"] == 0 and blocked["identity_blocked"] == 2
    assert blocked["remaining"] == 0 and manager.calls == []
    assert all(cell["status"] == "blocked" and cell["first_pass_outcome"] == "unattempted"
               for cell in manager._engagement_brain["coverage_cells"]
               if cell["test_type"] in {"sqli", "xss"})

    manager.logged_in = True
    reopened = asyncio.run(run_observed_input_batch(manager, max_checks=2))
    assert reopened["identity_reopened"] == 2
    assert reopened["processed"] == 2 and reopened["remaining"] == 0
    assert len(set(manager.calls)) == 2


def test_assigned_probe_reports_missing_identity_before_using_budget():
    manager = ASMToolsManager()
    manager._fallback_target = "https://app.test"
    manager._assessment_scope = {"app.test"}
    manager._capability_map = {"target": "https://app.test"}
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [{
        "method": "GET", "host": "app.test", "path": "/catalog",
        "name": "category", "location": "query", "identity": "legacy",
        "source": "browser_link", "testable": True,
    }])
    lease = claim_coverage_cell_leases(brain, ["sqli"])["sqli"]
    manager._engagement_brain = brain.to_dict()

    result = asyncio.run(manager.scoped_input_probe_assigned(
        lease.coverage_cell_id, lease.id,
    ))
    assert result["error"] == "identity_unavailable"
    assert getattr(manager, "_scoped_get_count", 0) == 0



def test_first_pass_covers_distinct_inputs_before_second_class():
    class Manager:
        def __init__(self):
            brain = EngagementBrain(target="https://app.test")
            seed_parameter_coverage_cells(brain, [
                {"method": "GET", "host": "app.test", "path": path,
                 "name": name, "location": "query", "identity": "anonymous",
                 "source": "browser_link", "testable": True}
                for path, name in (
                    ("/catalog", "category"),
                    ("/catalog", "searchTerm"),
                    ("/blog", "q"),
                    ("/login", "next"),
                )
            ])
            self._engagement_brain = brain.to_dict()
            self._capability_map = {"target": "https://app.test"}
            self.calls = []

        async def scoped_input_probe_assigned(self, coverage_cell_id, **_kwargs):
            cell = next(row for row in self._engagement_brain["coverage_cells"]
                        if row["id"] == coverage_cell_id)
            self.calls.append((cell["path"], cell["parameter"], cell["test_type"]))
            return {"success": True, "evidence_id": "receipt-" + coverage_cell_id,
                    "proof_confirmed": False}

    manager = Manager()
    result = asyncio.run(run_observed_input_batch(manager, max_checks=4))
    assert result["processed"] == 4
    assert len({(path, param) for path, param, _ in manager.calls}) == 4
    assert {kind for _, _, kind in manager.calls} == {"sqli", "xss"}


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


def test_observed_post_form_xss_is_sent_to_browser_execution():
    class Manager:
        def __init__(self):
            brain = EngagementBrain(target="https://app.test")
            seed_parameter_coverage_cells(brain, [{
                "method": "POST", "host": "app.test", "path": "/newsletter",
                "name": "email", "location": "body_form", "identity": "anonymous",
                "source": "observed_form", "testable": True,
            }])
            self._engagement_brain = brain.to_dict()
            self._capability_map = {"target": "https://app.test", "scope": "https://app.test",
                                    "forms": [{"method": "POST",
                                               "action": "https://app.test/newsletter",
                                               "page": "https://app.test/catalog",
                                               "inputs": ["email"]}]}
            self._scoped_body_replay_paths = {"/newsletter"}
            self.calls = []

        async def scoped_input_probe_assigned(self, **kwargs):
            self.calls.append(kwargs)
            return {"success": True, "evidence_id": "post-browser-proof",
                    "proof_confirmed": False, "probe_result": {"reflection_contexts": []}}

    manager = Manager()
    assert {row["test_type"] for row in pending_first_pass_cells(manager._engagement_brain)} == {"xss"}
    result = asyncio.run(run_observed_input_batch(manager, max_checks=2))
    assert result["processed"] == 1
    assert len(manager.calls) == 1
    assert manager.calls[0]["technique"] == "html_body"
    assert any(row["outcome"] == "inconclusive" for row in result["results"])



def test_unapproved_post_form_is_recorded_as_open_blocked_coverage():
    class Manager:
        def __init__(self):
            brain = EngagementBrain(target="https://app.test")
            seed_parameter_coverage_cells(brain, [{
                "method": "POST", "host": "app.test", "path": "/newsletter",
                "name": "email", "location": "body_form", "identity": "anonymous",
                "source": "observed_form", "testable": True,
            }])
            self._engagement_brain = brain.to_dict()
            self._capability_map = {"target": "https://app.test"}
            self._scoped_body_replay_paths = set()

        async def scoped_input_probe_assigned(self, **_kwargs):
            raise AssertionError("Unapproved POST must not reach the executor")

    manager = Manager()
    result = asyncio.run(run_observed_input_batch(manager, max_checks=2))
    assert result["processed"] == 0
    assert result["policy_blocked"] == 1
    assert result["funnel"]["blocked"] == 1
    assert result["funnel"]["attempted"] == 0
    cell = next(row for row in manager._engagement_brain["coverage_cells"]
                if row["test_type"] == "xss")
    assert cell["status"] == "blocked"
    assert cell["first_pass_outcome"] == "unattempted"

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
    assert manager.calls == 8  # two stale attempts, then six XSS variants
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
    assert result["funnel"]["proof_signals"] == 1
    assert result["funnel"]["candidate_handoffs_pending"] == 0


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
    assert result["results"][0]["candidate_handoff_error"] == (
        "RuntimeError" if raises else "temporary_candidate_failure"
    )
    assert result["funnel"]["proof_signals"] == 1
    assert result["funnel"]["candidate_handoffs_pending"] == 1
    assert result["funnel"]["handoff_rows"][0]["evidence_id"] == "positive-sql-receipt"
    cell = next(row for row in manager._engagement_brain["coverage_cells"]
                if row["test_type"] == "sqli")
    assert cell["first_pass_outcome"] == "proof_signal"
    assert cell["first_pass_evidence_id"] == "positive-sql-receipt"
    assert cell["first_pass_evidence_source"] == "local"
    assert cell["first_pass_candidate_handoff_error"] == result["results"][0]["candidate_handoff_error"]
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
    state["execution_trace"] = [
        {"tool_name": "submit_finding_candidate", "tool_args": next_step["tool_args"],
         "success": False},
        {"tool_name": "submit_finding_candidate", "tool_args": next_step["tool_args"],
         "success": False},
    ]
    # Candidate handoff retries are exhausted; other unprobed classes on the
    # same observed input must still get their own first pass.
    followup = forced_next_step(state)
    assert followup["tool_name"] == "fireteam_dispatch"
    assert followup["tool_args"]["mode"] == "coverage_followup"
    progress = loop_progress(state)
    assert any(item["id"] == "candidate_handoff_exhausted" for item in progress["missing"])


def test_scoped_service_proof_does_not_enter_local_verifier_queue():
    class Manager:
        def __init__(self):
            brain = EngagementBrain(target="https://app.test")
            seed_parameter_coverage_cells(brain, [{
                "method": "POST", "host": "app.test", "path": "/catalog",
                "name": "category", "location": "body_form", "identity": "anonymous",
                "source": "browser_traffic", "artifact_id": "capture-1", "testable": True,
            }])
            for cell in brain.coverage_cells:
                if cell["test_type"] == "xss":
                    cell["status"] = "skipped"
            self._engagement_brain = brain.to_dict()
            self._capability_map = {"target": "https://app.test"}
            self._scoped_body_replay_paths = {"/catalog"}

        async def scoped_assessment_probe_assigned(self, **_kwargs):
            return {"success": True, "service_artifact_ids": ["service-proof-1"],
                    "proof_confirmed": True}

        async def submit_finding_candidate(self, **_kwargs):
            raise AssertionError("A service artifact is not a local verifier receipt")

    manager = Manager()
    result = asyncio.run(run_observed_input_batch(manager, max_checks=1))
    assert result["results"][0]["outcome"] == "proof_signal"
    assert result["results"][0]["evidence_source"] == "service"
    assert result["funnel"]["service_candidate_handoffs_pending"] == 1
    state = {
        "mode": "agent", "assessment_resume": True,
        "target_info": {"primary_target": "https://app.test"},
        "capability_map": manager._capability_map,
        "engagement_brain": manager._engagement_brain,
        "execution_trace": [],
    }
    assert forced_next_step(state) is None
    assert any(item["id"] == "service_candidate_handoff"
               for item in loop_progress(state)["missing"])


def test_captured_post_xss_uses_reflection_canary_and_stays_inconclusive():
    class Manager:
        def __init__(self):
            brain = EngagementBrain(target="https://app.test")
            seed_parameter_coverage_cells(brain, [{
                "method": "POST", "host": "app.test", "path": "/feedback",
                "name": "message", "location": "body_form", "identity": "anonymous",
                "source": "browser_traffic", "artifact_id": "capture-1", "testable": True,
            }])
            for cell in brain.coverage_cells:
                if cell["test_type"] == "sqli":
                    cell["status"] = "skipped"
            self._engagement_brain = brain.to_dict()
            self._capability_map = {"target": "https://app.test"}
            self._scoped_body_replay_paths = {"/feedback"}
            self.techniques = []

        async def scoped_assessment_probe_assigned(self, **kwargs):
            self.techniques.append(kwargs["technique"])
            return {"success": True, "evidence_id": "xss-reflection-1",
                    "proof_confirmed": False,
                    "probe_result": {"reflection_detected": True,
                                     "raw_html_reflection": True}}

        async def submit_finding_candidate(self, **_kwargs):
            raise AssertionError("Reflection alone is not browser execution proof")

    manager = Manager()
    result = asyncio.run(run_observed_input_batch(manager, max_checks=1))
    assert manager.techniques == ["xss_reflection"]
    assert result["results"][0]["outcome"] == "inconclusive"
    assert "browser execution" in result["results"][0]["reason"]


def test_successful_candidate_retry_clears_saved_handoff_error():
    manager = ASMToolsManager()
    brain = _brain()
    cell = next(row for row in brain.coverage_cells if row["test_type"] == "sqli")
    cell.update(first_pass_outcome="proof_signal",
                first_pass_evidence_id="proof-retry-1",
                first_pass_evidence_source="local",
                first_pass_candidate_handoff_error="temporary_candidate_failure")
    manager._engagement_brain = brain.to_dict()
    response = asyncio.run(manager.submit_finding_candidate(
        title="SQLi proof on GET /catalog (searchTerm)",
        target="https://app.test/catalog",
        specialist="sqli", vulnerability_class="sql_injection",
        coverage_cell_id=cell["id"], evidence_ids=["proof-retry-1"],
    ))
    assert json.loads(response)["candidate"]["status"] == "pending"
    saved = next(row for row in manager._engagement_brain["coverage_cells"]
                 if row["id"] == cell["id"])
    assert saved.get("first_pass_candidate_handoff_error") is None
    assert parameter_test_funnel(manager._engagement_brain)["candidate_handoffs_pending"] == 0


def test_old_candidate_on_same_cell_does_not_hide_new_proof_handoff():
    brain = _brain()
    cell = next(row for row in brain.coverage_cells if row["test_type"] == "sqli")
    cell.update(first_pass_outcome="proof_signal",
                first_pass_evidence_id="new-proof", first_pass_evidence_source="local")
    brain.candidates = [{"id": "old-candidate", "coverage_cell_id": cell["id"],
                         "evidence_ids": ["old-proof"], "status": "refuted"}]
    funnel = parameter_test_funnel(brain)
    assert funnel["candidate_handoffs_pending"] == 1
    assert funnel["candidates"] == 0


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



def test_xss_html_text_reflection_gets_alternate_execution_check():
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
            return {
                "success": True, "evidence_id": "receipt-" + technique,
                "proof_confirmed": technique == "html_body_svg",
                "probe_result": {"reflection_contexts": ["html_text"]},
            }

        async def submit_finding_candidate(self, **kwargs):
            self._engagement_brain["candidates"] = [{
                "id": "svg-candidate", "status": "pending",
                "coverage_cell_id": kwargs["coverage_cell_id"],
                "evidence_ids": kwargs["evidence_ids"],
            }]
            return "candidate queued"

    manager = Manager()
    result = asyncio.run(run_observed_input_batch(manager, max_checks=1))
    assert manager.techniques == ["html_body", "html_body_svg"]
    assert result["results"][0]["outcome"] == "proof_signal"
    assert result["results"][0]["candidate_id"] == "svg-candidate"


def test_xss_attribute_followup_tries_single_quote_after_double_quote():
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
            return {
                "success": True, "evidence_id": "receipt-" + technique,
                "proof_confirmed": technique == "html_attribute_single",
                "probe_result": {"reflection_contexts": ["html_attribute"]},
            }

        async def submit_finding_candidate(self, **kwargs):
            self._engagement_brain["candidates"] = [{
                "id": "single-quote-candidate", "status": "pending",
                "coverage_cell_id": kwargs["coverage_cell_id"],
                "evidence_ids": kwargs["evidence_ids"],
            }]
            return "candidate queued"

    manager = Manager()
    result = asyncio.run(run_observed_input_batch(manager, max_checks=1))
    assert manager.techniques == [
        "html_body", "html_attribute", "html_attribute_single",
    ]
    assert result["results"][0]["outcome"] == "proof_signal"
    assert result["results"][0]["candidate_id"] == "single-quote-candidate"


def test_sqli_receipt_without_proof_recipe_cannot_close_cell_clean():
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
            raise AssertionError("An unproven SQLi first pass cannot close coverage")

    manager = Manager()
    result = asyncio.run(run_observed_input_batch(manager, max_checks=1))
    assert result["results"][0]["outcome"] == "inconclusive"
    assert result["funnel"]["tested_clean"] == 0


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
    assert len(set(manager.calls)) == 36
    assert len(manager.calls) == 36  # Every input gets SQLi and one XSS pass first.
    assert len(pending_first_pass_cells(manager._engagement_brain)) == 18
    for _ in range(5):
        asyncio.run(run_observed_input_batch(manager, max_checks=4))
    funnel = parameter_test_funnel(manager._engagement_brain)
    assert len(manager.calls) == 18 + 18 * 6  # SQLi once and six XSS variants per input
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
    assert manager.calls == ["ginandjuice.shop"] * 7  # SQLi once and six XSS variants
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

@pytest.mark.asyncio
async def test_nested_first_pass_probe_reserves_gets_without_context_leak():
    from app.services.agent.observed_input_batch import _invoke
    from app.services.agent.scoped_assessment_tools import first_pass_get_context

    class Manager:
        async def execute(self, name, kwargs):
            assert name == "scoped_input_probe_assigned"
            assert first_pass_get_context.get() is True
            return {"output": {"success": True}}

    assert first_pass_get_context.get() is False
    assert await _invoke(Manager(), "scoped_input_probe_assigned", {}) == {
        "success": True,
    }
    assert first_pass_get_context.get() is False


def test_get_xss_first_pass_sweeps_all_supported_contexts_without_reflection():
    """An inert first marker cannot suppress other reflected XSS contexts."""
    class Manager:
        def __init__(self):
            brain = EngagementBrain(target="https://app.test")
            seed_parameter_coverage_cells(brain, [{
                "method": "GET", "host": "app.test", "path": "/search",
                "name": "term", "location": "query", "identity": "anonymous",
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
            return {"success": True, "evidence_id": "receipt-" + technique,
                    "proof_confirmed": False,
                    "probe_result": {"reflection_contexts": []}}

    manager = Manager()
    result = asyncio.run(run_observed_input_batch(manager, max_checks=1))
    expected = ["html_body", "html_body_svg", "html_attribute",
                "html_attribute_single", "js_single", "js_double"]
    assert manager.techniques == expected
    assert result["results"][0]["outcome"] == "inconclusive"
    xss = next(cell for cell in manager._engagement_brain["coverage_cells"]
               if cell["test_type"] == "xss")
    assert xss["xss_techniques_attempted"] == expected
    assert xss["xss_pending_techniques"] == []


def test_get_xss_variant_sweep_resumes_saved_cell_without_repeating_probes():
    class Manager:
        def __init__(self):
            brain = EngagementBrain(target="https://app.test")
            seed_parameter_coverage_cells(brain, [{
                "method": "GET", "host": "app.test", "path": "/search",
                "name": "term", "location": "query", "identity": "anonymous",
                "source": "browser_link", "testable": True,
            }])
            for cell in brain.coverage_cells:
                if cell["test_type"] == "sqli":
                    cell["status"] = "skipped"
                else:
                    cell["status"] = "inconclusive"
                    cell["first_pass_outcome"] = "inconclusive"
                    cell["probe_artifact_ids"] = ["prior-receipt"]
                    cell["xss_techniques_attempted"] = ["html_body", "html_body_svg"]
                    cell["xss_pending_techniques"] = [
                        "html_attribute", "html_attribute_single", "js_single", "js_double",
                    ]
            self._engagement_brain = brain.to_dict()
            self._capability_map = {"target": "https://app.test"}
            self.techniques = []

        async def scoped_input_probe_assigned(self, coverage_cell_id, coverage_lease_id, technique):
            self.techniques.append(technique)
            return {"success": True, "evidence_id": "receipt-" + technique,
                    "proof_confirmed": False,
                    "probe_result": {"reflection_contexts": []}}

    manager = Manager()
    result = asyncio.run(run_observed_input_batch(manager, max_checks=1))
    assert result["processed"] == 1
    assert manager.techniques == [
        "html_attribute", "html_attribute_single", "js_single", "js_double",
    ]
    xss = next(cell for cell in manager._engagement_brain["coverage_cells"]
               if cell["test_type"] == "xss")
    assert xss["xss_pending_techniques"] == []



def test_get_xss_timeout_saves_remaining_variants_for_next_batch():
    class Manager:
        def __init__(self):
            brain = EngagementBrain(target="https://app.test")
            seed_parameter_coverage_cells(brain, [{
                "method": "GET", "host": "app.test", "path": "/search",
                "name": "term", "location": "query", "identity": "anonymous",
                "source": "browser_link", "testable": True,
            }])
            for cell in brain.coverage_cells:
                if cell["test_type"] == "sqli":
                    cell["status"] = "skipped"
            self._engagement_brain = brain.to_dict()
            self._capability_map = {"target": "https://app.test"}
            self.techniques = []
            self.fail_once = True

        async def scoped_input_probe_assigned(self, coverage_cell_id, coverage_lease_id, technique):
            self.techniques.append(technique)
            if technique == "html_body_svg" and self.fail_once:
                self.fail_once = False
                raise asyncio.TimeoutError
            return {"success": True, "evidence_id": "receipt-" + technique,
                    "proof_confirmed": False,
                    "probe_result": {"reflection_contexts": []}}

    manager = Manager()
    first = asyncio.run(run_observed_input_batch(manager, max_checks=1))
    assert first["processed"] == 1
    assert manager.techniques == ["html_body", "html_body_svg"]
    cell = next(row for row in manager._engagement_brain["coverage_cells"]
                if row["test_type"] == "xss")
    assert cell["xss_techniques_attempted"] == ["html_body"]
    assert cell["xss_pending_techniques"][0] == "html_body_svg"
    second = asyncio.run(run_observed_input_batch(manager, max_checks=1))
    assert second["processed"] == 1
    assert manager.techniques == [
        "html_body", "html_body_svg", "html_body_svg", "html_attribute",
        "html_attribute_single", "js_single", "js_double",
    ]
    cell = next(row for row in manager._engagement_brain["coverage_cells"]
                if row["test_type"] == "xss")
    assert cell["xss_pending_techniques"] == []


def test_get_xss_followup_failure_retries_then_reaches_remaining_variants():
    class Manager:
        def __init__(self):
            brain = EngagementBrain(target="https://app.test")
            seed_parameter_coverage_cells(brain, [{
                "method": "GET", "host": "app.test", "path": "/search",
                "name": "term", "location": "query", "identity": "anonymous",
                "source": "browser_link", "testable": True,
            }])
            for cell in brain.coverage_cells:
                if cell["test_type"] == "sqli":
                    cell["status"] = "skipped"
            self._engagement_brain = brain.to_dict()
            self._capability_map = {"target": "https://app.test"}
            self.techniques = []
            self.failures_left = 1

        async def scoped_input_probe_assigned(self, coverage_cell_id, coverage_lease_id, technique):
            self.techniques.append(technique)
            if technique == "html_body_svg" and self.failures_left:
                self.failures_left -= 1
                return {"success": False, "error": "temporary_probe_error"}
            return {"success": True, "evidence_id": "receipt-" + technique,
                    "proof_confirmed": False,
                    "probe_result": {"reflection_contexts": []}}

    manager = Manager()
    first = asyncio.run(run_observed_input_batch(manager, max_checks=1))
    assert first["processed"] == 1
    assert manager.techniques == ["html_body", "html_body_svg"]
    cell = next(row for row in manager._engagement_brain["coverage_cells"]
                if row["test_type"] == "xss")
    assert cell["xss_pending_techniques"][0] == "html_body_svg"
    assert cell["xss_variant_failures"] == {"html_body_svg": 1}

    second = asyncio.run(run_observed_input_batch(manager, max_checks=1))
    assert second["processed"] == 1
    assert manager.techniques == [
        "html_body", "html_body_svg", "html_body_svg", "html_attribute",
        "html_attribute_single", "js_single", "js_double",
    ]
    cell = next(row for row in manager._engagement_brain["coverage_cells"]
                if row["test_type"] == "xss")
    assert cell["xss_pending_techniques"] == []
    assert cell["xss_variant_failures"] == {}
    assert cell["xss_techniques_attempted"] == [
        "html_body", "html_body_svg", "html_attribute", "html_attribute_single",
        "js_single", "js_double",
    ]


def test_get_xss_repeated_failure_is_recorded_without_stranding_other_variants():
    class Manager:
        def __init__(self):
            brain = EngagementBrain(target="https://app.test")
            seed_parameter_coverage_cells(brain, [{
                "method": "GET", "host": "app.test", "path": "/search",
                "name": "term", "location": "query", "identity": "anonymous",
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
            if technique == "html_body_svg":
                return {"success": False, "error": "persistent_probe_error"}
            return {"success": True, "evidence_id": "receipt-" + technique,
                    "proof_confirmed": False,
                    "probe_result": {"reflection_contexts": []}}

    manager = Manager()
    for _ in range(3):
        result = asyncio.run(run_observed_input_batch(manager, max_checks=1))
        assert result["processed"] == 1
    cell = next(row for row in manager._engagement_brain["coverage_cells"]
                if row["test_type"] == "xss")
    assert manager.techniques == [
        "html_body", "html_body_svg", "html_body_svg",
        "html_attribute", "html_attribute_single", "js_single", "js_double",
    ]
    assert cell["xss_pending_techniques"] == []
    assert cell["xss_variant_failures"] == {"html_body_svg": 2}
    assert cell["xss_unattempted_techniques"] == ["html_body_svg"]
    assert "html_body_svg" in cell["xss_variant_error"]
