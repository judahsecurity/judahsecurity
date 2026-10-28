"""Observed input work should survive mapping upgrades and retain request context."""

import json
from urllib.parse import parse_qs, urlsplit

import pytest

from app.services.agent.assessment_scope import register_scope
from app.services.agent.coverage_cells import (
    claim_coverage_cell_leases,
    seed_parameter_coverage_cells,
)
from app.services.agent.engagement_brain import EngagementBrain
from app.services.agent.observed_input_batch import (
    pending_first_pass_cells, run_observed_input_batch,
)
from app.services.agent.parameter_inventory import collect_parameter_inventory
from app.services.agent.tools import ASMToolsManager


def _input(path, name, *, source="observed_form", capture="", method="POST",
           location="body_form"):
    return {"method": method, "host": "app.test", "path": path,
            "name": name, "location": location, "identity": "anonymous",
            "source": source, "artifact_id": capture, "testable": True}


def test_form_and_private_capture_are_one_replayable_input():
    cmap = {"target": "https://app.test", "forms": [
        {"method": "POST", "action": "/feedback", "fields": [{"name": "message"}]},
    ], "parameter_inventory": [
        _input("/feedback", "message", source="browser_traffic", capture="private-1"),
    ]}
    rows = [row for row in collect_parameter_inventory(cmap)
            if row["path"] == "/feedback" and row["name"] == "message"]
    assert len(rows) == 1
    assert rows[0]["location"] == "body_form"
    assert rows[0]["source"] == "browser_traffic"
    assert rows[0]["artifact_id"] == "private-1"


def test_private_capture_replaces_public_sample_for_same_input():
    cmap = {"target": "https://app.test", "api_samples": [
        {"method": "GET", "url": "https://app.test/items?term=ordinary",
         "artifact_id": "public-sample"},
    ], "parameter_inventory": [
        _input("/items", "term", method="GET", location="query",
               source="browser_traffic", capture="private-1"),
    ]}
    row = next(row for row in collect_parameter_inventory(cmap)
               if row["path"] == "/items" and row["name"] == "term")
    assert row["source"] == "browser_traffic"
    assert row["artifact_id"] == "private-1"


def test_new_private_capture_requeues_only_unprobed_checks():
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [_input("/feedback", "message")])
    before = {row["id"] for row in brain.coverage_cells}
    xss = next(row for row in brain.coverage_cells if row["test_type"] == "xss")
    sqli = next(row for row in brain.coverage_cells if row["test_type"] == "sqli")
    xss.update(status="inconclusive", first_pass_outcome="unattempted",
               first_pass_reason="No private request", attempts=1)
    sqli.update(status="tested_clean", first_pass_outcome="tested_clean",
                first_pass_evidence_id="proof-1")

    seed_parameter_coverage_cells(brain, [
        _input("/feedback", "message", source="browser_traffic", capture="private-1"),
    ])
    assert {row["id"] for row in brain.coverage_cells} == before
    assert xss["capture_id"] == "private-1"
    assert xss["observation_source"] == "browser_traffic"
    assert xss["status"] == "untested"
    assert "first_pass_outcome" not in xss
    assert [row["id"] for row in pending_first_pass_cells(brain)] == [xss["id"]]
    assert sqli["status"] == "tested_clean"
    assert sqli["capture_id"] != "private-1"


def test_verified_input_does_not_preempt_unseen_paths_in_first_pass():
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [
        _input("/items", "filter", method="GET", location="query", source="browser_link"),
        _input("/items", "extra", method="GET", location="query", source="browser_link"),
        _input("/search", "searchTerm", method="GET", location="query", source="browser_link"),
    ])
    proven = next(row for row in brain.coverage_cells
                  if row["path"] == "/items" and row["parameter"] == "query:filter"
                  and row["test_type"] == "sqli")
    proven.update(status="finding", first_pass_outcome="proof_signal")
    brain.candidates = [{"id": "candidate-1", "coverage_cell_id": proven["id"],
                         "status": "confirmed", "finding_id": "finding-1"}]
    pending = pending_first_pass_cells(brain)
    assert pending[0]["path"] == "/search"
    pending[0]["first_pass_outcome"] = "inconclusive"
    assert pending_first_pass_cells(brain)[0]["parameter"] == "query:extra"


def test_confirmed_xss_prioritizes_other_classes_on_same_path():
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [
        _input("/items", "term", method="GET", location="query", source="browser_link"),
        _input("/search", "category", method="GET", location="query", source="browser_link"),
    ])
    proven = next(row for row in brain.coverage_cells
                  if row["path"] == "/items" and row["test_type"] == "xss")
    proven["status"] = "finding"
    brain.candidates = [{"id": "candidate-1", "coverage_cell_id": proven["id"],
                         "status": "confirmed", "finding_id": "finding-1"}]
    lease = claim_coverage_cell_leases(brain, ["sqli"])["sqli"]
    selected = next(row for row in brain.coverage_cells
                    if row["id"] == lease.coverage_cell_id)
    assert selected["path"] == "/items"


@pytest.mark.asyncio
async def test_captured_post_form_is_dispatched_for_both_input_classes():
    class Manager:
        def __init__(self):
            brain = EngagementBrain(target="https://app.test")
            seed_parameter_coverage_cells(brain, [
                _input("/feedback", "message", source="browser_traffic", capture="private-1"),
            ])
            self._engagement_brain = brain.to_dict()
            self._capability_map = {"target": "https://app.test"}
            self._scoped_body_replay_paths = {"/feedback"}
            self.calls = []

        async def execute(self, name, kwargs):
            self.calls.append(name)
            if name == "scoped_assessment_probe_assigned":
                return {"output": {"success": True,
                        "service_artifact_ids": ["replay-1"],
                        "probe_result": {"proof_confirmed": False}}}
            return {"output": json.dumps({"error": "controls incomplete"})}

    manager = Manager()
    result = await run_observed_input_batch(manager, max_checks=2)
    assert result["processed"] == 2 and result["remaining"] == 0
    assert manager.calls.count("scoped_assessment_probe_assigned") == 2
    assert result["funnel"]["by_class"]["sqli"]["probed"] == 1
    assert result["funnel"]["by_class"]["xss"]["probed"] == 1


@pytest.mark.asyncio
async def test_assigned_xss_replays_observed_query_context(monkeypatch):
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [
        _input("/items", "term", method="GET", location="query", source="browser_link"),
    ])
    lease = claim_coverage_cell_leases(brain, ["xss"])["xss"]
    manager = ASMToolsManager()
    manager._fallback_target = "https://app.test"
    manager._capability_map = {"target": "https://app.test"}
    manager._scoped_link_baselines = {"anonymous": [
        "https://app.test/items?sort=recent&term=ordinary&page=2",
    ]}
    manager._engagement_brain = brain.to_dict()
    register_scope(manager, "app.test")
    sent = []

    async def fake_browser(operation, template, identity):
        sent.append((operation, template, identity))
        return json.dumps({"evidence_id": f"xss-proof-{len(sent)}", "executed": False,
                           "reflection_contexts": ["html_text"],
                           "reflection_observations": [
                               {"context": "html_text", "representation": "literal_markup_text"},
                           ]})

    monkeypatch.setattr(manager, "scoped_browser_assessment", fake_browser)
    result = await manager.scoped_input_probe_assigned(lease.coverage_cell_id, lease.id)
    assert result["success"]
    assert result["probe_result"]["request_context"] == "browser_link"
    operation, template, identity = sent[0]
    assert (operation, identity) == ("check_xss", "anonymous")
    query = parse_qs(urlsplit(template).query)
    assert query["sort"] == ["recent"] and query["page"] == ["2"]
    assert "__PROWL_NONCE__" in query["term"][0]
    assert result["xss_trace"]["render_observations"][0]["representation"] == "literal_markup_text"
    assert result["xss_trace"]["next_tests"][0] == {
        "technique": "html_body_svg", "variant": "base",
    }
    variant = await manager.scoped_input_probe_assigned(
        lease.coverage_cell_id, lease.id, technique="html_body", variant="mixed_case",
    )
    assert variant["success"] is True and "<ImG" in parse_qs(urlsplit(sent[1][1]).query)["term"][0]
    repeated = await manager.scoped_input_probe_assigned(
        lease.coverage_cell_id, lease.id, technique="html_body", variant="mixed_case",
    )
    assert repeated["error"] == "technique_already_attempted"


def test_manual_specialist_leases_untouched_input_before_positive_receipt():
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [
        _input("/catalog", "category", method="GET", location="query",
               source="browser_link"),
        _input("/search", "searchTerm", method="GET", location="query",
               source="browser_link"),
    ])
    proven = next(row for row in brain.coverage_cells
                  if row["test_type"] == "sqli" and row["path"] == "/catalog")
    untouched = next(row for row in brain.coverage_cells
                     if row["test_type"] == "sqli" and row["path"] == "/search")
    proven.update(status="in_focus", first_pass_outcome="proof_signal",
                  candidate_id="candidate-1", attempts=1)
    lease = claim_coverage_cell_leases(
        brain, ["sqli"], allowed_sources=frozenset({"parameter_inventory"}),
        allowed_test_types=frozenset({"sqli"}),
    )["sqli"]
    assert lease.coverage_cell_id == untouched["id"]
