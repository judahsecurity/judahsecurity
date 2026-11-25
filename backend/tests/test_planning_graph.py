"""Facts and intents with lineage on the engagement brain."""

import asyncio
import json

import pytest

from app.services.agent import planning_graph as g
from app.services.agent.assessment_scope import register_scope
from app.services.agent.engagement_brain import EngagementBrain, engagement_brain_from_dict
from app.services.agent.tools import ASMToolsManager

T = "https://app.example.com"


def _brain():
    return EngagementBrain(target=T)


def test_origin_fact_is_the_root_and_facts_default_to_it():
    brain = _brain()
    fact = g.record_fact(brain, kind="observation", summary="Login form at /login")
    origin = g.get_fact(brain, fact["parents"][0])
    assert origin["kind"] == "origin" and origin["target"] == T
    again = g.record_fact(brain, kind="observation", summary="Login form at /login")
    assert again["id"] == fact["id"] and len(brain.facts) == 2


def test_fact_needs_known_parents_and_a_valid_kind():
    brain = _brain()
    with pytest.raises(g.LineageError):
        g.record_fact(brain, kind="observation", summary="x", parents=["fact-nope"])
    with pytest.raises(ValueError):
        g.record_fact(brain, kind="origin", summary="x")
    with pytest.raises(ValueError):
        g.record_fact(brain, kind="rumour", summary="x")
    with pytest.raises(g.LineageError):
        g.record_fact(EngagementBrain(), kind="observation", summary="no target, no parent")


def test_intent_lineage_rules():
    brain = _brain()
    fact = g.record_fact(brain, kind="observation", summary="orders API takes id")
    with pytest.raises(g.LineageError):
        g.add_intent(brain, objective="", test_type="authz", target=T + "/api/orders/1", parents=[])
    with pytest.raises(g.LineageError):
        g.add_intent(brain, objective="", test_type="authz", target=T + "/api/orders/1",
                     parents=["fact-missing"])
    intent = g.add_intent(brain, objective="IDOR on order id", test_type="authz",
                          target=T + "/api/orders/1", parameter="id", location="path",
                          parents=[fact["id"]], link_coverage=False)
    with pytest.raises(g.LineageError):  # intents cannot hang off intents only
        g.add_intent(brain, objective="", test_type="sqli", target=T + "/api/orders/1",
                     parents=[intent["id"]], link_coverage=False)
    brain.candidates.append({"id": "cand-1", "title": "IDOR"})
    chained = g.add_intent(brain, objective="chain", test_type="ssrf", target=T + "/api/fetch",
                           parents=["cand-1"], link_coverage=False)
    assert chained["parents"] == ["cand-1"]
    same = g.add_intent(brain, objective="again", test_type="authz", target=T + "/api/orders/1",
                        parameter="id", location="path", parents=["cand-1"], link_coverage=False)
    assert same["id"] == intent["id"] and same["parents"] == [fact["id"], "cand-1"]
    with pytest.raises(ValueError):
        g.add_intent(brain, objective="", test_type="xss", target="/relative", parents=[fact["id"]])
    with pytest.raises(ValueError):
        g.add_intent(brain, objective="", test_type="xss", target=T, parents=[fact["id"]],
                     location="smoke-signal")


def test_claim_and_complete_need_the_claimer_and_result_facts():
    brain = _brain()
    fact = g.record_fact(brain, kind="observation", summary="search reflects q")
    intent = g.add_intent(brain, objective="", test_type="xss", target=T + "/search",
                          parameter="q", location="query", parents=[fact["id"]], link_coverage=False)
    claimed = g.claim_intent(brain, intent["id"], "xss")
    assert claimed["status"] == "claimed"
    with pytest.raises(ValueError):
        g.claim_intent(brain, intent["id"], "injection")
    with pytest.raises(ValueError):
        g.complete_intent(brain, intent["id"], "injection", result_facts=[fact["id"]])
    with pytest.raises(g.LineageError):
        g.complete_intent(brain, intent["id"], "xss", result_facts=[])
    result = g.record_fact(brain, kind="evidence", summary="payload rendered", parents=[intent["id"]],
                           evidence_ids=["ev-1"])
    done = g.complete_intent(brain, intent["id"], "xss", result_facts=[result["id"]])
    assert done["status"] == "done" and done["result_facts"] == [result["id"]]
    assert [step["id"] for step in g.lineage(brain, result["id"])][:2] == [intent["id"], fact["id"]]
    blocked_src = g.add_intent(brain, objective="", test_type="sqli", target=T + "/search",
                               parameter="q", location="query", parents=[fact["id"]], link_coverage=False)
    g.claim_intent(brain, blocked_src["id"], "injection")
    assert g.complete_intent(brain, blocked_src["id"], "injection", result_facts=[],
                             status="blocked")["status"] == "blocked"


def test_intent_creates_a_leaseable_coverage_cell_for_unobserved_inputs():
    brain = _brain()
    fact = g.record_fact(brain, kind="operator", summary="Operator: test X-Forwarded-Host header")
    intent = g.add_intent(brain, objective="header injection", test_type="crlf",
                          target=T + "/reset", parameter="X-Forwarded-Host", location="header",
                          method="POST", parents=[fact["id"]], created_by="operator")
    assert intent["coverage_cell_id"]
    cell = next(c for c in brain.coverage_cells if c["id"] == intent["coverage_cell_id"])
    assert cell["status"] == "untested" and cell["test_type"] == "crlf"
    assert cell["parameter"].endswith("X-Forwarded-Host") and cell["method"] == "POST"


def test_round_trip_through_the_brain_dict_and_old_snapshots():
    brain = _brain()
    fact = g.record_fact(brain, kind="observation", summary="x")
    g.add_intent(brain, objective="", test_type="xss", target=T + "/a", parents=[fact["id"]],
                 link_coverage=False)
    restored = engagement_brain_from_dict(brain.to_dict())
    assert restored.facts == brain.facts and restored.intents == brain.intents
    old = engagement_brain_from_dict({"target": T})
    assert old.facts == [] and old.intents == []


def test_overview_reports_active_work_with_lineage():
    brain = _brain()
    fact = g.record_fact(brain, kind="observation", summary="x")
    g.add_intent(brain, objective="", test_type="xss", target=T + "/a", parents=[fact["id"]],
                 link_coverage=False)
    view = g.overview(brain)
    assert view["facts"] == 2 and view["intents"] == {"open": 1}
    assert view["active_intents"][0]["lineage"][0] == fact["id"]


def test_bounds_drop_closed_intents_first(monkeypatch):
    monkeypatch.setattr(g, "MAX_INTENTS", 3)
    brain = _brain()
    fact = g.record_fact(brain, kind="observation", summary="x")
    ids = [g.add_intent(brain, objective="", test_type="xss", target=f"{T}/p{i}",
                        parents=[fact["id"]], link_coverage=False)["id"] for i in range(3)]
    g.claim_intent(brain, ids[1], "w")
    g.complete_intent(brain, ids[1], "w", result_facts=[fact["id"]])
    g.add_intent(brain, objective="", test_type="xss", target=f"{T}/p9", parents=[fact["id"]],
                 link_coverage=False)
    remaining = [i["id"] for i in brain.intents]
    assert ids[1] not in remaining and ids[0] in remaining and len(remaining) == 3


# ---------------------------------------------------------------- tools

def _manager():
    manager = ASMToolsManager()
    manager._engagement_brain = {"target": T}
    register_scope(manager, T)
    return manager


def test_tools_enforce_scope_and_lineage_and_persist():
    manager = _manager()
    overview = json.loads(asyncio.run(manager.graph_overview()))
    assert overview["facts"] == 1
    origin = manager._engagement_brain["facts"][0]["id"]
    out = json.loads(asyncio.run(manager.add_intent(test_type="xss", target="https://evil.example.net/x",
                                                    parents=[origin])))
    assert "out of scope" in out["error"]
    out = json.loads(asyncio.run(manager.add_intent(test_type="xss", target=T + "/x", parents=[])))
    assert "parent" in out["error"]
    intent = json.loads(asyncio.run(manager.add_intent(test_type="xss", target=T + "/x?q=1",
                                                       parents=origin, parameter="q",
                                                       location="query")))["intent"]
    assert intent["created_by"] == "agent" and intent["coverage_cell_id"]
    assert json.loads(asyncio.run(manager.claim_intent(intent["id"], worker="xss")))["intent"]["status"] == "claimed"
    fact = json.loads(asyncio.run(manager.record_fact(kind="evidence", summary="no reflection",
                                                      parents=[intent["id"]])))["fact"]
    done = json.loads(asyncio.run(manager.complete_intent(intent["id"], result_facts=fact["id"],
                                                          worker="xss")))["intent"]
    assert done["status"] == "done"
    assert manager._engagement_brain["intents"][0]["status"] == "done"


def test_specialists_work_intents_but_only_the_planner_adds_them():
    from app.services.agent.fireteam_service import DEFAULT_SPECIALISTS

    workers = [p for p in DEFAULT_SPECIALISTS if "submit_finding_candidate" in p.allowed_tools]
    assert workers
    for profile in workers:
        assert {"graph_overview", "record_fact", "claim_intent", "complete_intent"} <= set(profile.allowed_tools)
    assert not any("add_intent" in p.allowed_tools for p in DEFAULT_SPECIALISTS)
