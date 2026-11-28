"""Event-driven planner + parallel workers: scope, dedup, cancel, and stop rules."""

import asyncio
import json


from app.services.agent.hunt_engine import (
    HuntEngine, Intent, brain_overview, format_summary, parse_plan,
)

SCOPE = "https://shop.test"
SPECIALISTS = ["sqli", "xss", "explorer"]


def _plan_sequence(*rounds):
    """Return a planner callable that yields each round's JSON, then 'done'."""
    calls = {"n": 0, "prompts": []}

    async def plan(prompt):
        calls["prompts"].append(prompt)
        i = calls["n"]
        calls["n"] += 1
        if i < len(rounds):
            return json.dumps(rounds[i])
        return json.dumps({"done": True, "intents": []})

    plan.calls = calls
    return plan


def _worker(record, verdict="inconclusive"):
    async def run(intent):
        record.append(intent.id)
        await asyncio.sleep(0)
        return {"verdict": verdict, "summary": f"ran {intent.parameter}", "key_findings": []}
    return run


def _engine(plan, run_worker, **kw):
    opts = dict(
        plan=plan, run_worker=run_worker,
        overview=lambda intents: " ".join(f"{i.id}:{i.status}" for i in intents) or "state",
        in_scope=lambda url: url.startswith(SCOPE),
        specialists=SPECIALISTS, scope_label=SCOPE, objective="Assess " + SCOPE,
        workers=2, max_rounds=5, max_intents=10, max_seconds=30, debounce=0,
        planner_tick=0.2,
    )
    opts.update(kw)
    return HuntEngine(**opts)


def test_parse_plan_is_defensive():
    assert parse_plan("garbage") == {"done": False, "cancel": [], "intents": []}
    assert parse_plan('noise {"done": true, "intents": []} tail')["done"] is True
    big = {"done": False, "cancel": [], "intents": [{"title": str(i)} for i in range(9)]}
    assert len(parse_plan(json.dumps(big))["intents"]) == 4  # MAX_INTENTS_PER_ROUND


def test_runs_intents_and_reports_results():
    ran = []
    plan = _plan_sequence({"intents": [
        {"title": "SQLi on category", "specialist": "sqli",
         "target": f"{SCOPE}/catalog?category=Gin", "parameter": "category",
         "objective": "boolean true/false"},
        {"title": "Reflect on q", "specialist": "xss",
         "target": f"{SCOPE}/search?q=x", "parameter": "q", "objective": "reflection"},
    ]})
    summary = asyncio.run(_engine(plan, _worker(ran)).run())
    assert sorted(ran) == ["T1", "T2"]
    assert summary["by_status"].get("done") == 2
    assert summary["stop_reason"] == "planner_done"
    assert all(t["result"].startswith("ran ") for t in summary["tasks"])


def test_rejects_out_of_scope_and_unknown_specialist():
    plan = _plan_sequence({"intents": [
        {"title": "off", "specialist": "sqli", "target": "https://evil.test/x",
         "parameter": "p", "objective": "o"},
        {"title": "bad role", "specialist": "nuke", "target": f"{SCOPE}/a",
         "parameter": "p", "objective": "o"},
        {"title": "ok", "specialist": "sqli", "target": f"{SCOPE}/a", "parameter": "p",
         "objective": "o"},
    ]})
    ran = []
    summary = asyncio.run(_engine(plan, _worker(ran)).run())
    assert ran == ["T1"]
    reasons = {r["reason"] for r in summary["rejected"]}
    assert any("scope" in r for r in reasons) and any("specialist" in r for r in reasons)


def test_duplicate_tasks_are_dropped_across_rounds():
    dup = {"title": "SQLi", "specialist": "sqli", "target": f"{SCOPE}/a?id=1",
           "parameter": "id", "objective": "o"}
    # Round 2 cites T1's fact but names nothing new, so it is a plain repeat.
    plan = _plan_sequence({"intents": [dup]},
                          {"intents": [dict(dup, title="again", parent_ids=["F1"])]})
    ran = []
    summary = asyncio.run(_engine(plan, _worker(ran)).run())
    assert ran == ["T1"]
    assert any(r["reason"] == "duplicate of an existing task" for r in summary["rejected"])


def test_signal_can_spawn_a_follow_up_round():
    # Round 1 runs a first task; round 2 (planner saw its result) adds another.
    plan = _plan_sequence(
        {"intents": [{"title": "probe", "specialist": "sqli", "target": f"{SCOPE}/a?id=1",
                      "parameter": "id", "objective": "o"}]},
        {"intents": [{"title": "exploit", "specialist": "explorer", "target": f"{SCOPE}/a?id=1",
                      "parameter": "id", "objective": "dump", "parent_ids": ["F1"]}]},
    )
    ran = []
    summary = asyncio.run(_engine(plan, _worker(ran)).run())
    assert ran == ["T1", "T2"]
    assert summary["rounds"] >= 2


def test_planner_can_cancel_a_running_worker():
    started = asyncio.Event()

    async def slow_worker(intent):
        if intent.id == "T1":
            started.set()
            await asyncio.sleep(30)
        return {"verdict": "done", "summary": "fast"}

    async def plan(prompt):
        # First round starts T1; once it is running, cancel it and finish.
        if "T1" not in prompt:
            return json.dumps({"intents": [
                {"title": "slow", "specialist": "sqli", "target": f"{SCOPE}/a",
                 "parameter": "p", "objective": "o"}]})
        await started.wait()
        return json.dumps({"done": True, "cancel": ["T1"], "intents": []})

    summary = asyncio.run(_engine(plan, slow_worker, workers=1).run())
    statuses = {t["id"]: t["status"] for t in summary["tasks"]}
    assert statuses["T1"] == "cancelled"


def test_stop_request_ends_the_hunt():
    stop = {"v": False}
    plan = _plan_sequence({"intents": [
        {"title": "a", "specialist": "sqli", "target": f"{SCOPE}/a", "parameter": "p",
         "objective": "o"}]})

    async def worker(intent):
        stop["v"] = True  # operator stops mid-task
        return {"verdict": "done", "summary": "x"}

    summary = asyncio.run(_engine(plan, worker, should_stop=lambda: stop["v"]).run())
    assert summary["stop_reason"] == "stopped"


def test_max_intents_caps_total_work():
    def wave(start):
        return {"intents": [{"title": f"t{i}", "specialist": "sqli",
                             "target": f"{SCOPE}/a?id={i}", "parameter": f"id{i}",
                             "objective": "o", "parent_ids": ["F1"] if start else []}
                            for i in range(start, start + 4)]}
    # Distinct inputs each round, so only the cap (not dedup) can reject them.
    plan = _plan_sequence(wave(0), wave(4), wave(8))
    ran = []
    summary = asyncio.run(_engine(plan, _worker(ran), max_intents=5, max_rounds=5).run())
    assert len(ran) == 5
    assert any(r["reason"] == "task limit reached" for r in summary["rejected"])


def test_a_failing_worker_does_not_stop_the_hunt():
    async def worker(intent):
        if intent.id == "T1":
            raise RuntimeError("boom")
        return {"verdict": "done", "summary": "ok"}

    plan = _plan_sequence({"intents": [
        {"title": "a", "specialist": "sqli", "target": f"{SCOPE}/a", "parameter": "p", "objective": "o"},
        {"title": "b", "specialist": "xss", "target": f"{SCOPE}/b", "parameter": "q", "objective": "o"},
    ]})
    summary = asyncio.run(_engine(plan, worker).run())
    statuses = {t["id"]: t["status"] for t in summary["tasks"]}
    assert statuses == {"T1": "failed", "T2": "done"}


def test_overview_surfaces_signals_and_candidates():
    brain = {
        "coverage_cells": [
            {"path": "/catalog", "method": "GET", "parameter": "query:category",
             "test_type": "sqli", "first_pass_outcome": "proof_signal",
             "first_pass_reason": "boolean pair held"},
            {"path": "/x", "first_pass_outcome": "tested_clean"},
        ],
        "candidates": [{"id": "c1", "title": "SQLi", "vulnerability_class": "sql_injection",
                        "target": f"{SCOPE}/catalog", "status": "confirmed",
                        "verifier_summary": "reproduced"}],
    }
    text = brain_overview(brain, [Intent("T1", "t", "sqli", f"{SCOPE}/a", "p", "o", 0)])
    data = json.loads(text)
    assert data["first_pass_signals"][0]["outcome"] == "proof_signal"
    assert data["inputs_tested_clean"] == 1
    assert data["candidates"][0]["status"] == "confirmed"
    assert data["tasks"][0]["id"] == "T1"


def test_format_summary_names_the_verifier():
    summary = {"rounds": 1, "tasks": [{"id": "T1", "status": "done", "verdict": "",
               "specialist": "sqli", "title": "x"}], "by_status": {"done": 1},
               "rejected": [], "stop_reason": "idle"}
    text = format_summary(summary)
    assert "independent verifier" in text and "T1" in text


# -- facts, lineage, retries, todo --------------------------------------------

from app.services.agent.hunt_engine import facts_from_brain, worker_mission  # noqa: E402

SIGNAL_BRAIN = {"coverage_cells": [{
    "id": "cell-cat", "path": "/catalog", "method": "GET", "parameter": "query:category",
    "test_type": "sqli", "first_pass_outcome": "proof_signal",
    "first_pass_reason": "true/false product counts differ",
    "first_pass_evidence_id": "ev-pair", "url": f"{SCOPE}/catalog?category=Gin",
}]}


def _sqli_task(**extra):
    row = {"title": "SQLi on category", "specialist": "sqli",
           "target": f"{SCOPE}/catalog?category=Gin", "parameter": "category",
           "objective": "confirm boolean SQLi", "parent_ids": ["F1"]}
    row.update(extra)
    return row


def test_facts_from_brain_seed_signals_and_candidates():
    brain = dict(SIGNAL_BRAIN, candidates=[{"id": "c1", "vulnerability_class": "sql_injection",
                                            "title": "SQLi", "status": "rejected",
                                            "verifier_summary": "did not reproduce"}])
    rows = facts_from_brain(brain)
    assert rows[0]["confidence"] == "observed" and rows[0]["evidence_ids"] == ["ev-pair"]
    assert "category" in rows[0]["summary"]
    assert rows[1]["negative"] is True and "did not reproduce" in rows[1]["summary"]


def test_seeded_facts_reach_the_planner_and_tasks_must_cite_them():
    plan = _plan_sequence({"intents": [
        _sqli_task(),
        dict(_sqli_task(parameter="other", target=f"{SCOPE}/x?other=1"), parent_ids=[]),
        dict(_sqli_task(parameter="ghost", target=f"{SCOPE}/y?ghost=1"), parent_ids=["F99"]),
    ]})
    ran = []
    engine = _engine(plan, _worker(ran), seed_facts=lambda: facts_from_brain(SIGNAL_BRAIN))
    summary = asyncio.run(engine.run())
    assert "F1" in plan.calls["prompts"][0] and "proof signal" in plan.calls["prompts"][0]
    assert ran == ["T1"]
    reasons = {r["reason"] for r in summary["rejected"]}
    assert "task cites no existing fact" in reasons
    assert "parent_ids name facts that do not exist" in reasons
    assert summary["tasks"][0]["parents"] == ["F1"]


def test_seeding_twice_adds_no_duplicate_facts():
    engine = _engine(_plan_sequence(), _worker([]), seed_facts=lambda: facts_from_brain(SIGNAL_BRAIN))
    engine._sync_facts()
    engine._sync_facts()
    assert [f.id for f in engine.facts] == ["F1"]


def test_worker_facts_leads_and_lineage_are_recorded():
    async def worker(intent):
        return {"verdict": "proven", "summary": "boolean SQLi confirmed",
                "facts": [{"summary": "category is injectable (boolean)", "confidence": "observed",
                           "evidence_ids": ["ev-real", "ev-made-up"]}],
                "leads": [{"method": "GET", "url": f"{SCOPE}/admin", "why": "linked in error",
                           "evidence_ids": ["ev-real"]}]}

    plan = _plan_sequence({"intents": [_sqli_task()]})
    engine = _engine(plan, worker, seed_facts=lambda: facts_from_brain(SIGNAL_BRAIN),
                     known_evidence=lambda i: i == "ev-real")
    summary = asyncio.run(engine.run())
    facts = {f["id"]: f for f in summary["facts"]}
    assert facts["F2"]["from_task"] == "T1" and facts["F2"]["evidence_ids"] == ["ev-real"]
    assert facts["F3"]["summary"].startswith("Lead: GET")
    assert summary["tasks"][0]["yields"] == ["F2", "F3"]
    # The second planning round sees the new facts and where they came from.
    assert '"from_task": "T1"' in plan.calls["prompts"][1]


def test_unlabelled_worker_result_becomes_an_inferred_fact():
    plan = _plan_sequence({"intents": [_sqli_task()]})
    engine = _engine(plan, _worker([], verdict="killed"),
                     seed_facts=lambda: facts_from_brain(SIGNAL_BRAIN))
    summary = asyncio.run(engine.run())
    fact = summary["facts"][-1]
    assert fact["negative"] is True and fact["confidence"] == "inferred"


def _retry_engine(worker_result, second_round):
    async def worker(intent):
        return worker_result(intent)

    plan = _plan_sequence({"intents": [_sqli_task()]}, {"intents": second_round})
    return _engine(plan, worker, seed_facts=lambda: facts_from_brain(SIGNAL_BRAIN))


def test_retry_needs_a_new_fact_and_a_stated_difference():
    def result(intent):
        return {"verdict": "inconclusive", "summary": "x",
                "facts": [{"summary": f"{intent.id} saw a WAF block", "confidence": "observed"}]}

    # No differs_by: plain duplicate. differs_by but only the old fact: refused.
    engine = _retry_engine(result, [_sqli_task(title="again"),
                                    _sqli_task(title="again 2", differs_by="double URL encoding")])
    summary = asyncio.run(engine.run())
    reasons = [r["reason"] for r in summary["rejected"]]
    assert "duplicate of an existing task" in reasons
    assert "retry names no fact recorded after the earlier attempt" in reasons

    # Citing the fact T1 produced (recorded after it started) makes it a real retry.
    engine = _retry_engine(result, [_sqli_task(title="bypass WAF", parent_ids=["F2"],
                                               differs_by="double URL encoding past the WAF")])
    summary = asyncio.run(engine.run())
    retry = summary["tasks"][1]
    assert retry["retry_of"] == "T1" and retry["status"] == "done"


def test_inferred_negative_earns_one_recheck_only():
    def result(intent):
        return {"verdict": "killed", "summary": "x",
                "facts": [{"summary": "not injectable (one payload)", "negative": True,
                           "confidence": "inferred"}]}

    async def worker(intent):
        return result(intent)

    recheck = _sqli_task(title="re-check", differs_by="time-based variant")
    plan = _plan_sequence({"intents": [_sqli_task()]}, {"intents": [recheck]},
                          {"intents": [dict(recheck, title="third", parent_ids=["F3"])]})
    engine = _engine(plan, worker, seed_facts=lambda: facts_from_brain(SIGNAL_BRAIN))
    summary = asyncio.run(engine.run())
    assert [t["id"] for t in summary["tasks"]] == ["T1", "T2"]
    assert any(r["reason"] == "route already retried once" for r in summary["rejected"])


def test_planner_todo_survives_between_rounds():
    plan = _plan_sequence(
        {"todo": [{"step": "1 confirm SQLi on category", "done": False},
                  {"step": "2 enumerate columns", "done": False}],
         "intents": [_sqli_task()]},
        {"todo": [{"step": "1 confirm SQLi on category", "done": True},
                  {"step": "2 enumerate columns", "done": False}], "intents": []},
    )
    engine = _engine(plan, _worker([]), seed_facts=lambda: facts_from_brain(SIGNAL_BRAIN))
    summary = asyncio.run(engine.run())
    assert "[ ] 2 enumerate columns" in plan.calls["prompts"][1]
    assert summary["todo"][0]["done"] is True


def test_worker_mission_carries_parent_facts_and_rules():
    engine = _engine(_plan_sequence(), _worker([]), seed_facts=lambda: facts_from_brain(SIGNAL_BRAIN))
    engine._sync_facts()
    intent = Intent("T1", "SQLi on category", "sqli", f"{SCOPE}/catalog?category=Gin",
                    "category", "confirm", 1, parents=["F1"])
    text = worker_mission(intent, engine.facts)
    assert "F1 [observed]" in text and "evidence=ev-pair" in text
    assert "Do only this task" in text and '"facts"' in text
    assert "inferred" in text


# -- confirmed inputs are done -------------------------------------------------

from app.services.agent.hunt_engine import confirmed_inputs  # noqa: E402

CONFIRMED_BRAIN = {"candidates": [
    {"id": "c1", "status": "confirmed", "vulnerability_class": "sql_injection",
     "target": f"{SCOPE}/catalog?category=Gin"},
    {"id": "c2", "status": "pending", "vulnerability_class": "xss",
     "target": f"{SCOPE}/blog/?search=x"},
]}


def test_confirmed_inputs_come_from_confirmed_candidates_only():
    rows = confirmed_inputs(CONFIRMED_BRAIN)
    assert rows == [{"path": "/catalog", "parameter": "category", "class": "sql_injection"}]


def test_planner_cannot_send_more_work_to_a_confirmed_input():
    plan = _plan_sequence({"intents": [
        _sqli_task(title="dump tables", parameter="category"),
        _sqli_task(title="explore it", specialist="explorer", parameter="query:category"),
        _sqli_task(title="xss on same input", specialist="xss", parameter="category"),
        _sqli_task(title="other input", target=f"{SCOPE}/catalog?sort=price", parameter="sort"),
    ]})
    ran = []
    engine = _engine(plan, _worker(ran), seed_facts=lambda: facts_from_brain(SIGNAL_BRAIN),
                     confirmed=lambda: confirmed_inputs(CONFIRMED_BRAIN))
    summary = asyncio.run(engine.run())
    titles = {t["id"]: t["title"] for t in summary["tasks"]}
    assert sorted(titles.values()) == ["other input", "xss on same input"]
    blocked = [r for r in summary["rejected"]
               if r["reason"] == "input already has a confirmed finding of this class"]
    assert {r["title"] for r in blocked} == {"dump tables", "explore it"}
