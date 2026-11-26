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
    plan = _plan_sequence({"intents": [dup]}, {"intents": [dict(dup, title="again")]})
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
                      "parameter": "id", "objective": "dump"}]},
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
                             "objective": "o"} for i in range(start, start + 4)]}
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
