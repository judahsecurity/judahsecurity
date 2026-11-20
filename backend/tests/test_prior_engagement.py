"""Read-only reuse of the previous engagement against the same target."""

import json
import os
import time

import pytest

from app.services.agent import prior_engagement as prior
from app.services.agent import run_snapshot
from app.services.agent.tools import (
    ASMToolsManager,
    current_organization_id,
    current_seed_target,
    current_session_id,
)

ORG = 4321


def _save(tmp_dir, session, target, *, age=0.0, hypotheses=(), surfaces=(), goals=()):
    payload = {
        "schema_version": 1, "saved_at": time.time() - age,
        "capability_map": {"target": target, "scope": target},
        "engagement_brain": {
            "target": target,
            "hypotheses": list(hypotheses),
            "surfaces": list(surfaces),
            "candidates": [{"title": "IDOR on invoices", "status": "confirmed", "finding_id": "77"}],
            "engagement_goals": list(goals),
        },
        "original_objective": f"Assess {target}",
    }
    path = tmp_dir / f"{ORG}_{session}.json"
    path.write_text(json.dumps(payload))
    os.utime(path, (time.time() - age, time.time() - age))


def _card(title, status):
    return {"id": title, "title": title, "assumption": "a", "test": "t", "pass_criteria": "p",
            "kill_criteria": "k", "specialist": "xss", "status": status, "evidence": "ev"}


@pytest.fixture
def snapshots(tmp_path, monkeypatch):
    monkeypatch.setattr(run_snapshot, "_DIR", tmp_path)
    return tmp_path


def test_finds_the_latest_run_on_the_same_origin_only(snapshots):
    _save(snapshots, "old-shop", "https://shop.example.test", age=500)
    _save(snapshots, "new-shop", "https://shop.example.test/", age=10,
          hypotheses=[_card("Reflected XSS in q", "killed"), _card("IDOR", "proven")])
    _save(snapshots, "other", "https://other.example.test", age=1)
    _save(snapshots, "current", "https://shop.example.test", age=0)

    session, snapshot = prior.find_prior_snapshot(ORG, "current", "https://shop.example.test/login")
    assert session == "new-shop"
    summary = prior.summarize(snapshot)
    assert [c["title"] for c in summary["tested_clean"]] == ["Reflected XSS in q"]
    assert [c["title"] for c in summary["proven"]] == ["IDOR"]
    assert summary["confirmed_candidates"] == [{"title": "IDOR on invoices", "finding_id": "77"}]

    assert prior.find_prior_snapshot(ORG, "current", "https://nothing.example.test") == ("", {})
    assert prior.find_prior_snapshot(ORG + 1, "current", "https://shop.example.test") == ("", {})


def test_surfaces_are_paths_on_the_same_origin(snapshots):
    _save(snapshots, "prev", "https://shop.example.test", surfaces=[
        {"host": "shop.example.test", "method": "GET", "path": "/api/orders", "auth_gated": True},
        {"host": "cdn.example.test", "method": "GET", "path": "/x.js"},
        {"host": "shop.example.test", "method": "POST", "path": "//evil"},
    ])
    _, snapshot = prior.find_prior_snapshot(ORG, "current", "https://shop.example.test")
    assert prior.surfaces(snapshot, "https://shop.example.test") == [
        "https://shop.example.test/api/orders"]
    assert prior.summarize(snapshot)["auth_gated_surfaces"] == ["GET /api/orders"]


@pytest.mark.asyncio
async def test_tool_is_read_only_and_reports_nothing_without_history(snapshots, monkeypatch):
    org = current_organization_id.set(ORG)
    session = current_session_id.set("current")
    seed = current_seed_target.set("https://shop.example.test")
    try:
        manager = ASMToolsManager()
        monkeypatch.setattr(prior, "prior_findings", lambda org_id, target, limit=25: [])
        empty = json.loads(await manager.prior_engagement())
        assert empty["found"] is False

        _save(snapshots, "prev", "https://shop.example.test",
              hypotheses=[_card("SQLi in id", "killed")],
              goals=[{"id": "goal-1", "text": "Read another tenant's invoice", "status": "met"}])
        monkeypatch.setattr(prior, "prior_findings", lambda org_id, target, limit=25: [
            {"id": 77, "title": "IDOR on invoices", "status": "resolved"}])
        before = manager._engagement_brain
        brief = json.loads(await manager.prior_engagement("brief"))
        assert brief["found"] and brief["read_only"] and brief["prior_session"] == "prev"
        assert brief["findings"][0]["status"] == "resolved"
        assert brief["summary"]["goals"] == [{"text": "Read another tenant's invoice", "status": "met"}]
        assert manager._engagement_brain == before  # nothing written to this run
        listed = json.loads(await manager.prior_engagement("surfaces"))
        assert listed["surfaces"] == [] and "ingest_urls_into_map" in listed["next"]
    finally:
        current_seed_target.reset(seed)
        current_session_id.reset(session)
        current_organization_id.reset(org)
