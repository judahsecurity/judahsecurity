"""Durable agent test coverage: persist cells, inherit them, summarise per asset."""

from datetime import datetime, timedelta

import pytest

from app.services.agent.coverage_cells import _new_cell
from app.services.agent.engagement_brain import EngagementBrain
from app.services.agent import test_coverage_store as store


@pytest.fixture
def db():
    from sqlalchemy import Column, MetaData, Table, create_engine
    from sqlalchemy.orm import sessionmaker

    import app.models  # noqa: F401
    import app.models.business_application  # noqa: F401
    import app.models.org_role  # noqa: F401
    from app.db.database import Base

    from sqlalchemy.pool import StaticPool

    # One shared connection usable from TestClient's worker thread.
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    md = MetaData()
    # Bare copies (names, types, keys) so only these tables are needed.
    for name in ("assets", "agent_test_coverage", "vulnerabilities"):
        src = Base.metadata.tables[name]
        Table(name, md, *[Column(c.name, c.type, primary_key=c.primary_key) for c in src.columns])
    md.create_all(engine)
    session = sessionmaker(bind=engine)()
    store._FINGERPRINTS.clear()
    yield session
    session.close()


def _asset(db, value, org=1):
    from app.models.asset import Asset, AssetType

    asset = Asset(name=value, value=value, asset_type=AssetType.SUBDOMAIN, organization_id=org)
    db.add(asset)
    db.commit()
    return asset


def _brain(*cells):
    brain = EngagementBrain()
    for status, extra in cells:
        cell = _new_cell(brain, method="GET", path=extra.pop("path", "/search"), host=extra.pop("host", "app.example.com"),
                         parameter=extra.pop("parameter", "q"), test_type=extra.pop("test_type", "sqli"),
                         status=status, **extra)
        brain.coverage_cells.append(cell)
    return brain


def test_outcome_mapping():
    assert store.outcome_for({"status": "finding"}) == "reported"
    assert store.outcome_for({"status": "tested_clean"}) == "no_issue_found"
    assert store.outcome_for({"status": "tested_clean", "candidate_id": "c1"}) == "ruled_out"
    assert store.outcome_for({"status": "skipped"}) == "not_applicable"
    assert store.outcome_for({"status": "inconclusive"}) == "needs_follow_up"
    assert store.outcome_for({"status": "blocked"}) == "needs_follow_up"
    assert store.outcome_for({"status": "leased"}) == "in_progress"
    assert store.outcome_for({"status": "untested"}) == "untested"


def test_persist_resolves_assets_and_writes_only_changes(db):
    from app.models.agent_test_coverage import AgentTestCoverage

    asset = _asset(db, "app.example.com")
    brain = _brain(("tested_clean", {}), ("finding", {"parameter": "id", "finding_title": "SQLi in id"}),
                   ("untested", {"host": "other.example.net", "parameter": "x"}))

    assert store.persist(1, "s1", brain.to_dict(), db=db) == 3
    rows = {r.parameter: r for r in db.query(AgentTestCoverage)}
    assert rows["q"].asset_id == asset.id and rows["q"].outcome == "no_issue_found"
    assert rows["q"].last_tested_at is not None
    assert rows["id"].outcome == "reported" and rows["id"].finding_title == "SQLi in id"
    assert rows["x"].asset_id is None and rows["x"].last_tested_at is None

    assert store.persist(1, "s1", brain.to_dict(), db=db) == 0          # unchanged
    brain.coverage_cells[2]["status"] = "inconclusive"
    brain.coverage_cells[2]["reason"] = "WAF blocked payloads"
    assert store.persist(1, "s1", brain.to_dict(), db=db) == 1
    row = db.query(AgentTestCoverage).filter_by(parameter="x").one()
    assert row.outcome == "needs_follow_up"
    assert [h["outcome"] for h in row.history] == ["untested", "needs_follow_up"]


def test_next_session_inherits_recent_results_in_scope(db):
    _asset(db, "app.example.com")
    first = _brain(("tested_clean", {}), ("finding", {"parameter": "id", "finding_title": "SQLi"}),
                   ("inconclusive", {"parameter": "sort", "reason": "timeout"}),
                   ("untested", {"parameter": "page"}),
                   ("tested_clean", {"host": "out-of-scope.example.org"}))
    store.persist(1, "s1", first.to_dict(), db=db)

    rows = store.prior_rows(db, 1, {"*.example.com"})
    assert sorted(r.parameter for r in rows) == ["id", "q", "sort"]   # untested and out-of-scope excluded

    second = EngagementBrain()
    assert store.seed_brain(second, rows, organization_id=1, session_id="s2") == 3
    by_param = {c["parameter"]: c for c in second.coverage_cells}
    assert by_param["q"]["status"] == "tested_clean" and by_param["q"]["source"] == "prior_session"
    assert by_param["id"]["status"] == "finding"
    assert by_param["sort"]["status"] == "untested" and "Follow-up from session s1" in by_param["sort"]["reason"]
    # Same cell id as the original, so in-session seeding merges instead of duplicating.
    assert {c["id"] for c in second.coverage_cells} <= {c["id"] for c in first.coverage_cells}

    # Carried cells are not rewritten until this session changes them.
    assert store.persist(1, "s2", second.to_dict(), db=db) == 0
    by_param["sort"]["status"] = "tested_clean"
    assert store.persist(1, "s2", second.to_dict(), db=db) == 1


def test_reuse_window_and_disable(db, monkeypatch):
    from app.models.agent_test_coverage import AgentTestCoverage

    store.persist(1, "s1", _brain(("tested_clean", {})).to_dict(), db=db)
    db.query(AgentTestCoverage).update({"last_tested_at": datetime.utcnow() - timedelta(days=45)})
    db.commit()
    assert store.prior_rows(db, 1, {"app.example.com"}) == []        # older than 30 days: retest
    monkeypatch.setenv("AGENT_COVERAGE_REUSE_DAYS", "60")
    assert len(store.prior_rows(db, 1, {"app.example.com"})) == 1
    monkeypatch.setenv("AGENT_COVERAGE_REUSE_DAYS", "0")
    assert store.prior_rows(db, 1, {"app.example.com"}) == []


def test_prior_rows_are_org_scoped(db):
    store.persist(1, "s1", _brain(("tested_clean", {})).to_dict(), db=db)
    assert store.prior_rows(db, 2, {"app.example.com"}) == []


def test_asset_summary_counts_clean_tests(db):
    asset = _asset(db, "app.example.com")
    store.persist(1, "s1", _brain(
        ("tested_clean", {}), ("tested_clean", {"parameter": "id", "candidate_id": "c1"}),
        ("skipped", {"parameter": "file", "test_type": "xxe"}), ("finding", {"parameter": "u"}),
    ).to_dict(), db=db)
    summary = store.asset_coverage(db, 1, asset.id)
    assert summary["tested"] == 4
    assert summary["by_outcome"]["no_issue_found"] == 1
    assert summary["by_outcome"]["ruled_out"] == 1
    assert summary["by_risk_area"]["xxe"] == {"not_applicable": 1}


def test_run_snapshot_save_persists_coverage(monkeypatch, tmp_path):
    from app.services.agent import run_snapshot

    calls = []
    monkeypatch.setattr(store, "persist", lambda org, sid, brain: calls.append((org, sid, len(brain["coverage_cells"]))))
    monkeypatch.setattr(run_snapshot, "_DIR", tmp_path)
    brain = _brain(("tested_clean", {}))
    run_snapshot.save_run_snapshot(7, "sess-1", {"engagement_brain": brain.to_dict()})
    assert calls == [(7, "sess-1", 1)]


def test_asset_agent_coverage_endpoint(db, monkeypatch):
    from types import SimpleNamespace

    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.api.deps import get_current_active_user
    from app.api.routes import assets as asset_routes
    from app.db.database import get_db

    asset = _asset(db, "app.example.com")
    store.persist(1, "s1", _brain(("tested_clean", {})).to_dict(), db=db)

    app = FastAPI()
    app.include_router(asset_routes.router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_active_user] = lambda: SimpleNamespace(id=1, organization_id=1)
    monkeypatch.setattr(asset_routes, "check_org_access", lambda user, org: org == user.organization_id)
    client = TestClient(app)
    prefix = asset_routes.router.prefix or ""

    body = client.get(f"{prefix}/{asset.id}/agent-coverage").json()
    assert body["tested"] == 1 and body["by_outcome"]["no_issue_found"] == 1
    assert body["exploitable_untested"] is False

    other = _asset(db, "x.other.org", org=2)
    assert client.get(f"{prefix}/{other.id}/agent-coverage").status_code == 403
