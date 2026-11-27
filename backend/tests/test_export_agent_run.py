"""The run export used by the Gin & Juice scorecard reads the ledger and snapshot."""

import json

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models.organization import Organization  # noqa: F401 - ledger FK metadata
from app.models.user import User  # noqa: F401 - ledger FK metadata
from app.models.agent_conversation import AgentConversation
from app.models.agent_run_ledger import AgentActionReceipt, AgentHypothesisCoverage, AgentRunLedger
from app.services.agent import action_ledger, run_snapshot


def test_export_finds_the_latest_run_for_a_target(monkeypatch, tmp_path):
    import app.db.database as database
    from scripts import export_agent_run

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    for model in (AgentRunLedger, AgentActionReceipt, AgentHypothesisCoverage, AgentConversation):
        model.__table__.create(engine)
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr(action_ledger, "SessionLocal", factory)
    monkeypatch.setattr(database, "SessionLocal", factory)
    monkeypatch.setattr(run_snapshot, "_DIR", tmp_path)

    run_id = action_ledger.start_run(session_id="gj-1", organization_id=5, user_id=9,
                                     objective="https://ginandjuice.shop", mode="agent",
                                     budget_seconds=3600)
    for tool in ("execute_deep_crawl", "check_exposures", "run_hunt_engine"):
        action_ledger.append_action(run_id, f"a-{tool}", "started", tool)
        action_ledger.append_action(run_id, f"a-{tool}", "completed", tool)
    action_ledger.finish_run(run_id, "timeout", "Request ceiling reached")
    run_snapshot.save_run_snapshot(5, "gj-1", {
        "engagement_brain": {
            "candidates": [{"id": "c1", "title": "SQLi", "vulnerability_class": "sql_injection",
                            "status": "confirmed", "target": "https://ginandjuice.shop/catalog",
                            "nonce": "internal"}],
            "coverage_cells": [{"test_type": "sqli", "first_pass_outcome": "proof_signal"},
                               {"test_type": "xss"}],
        },
        "capability_map": {"pages_visited": ["/", "/catalog"], "value_flows": [{"producer": "x"}]},
    })

    data = export_agent_run.export_run(target="ginandjuice.shop")
    assert data["schema"] == "prowl-run-export/1" and data["session_id"] == "gj-1"
    assert data["run"]["status"] == "timeout" and "ceiling" in data["run"]["reason"]
    assert data["candidates"] == [{"id": "c1", "title": "SQLi", "vulnerability_class": "sql_injection",
                                   "status": "confirmed", "target": "https://ginandjuice.shop/catalog"}]
    assert data["coverage"]["by_test_type"] == {"sqli": 1, "xss": 1}
    assert data["coverage"]["tested_test_types"] == ["sqli"]
    assert data["tools"]["runs"] == {"execute_deep_crawl": 1, "check_exposures": 1, "run_hunt_engine": 1}
    assert data["map"] == {"pages": 2, "api_endpoints": 0, "forms": 0, "value_flows": 1}
    json.dumps(data, default=str)
