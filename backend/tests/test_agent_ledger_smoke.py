"""Staging ledger check rejects empty and internally inconsistent runs."""

from scripts.check_agent_ledger import validate_ledger


def test_schema_migration_is_repeatable(monkeypatch):
    from sqlalchemy import create_engine, inspect
    from sqlalchemy.pool import StaticPool

    from app.models.organization import Organization
    from app.models.user import User
    from scripts import apply_agent_ledger_migration

    engine = create_engine("sqlite://", poolclass=StaticPool)
    Organization.metadata.create_all(bind=engine, tables=[
        Organization.__table__, User.__table__,
    ])
    monkeypatch.setattr(apply_agent_ledger_migration, "engine", engine)
    apply_agent_ledger_migration.apply()
    apply_agent_ledger_migration.apply()
    assert all(inspect(engine).has_table(name) for name in (
        "agent_run_ledger", "agent_action_receipts", "agent_hypothesis_coverage",
    ))


def test_terminal_partial_run_with_interrupted_action_is_reviewable():
    report = {
        "run_id": "r1", "status": "timeout",
        "actions": [{"id": "a1", "status": "interrupted"}],
        "coverage": {"actions": 1, "model_calls": 1, "test_actions": 0,
                     "published_findings": 0},
    }
    ok, errors, summary = validate_ledger(report)
    assert ok and not errors
    assert summary["actions"] == 1
    assert summary["published_findings"] == 0


def test_empty_or_open_terminal_run_fails_validation():
    empty = {"run_id": "r1", "status": "timeout", "actions": [],
             "coverage": {"actions": 0}}
    assert validate_ledger(empty)[0] is False
    open_run = {"run_id": "r2", "status": "completed",
                "actions": [{"id": "a1", "status": "running"}],
                "coverage": {"actions": 1}}
    assert validate_ledger(open_run)[0] is False
