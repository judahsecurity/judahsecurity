from datetime import datetime, timezone

from sqlalchemy.dialects import postgresql

from app.workers.schedule_worker import due_schedule_claim_statement


def test_due_schedule_claim_uses_skip_locked_and_rechecks_due_state():
    statement = due_schedule_claim_statement(
        42, datetime(2026, 9, 9, 12, 0, tzinfo=timezone.utc)
    )
    sql = str(statement.compile(dialect=postgresql.dialect()))

    assert "FOR UPDATE SKIP LOCKED" in sql
    assert "scan_schedules.id" in sql
    assert "scan_schedules.next_run_at" in sql
    assert "scan_schedules.is_enabled" in sql
