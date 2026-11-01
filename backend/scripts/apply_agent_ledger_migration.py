"""Create and verify durable agent ledger tables before an ECS API rollout."""

from __future__ import annotations

from sqlalchemy import inspect, text

from app.db.database import engine
from app.models.organization import Organization  # noqa: F401 - referenced metadata
from app.models.user import User  # noqa: F401 - referenced metadata
from app.models.scan_schedule import ScanSchedule  # noqa: F401 - referenced metadata
from app.models.agent_autonomy_work import AgentAutonomyWork, AgentRunSnapshot
from app.models.agent_run_ledger import (
    AgentActionReceipt,
    AgentHypothesisCoverage,
    AgentRunLedger,
)


def apply() -> None:
    tables = [
        AgentRunLedger.__table__,
        AgentActionReceipt.__table__,
        AgentHypothesisCoverage.__table__,
        AgentAutonomyWork.__table__,
        AgentRunSnapshot.__table__,
    ]
    with engine.begin() as connection:
        AgentRunLedger.metadata.create_all(bind=connection, tables=tables, checkfirst=True)
        inspector = inspect(connection)
        work_columns = {column["name"] for column in inspector.get_columns("agent_autonomy_work")}
        if "turn_started_at" not in work_columns:
            connection.execute(text("ALTER TABLE agent_autonomy_work ADD COLUMN turn_started_at TIMESTAMP"))
            inspector.clear_cache()
        for table in tables:
            existing = {column["name"] for column in inspector.get_columns(table.name)}
            missing = {column.name for column in table.columns} - existing
            if missing:
                raise RuntimeError(f"{table.name} is missing columns: {', '.join(sorted(missing))}")


if __name__ == "__main__":
    apply()
    print("Agent ledger schema ready")
