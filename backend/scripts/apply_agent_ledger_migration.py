"""Create and verify durable agent ledger tables before an ECS API rollout."""

from __future__ import annotations

from sqlalchemy import inspect

from app.db.database import engine
from app.models.organization import Organization  # noqa: F401 - referenced metadata
from app.models.user import User  # noqa: F401 - referenced metadata
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
    ]
    with engine.begin() as connection:
        AgentRunLedger.metadata.create_all(bind=connection, tables=tables, checkfirst=True)
        inspector = inspect(connection)
        for table in tables:
            existing = {column["name"] for column in inspector.get_columns(table.name)}
            missing = {column.name for column in table.columns} - existing
            if missing:
                raise RuntimeError(f"{table.name} is missing columns: {', '.join(sorted(missing))}")


if __name__ == "__main__":
    apply()
    print("Agent ledger schema ready")
