"""MemPalace-style verbatim drawers for org-scoped agent memory."""

from datetime import datetime

from sqlalchemy import Column, DateTime, Index, Integer, JSON, String, Text

from app.db.database import Base


class AgentPalaceDrawer(Base):
    """One verbatim memory chunk (a MemPalace drawer).

    Tenant isolation is ``organization_id`` (NULL = global / shared playbooks).
    ``wing`` / ``room`` / ``hall`` are retrieval scopes, not security boundaries —
    queries must always filter by organization_id in code.
    """

    __tablename__ = "agent_palace_drawers"
    __table_args__ = (
        Index("ix_palace_org_wing_room", "organization_id", "wing", "room"),
        Index("ix_palace_org_hash", "organization_id", "content_hash"),
        Index("ix_palace_org_target", "organization_id", "target"),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, nullable=True, index=True)
    wing = Column(String(128), nullable=False, default="org")
    room = Column(String(128), nullable=False, default="general")
    hall = Column(String(64), nullable=False, default="facts")
    title = Column(String(512), nullable=False, default="")
    content = Column(Text, nullable=False)
    content_hash = Column(String(64), nullable=False)
    source = Column(String(64), nullable=False, default="manual")
    source_id = Column(String(255), nullable=True)
    tool_name = Column(String(128), nullable=True)
    session_id = Column(String(64), nullable=True, index=True)
    target = Column(String(512), nullable=True)
    embedding = Column(JSON, nullable=True)
    embedding_model = Column(String(128), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self) -> str:
        return (
            f"<AgentPalaceDrawer id={self.id} org={self.organization_id} "
            f"wing={self.wing} room={self.room}>"
        )
