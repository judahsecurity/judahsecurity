"""Per-session exploration lineage (app.services.agent.exploration_graph).

``agent_exploration_graphs`` holds one typed goal/intent/fact/finding graph per
agent session. ``agent_exploration_anchors`` ties each intent, fact and finding
to the asset it concerns, so "which sessions and intents touched this asset"
is one indexed query across sessions.
"""

from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, String

from app.db.database import Base


class AgentExplorationGraph(Base):
    __tablename__ = "agent_exploration_graphs"

    session_id = Column(String(128), primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    digest = Column(String(16), nullable=False, default="")
    graph = Column(JSON, nullable=False, default=dict)
    node_counts = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)


class AgentExplorationAnchor(Base):
    __tablename__ = "agent_exploration_anchors"

    id = Column(Integer, primary_key=True)
    session_id = Column(String(128), nullable=False, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    node_key = Column(String(200), nullable=False)
    kind = Column(String(16), nullable=False)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    label = Column(String(160), nullable=False, default="")
    status = Column(String(24), nullable=False, default="")
