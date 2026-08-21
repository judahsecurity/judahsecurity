"""Agent conversation model for persistent chat history."""

from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, JSON, Boolean, Float
from sqlalchemy.orm import relationship

from app.db.database import Base


class AgentConversation(Base):
    """Stores agent chat sessions so users don't lose context on page refresh."""

    __tablename__ = "agent_conversations"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(64), unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    title = Column(String(255), nullable=True)
    mode = Column(String(20), default="assist")
    current_phase = Column(String(30), default="informational")
    is_active = Column(Boolean, default=True)

    messages = Column(JSON, default=list)
    execution_summary = Column(Text, nullable=True)
    todo_list = Column(JSON, default=list)
    engagement_replay = Column(JSON, default=list)
    token_usage = Column(JSON, nullable=True)
    cost_usd = Column(Float, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = relationship("User", backref="agent_conversations")
    organization = relationship("Organization", backref="agent_conversations")

    def __repr__(self):
        return f"<AgentConversation session={self.session_id} title={self.title}>"
