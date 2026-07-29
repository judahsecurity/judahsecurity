"""Agent API Key model for authenticating external agents (Aegis Vanguard, CI/CD, etc.)."""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship

from app.db.database import Base


class AgentAPIKey(Base):
    """API key for external agent authentication.
    
    Stores a hashed version of the key. The plaintext key is only shown
    once at creation time and never stored.
    """

    __tablename__ = "agent_api_keys"

    id = Column(Integer, primary_key=True, index=True)
    key_id = Column(String(32), unique=True, nullable=False, index=True)
    key_hash = Column(String(255), nullable=False)
    key_prefix = Column(String(12), nullable=False)

    name = Column(String(100), nullable=False)
    agent_type = Column(String(50), nullable=False, default="aegis_vanguard")
    scopes = Column(JSON, default=list)

    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    organization = relationship("Organization")
    created_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    is_active = Column(Boolean, default=True, nullable=False)
    last_used_at = Column(DateTime, nullable=True)
    last_agent_ip = Column(String(45), nullable=True)
    usage_count = Column(Integer, default=0, nullable=False)

    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    revoked_at = Column(DateTime, nullable=True)
