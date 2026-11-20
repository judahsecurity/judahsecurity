"""Source-backed NetBrain path calculations between exact Judah assets."""

from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, UniqueConstraint

from app.db.database import Base


class NetBrainPath(Base):
    __tablename__ = "netbrain_paths"
    __table_args__ = (UniqueConstraint("integration_id", "task_id", name="uq_netbrain_path_task"),)

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    # Retain historical evidence when a connection is removed.
    integration_id = Column(Integer, ForeignKey("netbrain_integrations.id", ondelete="SET NULL"), index=True)
    source_integration_id = Column(Integer, nullable=False)
    task_id = Column(String(128), nullable=False)
    source_asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    target_asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    source_ip = Column(String(45), nullable=False)
    target_ip = Column(String(45), nullable=False)
    source_scope_id = Column(String(255), nullable=False)
    target_scope_id = Column(String(255), nullable=False)
    tenant_id = Column(String(128), nullable=False)
    domain_id = Column(String(128), nullable=False)
    gateway_ip = Column(String(45), nullable=False)
    gateway_device = Column(String(255), nullable=False)
    gateway_interface = Column(String(255), nullable=False)
    protocol = Column(Integer, nullable=False)
    destination_port = Column(Integer, nullable=False, default=0)
    is_live = Column(Boolean, nullable=False, default=False)
    status = Column(String(24), nullable=False, default="pending")
    hop_list = Column(JSON, nullable=False, default=list)
    error = Column(String(500))
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime)
    graph_projected_at = Column(DateTime)
