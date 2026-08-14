"""Recon job queue for Mac / Ubuntu Interceptor workers."""

from datetime import datetime

from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, JSON

from app.db.database import Base


class ReconJob(Base):
    """Queued interaction-first crawl for remote Interceptor workers."""

    __tablename__ = "recon_jobs"

    id = Column(String(36), primary_key=True)
    organization_id = Column(
        Integer,
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    session_id = Column(String(128), nullable=True, index=True)
    url = Column(String(2048), nullable=False)
    scope = Column(String(512), nullable=True)
    max_pages = Column(Integer, default=20)
    interact = Column(Integer, default=1)  # 1/0
    prefer = Column(JSON, default=list)  # ["mac", "ubuntu"]
    opts = Column(JSON, default=dict)  # extra crawl options (login, cookies, …)
    status = Column(String(32), default="queued", index=True)
    # queued | claimed | running | completed | failed | cancelled
    worker_kind = Column(String(32), nullable=True)  # mac | ubuntu
    worker_id = Column(String(128), nullable=True)
    claimed_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    error = Column(Text, nullable=True)
    result = Column(JSON, nullable=True)  # normalised recon + capability_map + auth_session
    created_by_user_id = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ReconWorkerHeartbeat(Base):
    """Last-seen heartbeat for Mac / Ubuntu Interceptor workers."""

    __tablename__ = "recon_worker_heartbeats"

    worker_id = Column(String(128), primary_key=True)
    worker_kind = Column(String(32), nullable=False, index=True)  # mac | ubuntu
    hostname = Column(String(256), nullable=True)
    meta = Column(JSON, default=dict)
    last_seen = Column(DateTime, default=datetime.utcnow, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
