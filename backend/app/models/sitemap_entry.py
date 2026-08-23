"""Praetorian-style application sitemap: one row per discovered path/API/external URL."""

from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from app.db.database import Base


KIND_SITEMAP = "sitemap"
KIND_API = "api"
KIND_EXTERNAL = "external"


class SitemapEntry(Base):
    """
    Durable application-map row attached to a host asset.

    Mirrors Praetorian's Application tab:
      - Sitemap (same-origin paths)
      - REST API Endpoints
      - External URLs
    with per-path flags: secrets, login, SSO, screenshots, response.
    """

    __tablename__ = "sitemap_entries"
    __table_args__ = (
        UniqueConstraint("asset_id", "path_key", name="uq_sitemap_asset_path_key"),
        Index("ix_sitemap_asset_kind", "asset_id", "kind"),
        Index("ix_sitemap_org_asset", "organization_id", "asset_id"),
        Index("ix_sitemap_login", "asset_id", "has_login"),
        Index("ix_sitemap_sso", "asset_id", "has_sso"),
        Index("ix_sitemap_secrets", "asset_id", "has_secrets"),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    asset_id = Column(
        Integer,
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    asset = relationship("Asset", back_populates="sitemap_entries")

    # sitemap | api | external
    kind = Column(String(20), nullable=False, index=True)
    # sha256(kind|host|method|path) — unique per asset without a huge btree key
    path_key = Column(String(64), nullable=False)

    host = Column(String(255), nullable=False, default="")
    method = Column(String(16), nullable=False, default="")
    path = Column(String(2048), nullable=False, default="/")
    url = Column(String(2048), nullable=False, default="")
    query_template = Column(String(1024), nullable=True)

    has_secrets = Column(Boolean, default=False, nullable=False)
    has_login = Column(Boolean, default=False, nullable=False)
    has_sso = Column(Boolean, default=False, nullable=False)
    screenshot_count = Column(Integer, default=0, nullable=False)
    screenshot_id = Column(Integer, ForeignKey("screenshots.id", ondelete="SET NULL"), nullable=True)
    http_status = Column(Integer, nullable=True)
    response_title = Column(String(512), nullable=True)

    source = Column(String(64), nullable=True)
    sources = Column(JSON, default=list)
    parameters = Column(JSON, default=list)
    extra = Column(JSON, default=dict)

    first_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "host": self.host,
            "method": self.method or None,
            "path": self.path,
            "url": self.url,
            "query_template": self.query_template,
            "has_secrets": bool(self.has_secrets),
            "has_login": bool(self.has_login),
            "has_sso": bool(self.has_sso),
            "screenshot_count": int(self.screenshot_count or 0),
            "screenshot_id": self.screenshot_id,
            "http_status": self.http_status,
            "response_title": self.response_title,
            "source": self.source,
            "sources": list(self.sources or []),
            "parameters": list(self.parameters or []),
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }
