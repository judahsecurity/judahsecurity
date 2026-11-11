"""Stable identifiers that tie one asset to the records each source holds for it.

An asset's ``value`` is a display key (a hostname, an IP, a cloud ID). It is
not how sources find the asset again. Every connector instead registers the
identifiers its own data carries — a cloud provider's instance or resource ID,
the source's record ID, a MAC or BIOS UUID — and looks assets up by them.

Each ``(organization_id, namespace, value)`` belongs to exactly one asset, so
two sources reporting the same cloud instance always land on the same asset.
"""

from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import relationship

from app.db.database import Base


class AssetIdentifier(Base):
    __tablename__ = "asset_identifiers"
    __table_args__ = (
        UniqueConstraint("organization_id", "namespace", "value", name="uq_asset_identifier"),
        Index("ix_asset_identifiers_asset", "asset_id"),
    )

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    # e.g. "aws:ec2_instance", "azure:resource_id", "gcp:instance_id", "wiz:id",
    # "tenable:asset_uuid", "mac", "bios_uuid". See app.services.asset_identity.
    namespace = Column(String(64), nullable=False)
    value = Column(String(512), nullable=False)  # normalized
    source = Column(String(64), nullable=True)  # connector that first reported it
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

    asset = relationship("Asset", back_populates="identifiers")
