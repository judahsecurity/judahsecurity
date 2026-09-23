"""Organization model for multi-tenant support."""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, JSON
from sqlalchemy.orm import relationship

from app.db.database import Base


class Organization(Base):
    """Organization model for multi-tenant ASM."""
    
    __tablename__ = "organizations"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, index=True, nullable=False)
    description = Column(Text, nullable=True)
    domain = Column(String(255), nullable=True)  # Primary domain
    industry = Column(String(100), nullable=True)
    is_active = Column(Boolean, default=True)
    
    # Discovery configuration - persisted keywords for Common Crawl and SNI searches
    commoncrawl_org_name = Column(String(255), nullable=True)  # Organization name for TLD search
    commoncrawl_keywords = Column(JSON, default=list)  # Keywords for wildcard search (e.g., ["rockwell", "allen-bradley"])
    sni_keywords = Column(JSON, default=list)  # Keywords for SNI cloud asset discovery

    # Severity evaluation: this organization's default 1–4 weight per risk
    # factor, e.g. {"business_impact": 3}. Missing factors use the platform
    # default; analysts can still override per finding during triage.
    risk_weight_defaults = Column(JSON, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    users = relationship("User", back_populates="organization")
    assets = relationship("Asset", back_populates="organization", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="organization", cascade="all, delete-orphan")
    acquisitions = relationship("Acquisition", back_populates="organization", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Organization {self.name}>"

















