"""Source sightings and atomic evidence for one finding on one endpoint."""

from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship

from app.db.database import Base


class FindingObservation(Base):
    """One source record about one canonical endpoint finding."""

    __tablename__ = "finding_observations"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "source", "source_instance", "source_record_key",
            name="uq_finding_observations_source_record",
        ),
        Index("ix_finding_observations_finding_seen", "vulnerability_id", "last_seen"),
    )

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="SET NULL"), nullable=True)
    source = Column(String(100), nullable=False)
    source_instance = Column(String(255), nullable=False, default="")
    source_record_id = Column(String(500), nullable=True)
    source_record_key = Column(String(64), nullable=False)
    rule_id = Column(String(255), nullable=True)
    severity = Column(String(20), nullable=True)
    confidence = Column(String(20), nullable=True)
    first_seen = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_seen = Column(DateTime, nullable=False, default=datetime.utcnow)
    seen_count = Column(Integer, nullable=False, default=1)

    vulnerability = relationship("Vulnerability", back_populates="observations")
    evidence_items = relationship("FindingEvidence", back_populates="observation", cascade="all, delete-orphan")


class FindingEvidence(Base):
    """One typed proof item. The parent finding already identifies its endpoint."""

    __tablename__ = "finding_evidence"
    __table_args__ = (
        UniqueConstraint("observation_id", "kind", "value_hash", name="uq_finding_evidence_item"),
    )

    id = Column(Integer, primary_key=True)
    observation_id = Column(Integer, ForeignKey("finding_observations.id", ondelete="CASCADE"), nullable=False, index=True)
    kind = Column(String(30), nullable=False)
    value = Column(Text, nullable=False)
    value_hash = Column(String(64), nullable=False)
    observed_at = Column(DateTime, nullable=True)

    observation = relationship("FindingObservation", back_populates="evidence_items")


class FindingIdentifier(Base):
    """Additional atomic identifiers; CVE/CWE are also projected onto the finding."""

    __tablename__ = "finding_identifiers"
    __table_args__ = (
        UniqueConstraint("vulnerability_id", "kind", "value", name="uq_finding_identifiers_value"),
        Index("ix_finding_identifiers_kind_value", "kind", "value"),
    )

    id = Column(Integer, primary_key=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True)
    kind = Column(String(20), nullable=False)
    value = Column(String(255), nullable=False)

    vulnerability = relationship("Vulnerability", back_populates="identifiers")
