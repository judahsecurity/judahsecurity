"""Normalized targets, source records, and evidence for analyst findings."""

from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship

from app.db.database import Base


class FindingTarget(Base):
    """One affected asset/endpoint; many targets may belong to one finding."""

    __tablename__ = "finding_targets"
    __table_args__ = (
        UniqueConstraint("vulnerability_id", "target_key", name="uq_finding_targets_key"),
        Index("ix_finding_targets_org_asset", "organization_id", "asset_id"),
    )

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    target_key = Column(String(64), nullable=False)
    port = Column(Integer, nullable=True)
    protocol = Column(String(10), nullable=True)
    service_name = Column(String(100), nullable=True)
    url = Column(String(2048), nullable=True)
    # reported is a source claim; confirmed requires direct evidence or analyst review.
    verification = Column(String(20), nullable=False, default="reported")
    first_seen = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_seen = Column(DateTime, nullable=False, default=datetime.utcnow)

    vulnerability = relationship("Vulnerability", back_populates="targets")
    asset = relationship("Asset")


class FindingObservation(Base):
    """One native source record, independently of how many targets it covers."""

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
    source_record_id = Column(String(500), nullable=True)  # native ID, not our finding ID
    source_record_key = Column(String(64), nullable=False)
    rule_id = Column(String(255), nullable=True)
    title = Column(String(500), nullable=True)
    severity = Column(String(20), nullable=True)
    confidence = Column(String(20), nullable=True)
    description = Column(Text, nullable=True)  # source narrative, not a target list
    first_seen = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_seen = Column(DateTime, nullable=False, default=datetime.utcnow)
    seen_count = Column(Integer, nullable=False, default=1)

    vulnerability = relationship("Vulnerability", back_populates="observations")
    targets = relationship("FindingObservationTarget", back_populates="observation", cascade="all, delete-orphan")
    evidence_items = relationship("FindingEvidence", back_populates="observation", cascade="all, delete-orphan")


class FindingObservationTarget(Base):
    """Many-to-many attribution from a source record to its exact targets."""

    __tablename__ = "finding_observation_targets"
    observation_id = Column(Integer, ForeignKey("finding_observations.id", ondelete="CASCADE"), primary_key=True)
    target_id = Column(Integer, ForeignKey("finding_targets.id", ondelete="CASCADE"), primary_key=True)

    observation = relationship("FindingObservation", back_populates="targets")
    target = relationship("FindingTarget")


class FindingEvidence(Base):
    """One typed evidence item from one source record."""

    __tablename__ = "finding_evidence"
    __table_args__ = (
        UniqueConstraint("observation_id", "kind", "value_hash", name="uq_finding_evidence_item"),
    )

    id = Column(Integer, primary_key=True)
    observation_id = Column(Integer, ForeignKey("finding_observations.id", ondelete="CASCADE"), nullable=False, index=True)
    target_id = Column(Integer, ForeignKey("finding_targets.id", ondelete="CASCADE"), nullable=True, index=True)
    kind = Column(String(30), nullable=False)  # url, request, response, excerpt, screenshot, note
    value = Column(Text, nullable=False)
    value_hash = Column(String(64), nullable=False)
    observed_at = Column(DateTime, nullable=True)

    observation = relationship("FindingObservation", back_populates="evidence_items")
    target = relationship("FindingTarget")


class FindingIdentifier(Base):
    """An atomic issue identifier such as one CVE or CWE."""

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
