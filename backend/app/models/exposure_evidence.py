"""Source detection evidence and provider attack-path assertions.

Provider claims are kept separate from Judah's FindingValidation verdicts.
Paths retain source node references even when no Judah asset match exists yet.
"""

from datetime import datetime

from sqlalchemy import CheckConstraint, Column, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship

from app.db.database import Base


class FindingSourceEvidence(Base):
    __tablename__ = "finding_source_evidence"
    __table_args__ = (
        UniqueConstraint("vulnerability_id", "source", "evidence_key", name="uq_finding_source_evidence"),
    )

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True)
    source = Column(String(50), nullable=False)
    source_finding_id = Column(String(255), nullable=False)
    evidence_key = Column(String(100), nullable=False)  # Stable within a source finding
    detection_method = Column(String(100), nullable=False)  # e.g. falcon_spotlight, remote_probe
    basis = Column(String(50), nullable=False)  # provider_assertion, observed, reproduced
    source_status = Column(String(50))
    summary = Column(Text)
    details = Column(JSON, nullable=False, default=dict)  # Allowlisted, structured source signals
    observed_at = Column(DateTime)
    first_ingested_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_ingested_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    vulnerability = relationship("Vulnerability", back_populates="source_evidence")


class ExposurePath(Base):
    """One provider path; its existence is a claim, not an exploit verdict."""

    __tablename__ = "exposure_paths"
    __table_args__ = (
        UniqueConstraint("organization_id", "source", "source_instance_id", "source_path_id", name="uq_exposure_path_source"),
    )

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    source = Column(String(50), nullable=False)
    source_instance_id = Column(String(100), nullable=False)  # Connector identity, e.g. CrowdStrike integration ID
    source_path_id = Column(String(255), nullable=False)
    title = Column(String(500))
    source_status = Column(String(50))
    source_observed_at = Column(DateTime)
    first_ingested_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_ingested_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    details = Column(JSON, nullable=False, default=dict)

    steps = relationship("ExposurePathStep", back_populates="path", cascade="all, delete-orphan", order_by="ExposurePathStep.position")


class ExposurePathStep(Base):
    """An ordered edge with optional Judah IDs and independently graded proof."""

    __tablename__ = "exposure_path_steps"
    __table_args__ = (
        UniqueConstraint("path_id", "position", name="uq_exposure_path_step_position"),
        CheckConstraint("proof_state IN ('asserted', 'observed', 'validated', 'blocked', 'unknown')", name="ck_exposure_path_proof_state"),
    )

    id = Column(Integer, primary_key=True)
    path_id = Column(Integer, ForeignKey("exposure_paths.id", ondelete="CASCADE"), nullable=False, index=True)
    position = Column(Integer, nullable=False)
    from_source_ref = Column(String(255))
    to_source_ref = Column(String(255))
    from_asset_id = Column(Integer, ForeignKey("assets.id", ondelete="SET NULL"), index=True)
    to_asset_id = Column(Integer, ForeignKey("assets.id", ondelete="SET NULL"), index=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id", ondelete="SET NULL"), index=True)
    edge_type = Column(String(100), nullable=False)
    source_claim = Column(Text)
    proof_state = Column(String(20), nullable=False, default="asserted")
    evidence = Column(JSON, nullable=False, default=list)  # Bounded observation references, not raw secrets
    observed_at = Column(DateTime)
    finding_validation_id = Column(Integer, ForeignKey("finding_validations.id", ondelete="SET NULL"))
    validated_at = Column(DateTime)

    path = relationship("ExposurePath", back_populates="steps")
