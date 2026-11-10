"""Per-source observations of a canonical finding.

A ``Vulnerability`` row is the canonical issue (one per real-world problem);
each scanner or vendor that reports it gets one ``FindingObservation`` keyed by
``(organization_id, source, vendor_finding_id)``. Re-syncs update the
observation, and the canonical row is recomputed from all of them, so two
tools reporting the same CVE on the same host never produce two findings.
"""

from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, String, UniqueConstraint
from sqlalchemy.orm import relationship

from app.db.database import Base


class FindingObservation(Base):
    __tablename__ = "finding_observations"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "source", "vendor_finding_id", name="uq_finding_observation_source_id"
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    vulnerability_id = Column(
        Integer, ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    vulnerability = relationship("Vulnerability", back_populates="observations")

    source = Column(String(50), nullable=False, index=True)  # tenable_vm, wiz, nuclei, ...
    vendor_finding_id = Column(String(255), nullable=False)
    vendor_severity = Column(String(50), nullable=True)
    # "open" or "fixed" as the source last reported it.
    state = Column(String(20), nullable=False, default="open", index=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    details = Column(JSON, default=dict)  # small source-specific summary, not the raw payload
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<FindingObservation {self.source}:{self.vendor_finding_id} -> {self.vulnerability_id}>"
