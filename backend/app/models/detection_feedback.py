"""
Detection Feedback model.

Captures analyst/agent feedback about a detection's LOGIC being wrong, keyed on
the detection template (e.g. a Nuclei `template_id`). This is the durable record
of "this template produces false positives and here is why", separate from a
per-finding false-positive status.

When the validator agent (or an analyst) determines a finding is a false
positive caused by the template's matching logic, a DetectionFeedback row is
created with the flawed-logic description and a generated, copy-pasteable
upstream bug report suitable for filing to projectdiscovery/nuclei-templates.
"""

from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.db.database import Base


class DetectionFeedback(Base):
    """Template-keyed feedback about incorrect detection logic."""

    __tablename__ = "detection_feedback"

    id = Column(Integer, primary_key=True, index=True)

    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    # The detection this feedback is about
    template_id = Column(String(255), nullable=False, index=True)  # e.g. ldap-anonymous-login-detect
    detected_by = Column(String(100), nullable=True)               # e.g. nuclei

    # What was concluded
    verdict = Column(String(50), nullable=True)      # typically false_positive
    logic_issue = Column(Text, nullable=False)       # description of the flawed matcher/logic
    upstream_report = Column(Text, nullable=True)    # generated markdown bug report for filing upstream

    # Provenance
    example_vulnerability_id = Column(
        Integer, ForeignKey("vulnerabilities.id", ondelete="SET NULL"), nullable=True,
    )
    example_vulnerability = relationship("Vulnerability")
    finding_validation_id = Column(
        Integer, ForeignKey("finding_validations.id", ondelete="SET NULL"), nullable=True,
    )
    source = Column(String(30), default="validator_agent")  # validator_agent | analyst
    reported_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    def __repr__(self) -> str:
        return f"<DetectionFeedback {self.id} template={self.template_id} verdict={self.verdict}>"
