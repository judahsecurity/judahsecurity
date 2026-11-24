"""Append-only log of independent-verifier verdicts.

One row per verdict (confirmed / refuted / inconclusive) so operators can see
which vulnerability classes and proof recipes reject candidates most often.
Request bytes, payloads and evidence bodies are never stored here.
"""

from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text

from app.db.database import Base


class AgentVerdictLog(Base):
    __tablename__ = "agent_verdict_log"

    id = Column(Integer, primary_key=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    session_id = Column(String(64), nullable=False, default="", index=True)
    run_id = Column(String(64), nullable=True, index=True)
    candidate_id = Column(String(64), nullable=False, default="")
    revision = Column(Integer, nullable=False, default=1)
    vulnerability_class = Column(String(64), nullable=False, default="unclassified", index=True)
    verdict = Column(String(24), nullable=False, index=True)
    proof_kind = Column(String(64), nullable=False, default="")
    reason = Column(Text, nullable=False, default="")
    target = Column(String(512), nullable=False, default="")
    hunter_evidence_count = Column(Integer, nullable=False, default=0)
    finding_id = Column(Integer, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
