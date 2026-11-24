"""Durable, per-asset record of what the agent tested and what it concluded.

One row per coverage cell per organization. A cell is one unit of testing:
method + host + path + operation + identity + tenant + parameter + test type,
hashed into a stable ``cell_key`` (``coverage_cells.coverage_cell_id``), so the
same test in a later session updates the same row. Written from the agent's
engagement brain whenever the run is saved, read back when the next session
for the organization starts, and exposed per asset.
"""

from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint

from app.db.database import Base

# Outcome vocabulary (ARTEX-compatible, plus open states):
#   reported         a finding was raised for this cell
#   no_issue_found   tested, nothing there
#   ruled_out        a candidate was raised and then refuted
#   not_applicable   skipped: the test does not apply to this surface
#   needs_follow_up  inconclusive or blocked; worth another attempt
#   in_progress      leased / in focus when last saved
#   untested         known surface, not tested yet
COVERAGE_OUTCOMES = (
    "reported", "no_issue_found", "ruled_out", "not_applicable",
    "needs_follow_up", "in_progress", "untested",
)
TERMINAL_OUTCOMES = ("reported", "no_issue_found", "ruled_out", "not_applicable")


class AgentTestCoverage(Base):
    __tablename__ = "agent_test_coverage"
    __table_args__ = (UniqueConstraint("organization_id", "cell_key", name="uq_agent_test_coverage_cell"),)

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True)
    cell_key = Column(String(64), nullable=False)
    host = Column(String(255), nullable=False, default="", index=True)
    method = Column(String(16), nullable=False, default="GET")
    path = Column(String(1024), nullable=False, default="/")
    surface_key = Column(String(1300), nullable=False, default="")
    parameter = Column(String(255), nullable=False, default="endpoint")
    identity = Column(String(128), nullable=False, default="unspecified")
    operation_id = Column(String(255), nullable=False, default="")
    tenant = Column(String(128), nullable=False, default="")
    risk_area = Column(String(64), nullable=False, default="surface_review", index=True)
    outcome = Column(String(24), nullable=False, default="untested", index=True)
    cell_status = Column(String(24), nullable=False, default="untested")
    reason = Column(Text, nullable=False, default="")
    specialist = Column(String(64), nullable=False, default="")
    finding_title = Column(String(500), nullable=False, default="")
    evidence_ids = Column(JSON, nullable=False, default=list)
    attempts = Column(Integer, nullable=False, default=0)
    # Last few (session, outcome, at) transitions, newest last.
    history = Column(JSON, nullable=False, default=list)
    first_session_id = Column(String(128), nullable=False, default="")
    last_session_id = Column(String(128), nullable=False, default="", index=True)
    first_seen_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_tested_at = Column(DateTime, nullable=True, index=True)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
