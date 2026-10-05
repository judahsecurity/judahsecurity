"""Private capability binding between an agent session and a scoped assessment run."""

from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint

from app.db.database import Base
from app.models.api_config import get_cipher


class ScopedAssessmentRun(Base):
    __tablename__ = "scoped_assessment_runs"
    __table_args__ = (
        UniqueConstraint("organization_id", "session_id", name="uq_scoped_assessment_session"),
    )

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    session_id = Column(String(64), nullable=False)
    service_run_id = Column(String(32), nullable=False, unique=True)
    allowed_origin = Column(String(512), nullable=False)
    hunter_token_encrypted = Column(Text, nullable=False)
    verifier_token_encrypted = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    def set_tokens(self, hunter: str, verifier: str) -> None:
        cipher = get_cipher()
        self.hunter_token_encrypted = cipher.encrypt(hunter.encode()).decode()
        self.verifier_token_encrypted = cipher.encrypt(verifier.encode()).decode()

    def hunter_token(self) -> str:
        return get_cipher().decrypt(self.hunter_token_encrypted.encode()).decode()

    def verifier_token(self) -> str:
        return get_cipher().decrypt(self.verifier_token_encrypted.encode()).decode()
