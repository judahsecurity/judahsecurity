"""Validated analyst review writes; identity and timestamps are server supplied."""
from typing import Annotated, Literal
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

Reference = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2048)]


class FindingTriageWrite(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    task_id: Literal["evidence", "impact", "scope", "priority"]
    expected_revision: int = Field(ge=0)
    evidence_version: str = Field(pattern=r"^[a-f0-9]{64}$")
    state: Literal["draft", "reviewed"] = "draft"
    decision: Literal["confirm", "correct", "needs_evidence"] | None = None
    rationale: str = Field(default="", max_length=6000)
    correction: str = Field(default="", max_length=2000)
    evidence_references: list[Reference] = Field(default_factory=list, max_length=20)

    @model_validator(mode="after")
    def validate_review(self):
        if self.state == "reviewed":
            if not self.decision or not self.rationale:
                raise ValueError("A reviewed decision requires a decision and rationale")
            if self.decision == "correct" and not self.correction:
                raise ValueError("Describe the corrected assessment")
            if self.decision in ("confirm", "correct") and not self.evidence_references:
                raise ValueError("Cite supporting evidence before completing this item")
        return self
