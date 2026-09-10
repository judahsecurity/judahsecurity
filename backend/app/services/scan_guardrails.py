"""Fail-closed safety checks shared by every scan launch path."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from app.services import roe_service


@dataclass
class RulesOfEngagementViolation(Exception):
    reason: str
    rejected_targets: list[str]

    def __str__(self) -> str:
        return self.reason


def validate_rules_of_engagement(
    db, organization_id: int, targets: Iterable[str], scan_type: str
) -> None:
    allowed, reason, rejected = roe_service.check_targets(
        db, organization_id, targets, scan_type=scan_type
    )
    if not allowed:
        raise RulesOfEngagementViolation(
            reason or "One or more targets are outside the accepted scope", rejected
        )
