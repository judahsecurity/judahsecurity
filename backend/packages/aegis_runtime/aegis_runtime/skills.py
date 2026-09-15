"""Versioned skill manifests and deterministic tool authorization."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence


class SkillPolicyError(ValueError):
    """Raised when a skill manifest is invalid or attempts a forbidden action."""


class RiskClass(str, Enum):
    PASSIVE = "passive"
    ACTIVE = "active"
    MUTATING = "mutating"
    HIGH_IMPACT = "high_impact"


_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][a-zA-Z0-9.-]+)?$")


@dataclass(frozen=True)
class SkillManifest:
    id: str
    version: str = "1.0.0"
    description: str = ""
    risk: RiskClass = RiskClass.ACTIVE
    allowed_tools: tuple[str, ...] = ()
    required_inputs: tuple[str, ...] = ()
    max_cost_usd: float = 5.0
    max_runtime_minutes: int = 30
    evaluation_suite: str = ""
    requires_approval: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not _ID.fullmatch(self.id):
            raise SkillPolicyError(f"invalid skill id: {self.id!r}")
        if not _VERSION.fullmatch(self.version):
            raise SkillPolicyError(f"invalid semantic version: {self.version!r}")
        if self.max_cost_usd < 0:
            raise SkillPolicyError("max_cost_usd cannot be negative")
        if not 1 <= self.max_runtime_minutes <= 24 * 60:
            raise SkillPolicyError("max_runtime_minutes must be between 1 and 1440")
        if self.risk in (RiskClass.MUTATING, RiskClass.HIGH_IMPACT) and not self.requires_approval:
            raise SkillPolicyError(f"{self.risk.value} skills must require approval")
        for tool in self.allowed_tools:
            if not _ID.fullmatch(tool.replace(".", "_")):
                raise SkillPolicyError(f"invalid tool id: {tool!r}")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "SkillManifest":
        try:
            risk = RiskClass(str(value.get("risk") or RiskClass.ACTIVE.value))
        except ValueError as exc:
            raise SkillPolicyError(f"invalid risk class: {value.get('risk')!r}") from exc
        return cls(
            id=str(value.get("id") or value.get("name") or ""),
            version=str(value.get("version") or "1.0.0"),
            description=str(value.get("description") or ""),
            risk=risk,
            allowed_tools=_tuple(value.get("allowed_tools")),
            required_inputs=_tuple(value.get("required_inputs")),
            max_cost_usd=float(value.get("max_cost_usd", 5.0)),
            max_runtime_minutes=int(value.get("max_runtime_minutes", 30)),
            evaluation_suite=str(value.get("evaluation_suite") or ""),
            requires_approval=bool(value.get("requires_approval", False)),
            metadata=dict(value.get("metadata") or {}),
        )

    def authorize_tool(self, tool_name: str) -> None:
        if not self.allowed_tools:
            raise SkillPolicyError(f"skill {self.id} has no authorized tools")
        if tool_name not in self.allowed_tools:
            raise SkillPolicyError(
                f"tool {tool_name!r} is not authorized for skill {self.id}@{self.version}"
            )

    def digest(self) -> str:
        payload = asdict(self)
        payload["risk"] = self.risk.value
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["risk"] = self.risk.value
        result["digest"] = self.digest()
        return result


def _tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return tuple(item.strip() for item in value.split(",") if item.strip())
    if isinstance(value, Sequence):
        return tuple(str(item).strip() for item in value if str(item).strip())
    raise SkillPolicyError("expected a string or sequence")
