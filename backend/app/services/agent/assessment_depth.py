"""Assessment depth: how much room the model gets to explore.

``standard`` is the deterministic pipeline Prowl has always run: the tester
loop picks most steps and specialists get short, fixed turn budgets.

``deep`` keeps the same recon, scope rules and publication gates, but gives
specialists, hunters and the main loop much larger budgets and seeds each
specialist with shared context. It also turns on advisory steering for the
run (see model_led.steering_mode), so after the surface is mapped the model
chooses what to test next. It exists because a model with a dozen tool calls
can confirm a suspected bug but rarely finds a subtle one.

This module owns only the budget/seeding dimension; the advisory-steering
mechanism itself lives in model_led.py.

What deep mode never changes:
- scope enforcement, Lictor/Censor checks, method and credential gates;
- operator autonomy limits (scheduled runs keep their own caps);
- pilot mode, which stays bounded;
- the proof policy, independent verification and publication invariants.
"""

from __future__ import annotations

from contextvars import ContextVar, Token
from dataclasses import dataclass

ASSESSMENT_MODES = ("standard", "deep")


@dataclass(frozen=True)
class AssessmentDepth:
    name: str
    # Multiplies AGENT_SPECIALIST_TURN_MULTIPLIER; the product is clamped to
    # [0.5, specialist_turn_cap].
    specialist_turn_factor: float
    specialist_turn_cap: float
    # Specialists run concurrently in one fireteam wave.
    max_parallel_specialists: int
    # Main-loop iteration floor when the caller did not pass an explicit cap.
    main_iterations: int
    # Multiplies hunter (never verifier) scoped HTTP budgets.
    hunter_budget_factor: int
    # Per-tool ceiling for fireteam_dispatch, which must fit a whole wave.
    fireteam_timeout_seconds: int
    # Seed each specialist with shared engagement context instead of "Begin."
    seed_specialist_context: bool


STANDARD = AssessmentDepth(
    name="standard",
    specialist_turn_factor=1.0,
    specialist_turn_cap=4.0,
    max_parallel_specialists=4,
    main_iterations=0,
    hunter_budget_factor=1,
    fireteam_timeout_seconds=0,
    seed_specialist_context=False,
)

DEEP = AssessmentDepth(
    name="deep",
    specialist_turn_factor=5.0,
    specialist_turn_cap=10.0,
    max_parallel_specialists=8,
    main_iterations=300,
    hunter_budget_factor=4,
    fireteam_timeout_seconds=1800,
    seed_specialist_context=True,
)

_DEPTHS = {depth.name: depth for depth in (STANDARD, DEEP)}

current_assessment_depth: ContextVar[AssessmentDepth] = ContextVar(
    "current_assessment_depth", default=STANDARD,
)


def resolve_assessment_depth(mode: str | None) -> AssessmentDepth:
    """Map a requested mode to a depth, falling back to the configured default."""
    name = str(mode or "").strip().lower()
    if not name:
        from app.core.config import settings

        name = str(getattr(settings, "AGENT_ASSESSMENT_MODE", "standard") or "standard").lower()
    return _DEPTHS.get(name, STANDARD)


def resolve_org_default_mode(organization_id: int | None) -> str | None:
    """A per-org default assessment mode from project_settings.agent, if set.

    Returns None when there is no org, no setting, or the value is invalid, so
    the caller falls back to the global AGENT_ASSESSMENT_MODE default.
    """
    if organization_id is None:
        return None
    try:
        from app.db.database import SessionLocal
        from app.models.project_settings import MODULE_AGENT, ProjectSettings

        with SessionLocal() as db:
            config = ProjectSettings.get_config(db, organization_id, MODULE_AGENT) or {}
    except Exception:
        return None
    mode = str(config.get("assessment_mode") or "").strip().lower()
    return mode if mode in _DEPTHS else None


def set_assessment_depth(mode: str | None) -> Token:
    return current_assessment_depth.set(resolve_assessment_depth(mode))


def assessment_depth() -> AssessmentDepth:
    """The depth for this run. Pilot and scheduled-autonomy runs stay standard."""
    depth = current_assessment_depth.get()
    if depth is STANDARD:
        return depth
    from app.services.agent.autonomy_limits import current_autonomy_limits
    from app.services.agent.pilot_policy import current_pilot

    if current_pilot() is not None or current_autonomy_limits.get() is not None:
        return STANDARD
    return depth


def hunter_budget(base: int) -> int:
    """Scale a hunter request budget for the current depth."""
    return int(base) * max(1, assessment_depth().hunter_budget_factor)


def fireteam_dispatch_cap(default_cap: float) -> float:
    """Per-call ceiling for fireteam_dispatch; deep waves get longer."""
    return max(float(default_cap), float(assessment_depth().fireteam_timeout_seconds or 0))

