"""Full Pursuit: keep testing after the first finding and prove the whole impact.

Two parts:

* :data:`FULL_PURSUIT_GUIDANCE`, a standing instruction appended to the
  autonomous system prompt. It tells the agent that one finding is not the end
  of the assessment, that each finding should be pushed to its demonstrated
  impact, and how to approach business logic with general method rather than
  vulnerability-specific hints.
* :func:`rendered_client_side`, used by the tester-loop gate. A pure-HTTP
  crawl (Katana without headless mode) cannot see routes and API calls built in
  the browser. Completion requires at least one real browser render of the
  application.

Per-org switch: agent config ``full_pursuit_enabled`` (default on), so runs can
be compared with and without it on the class lab.
"""

from __future__ import annotations

import logging
import shlex
from typing import Any, Iterable, Optional

logger = logging.getLogger(__name__)

FULL_PURSUIT_GUIDANCE = """
## Full pursuit
- One finding does not end the assessment. After each confirmed finding, keep
  working the remaining coverage cells, hypotheses and inventory; report the
  application as tested only when every class is proven, killed, or explicitly
  deferred with a reason.
- Prove the full impact, not the first symptom. For each confirmed issue ask
  what an attacker reaches next (other users' data, privilege, write access,
  account takeover, a second bug it chains into) and demonstrate the furthest
  step the rules of engagement allow, inside scope and with test identities.
- Render the application in a browser before calling the surface mapped.
  Client-side routes, lazily loaded chunks and XHR/fetch calls only appear when
  the JavaScript runs; a plain HTTP crawl misses them.
- Business logic: model each workflow (sign-up, checkout, transfer, approval,
  password reset, invitations, coupons, quotas) as a sequence of states. Then
  test skipped steps, reordered steps, replayed steps, negative or boundary
  values, concurrent requests, and the same action performed by a different
  identity or role. Compare every result to what the workflow should allow.
""".strip()

# Tools that execute the application's JavaScript in a real browser.
BROWSER_RENDER_TOOLS = frozenset({
    "execute_interceptor",
    "execute_deep_crawl",
    "execute_browser",
    "scoped_browser_crawl",
    "scoped_browser_assessment",
})
_HEADLESS_FLAGS = {"-headless", "-hl", "--headless"}


def _steps(trace: Optional[Iterable[Any]]) -> list[dict]:
    return [s for s in (trace or []) if isinstance(s, dict)]


def _katana_headless(step: dict) -> bool:
    args = step.get("tool_args") or {}
    raw = args.get("args") if isinstance(args, dict) else None
    if not isinstance(raw, str):
        return False
    try:
        tokens = shlex.split(raw)
    except ValueError:
        tokens = raw.split()
    return any(tok.split("=", 1)[0] in _HEADLESS_FLAGS for tok in tokens)


def rendered_client_side(trace: Optional[Iterable[Any]]) -> bool:
    """True once a successful step ran the target's JavaScript in a browser."""
    for step in _steps(trace):
        if step.get("success") is False:
            continue
        name = str(step.get("tool_name") or "")
        if name in BROWSER_RENDER_TOOLS:
            return True
        if name == "execute_katana" and _katana_headless(step):
            return True
    return False


def full_pursuit_enabled(agent_config: Optional[dict]) -> bool:
    if not isinstance(agent_config, dict):
        return True
    return bool(agent_config.get("full_pursuit_enabled", True))


def org_full_pursuit_enabled(organization_id: Optional[int]) -> bool:
    """Read the org switch; on any error keep the discipline on."""
    if organization_id is None:
        return True
    try:
        from app.db.database import SessionLocal
        from app.models.project_settings import MODULE_AGENT, ProjectSettings

        db = SessionLocal()
        try:
            cfg = ProjectSettings.get_config(db, organization_id, MODULE_AGENT) or {}
        finally:
            db.close()
        return full_pursuit_enabled(cfg)
    except Exception:
        logger.debug("full pursuit config unavailable; keeping it on", exc_info=True)
        return True


__all__ = [
    "BROWSER_RENDER_TOOLS",
    "FULL_PURSUIT_GUIDANCE",
    "full_pursuit_enabled",
    "org_full_pursuit_enabled",
    "rendered_client_side",
]
