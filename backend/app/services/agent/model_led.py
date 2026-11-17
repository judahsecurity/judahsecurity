"""Let the model lead stack-specific hunts; the code steps in only on a stall.

A stack-specific forced step (WordPress, container registry, …) used to replace
the model's choice as soon as the stack was fingerprinted. Now it fires only
when the model has had its chance and is not working that surface:

* the model has made ``grace`` of its own decisions since the stack was seen,
* and none of its last ``grace`` decisions touched the stack's surface.

Steps the deterministic pipeline chose do not count toward the grace window, so
a long crawl or fireteam wave cannot exhaust it on the model's behalf. Completing
early is still blocked separately by the tester-loop ``missing`` gate.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, Iterable, List, Optional

DEFAULT_GRACE_STEPS = 4


def grace_steps() -> int:
    try:
        return max(0, int(os.environ.get("AEGIS_MODEL_LED_GRACE_STEPS", DEFAULT_GRACE_STEPS)))
    except ValueError:
        return DEFAULT_GRACE_STEPS


def _blob(step: Dict[str, Any]) -> str:
    args = step.get("tool_args") or {}
    try:
        args_text = json.dumps(args, default=str)
    except (TypeError, ValueError):
        args_text = str(args)
    return " ".join((
        str(step.get("tool_name") or ""), args_text,
        str(step.get("tool_output") or "")[:4000], str(step.get("thought") or ""),
    )).lower()


def stack_forced_step_due(
    trace: Optional[Iterable[Any]],
    *,
    detect: re.Pattern[str],
    surface: re.Pattern[str],
    grace: Optional[int] = None,
) -> bool:
    """True when a stack-specific forced step should replace the model's choice."""
    grace = grace_steps() if grace is None else grace
    if grace <= 0:
        return True
    steps: List[Dict[str, Any]] = [s for s in trace or [] if isinstance(s, dict)]
    seen_at = next((i for i, s in enumerate(steps) if detect.search(_blob(s))), None)
    after = steps[seen_at + 1:] if seen_at is not None else steps
    model_steps = [s for s in after if s.get("decision_source") == "model"]
    if len(model_steps) < grace:
        return False
    recent = model_steps[-grace:]
    return not any(surface.search(_blob(s)) for s in recent)


WORDPRESS_DETECT = re.compile(r"wp-content|wp-includes|wp-json|generator[^\n]{0,40}wordpress", re.I)
WORDPRESS_SURFACE = re.compile(
    r"/wp-|wp-json|xmlrpc|admin-ajax|readme\.txt|changelog|style\.css|wordpress|wp_", re.I,
)
REGISTRY_DETECT = re.compile(r"azurecr\.io|/v2/_catalog|docker-distribution|registry", re.I)
REGISTRY_SURFACE = re.compile(r"azurecr|/v2/|registry|catalog", re.I)


def wordpress_step_due(state: Optional[Dict[str, Any]]) -> bool:
    return stack_forced_step_due(
        (state or {}).get("execution_trace"), detect=WORDPRESS_DETECT, surface=WORDPRESS_SURFACE,
    )


def registry_step_due(state: Optional[Dict[str, Any]]) -> bool:
    return stack_forced_step_due(
        (state or {}).get("execution_trace"), detect=REGISTRY_DETECT, surface=REGISTRY_SURFACE,
    )
