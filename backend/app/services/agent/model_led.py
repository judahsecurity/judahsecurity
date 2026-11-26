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


# --- advisory steering for the deterministic assessment pipeline ------------
#
# In "strict" mode every step tester_loop.forced_next_step returns replaces the
# model's decision. In "advisory" mode a pipeline step is first shown to the
# model as a suggestion; the model gets ``free_turns`` of its own decisions
# after the last forced step, and only then is the pipeline step forced. The
# pipeline still runs to completion, but the model can chase a live lead
# between steps instead of being driven straight through the checklist.

STEERING_MODES = ("strict", "advisory")
DEFAULT_STEERING_FREE_TURNS = 2

# Steps that stay forced in every mode: the initial application map (nothing
# can be hunted without it), proof bookkeeping (a confirmed candidate must
# not wait behind the model's curiosity), and the bounded first pass over
# observed inputs. Without the last, a deep run spent its free turns crawling
# again and its request budget ran out before the SQLi/XSS true-vs-false
# checks on already-observed parameters ever ran.
ALWAYS_FORCED_TOOLS = frozenset({
    "execute_interceptor",
    "execute_deep_crawl",
    # Seeds observed-input hypotheses from the map; sends no target traffic.
    "sync_engagement_brain",
    # Capped (32 checks, 180 s) SQLi/XSS first passes on observed inputs.
    "probe_observed_input_batch",
    "independent_verify",
    "submit_finding_candidate",
    "create_finding",
    "validate_finding",
    "check_cve_applicability",
    "probe_pilot_ports",
})
_ALWAYS_FORCED_BROWSER_OPERATIONS = frozenset({"map", "crawl", "inspect_js"})


def steering_mode() -> str:
    from app.core.config import settings

    # A deep assessment always steers advisory for that run, whatever the
    # global default, so the model chooses steps after recon.
    try:
        from app.services.agent.assessment_depth import assessment_depth

        if assessment_depth().name == "deep":
            return "advisory"
    except Exception:
        pass
    mode = str(getattr(settings, "AGENT_STEERING_MODE", "strict") or "strict").strip().lower()
    return mode if mode in STEERING_MODES else "strict"


def steering_free_turns() -> int:
    from app.core.config import settings

    try:
        value = int(getattr(settings, "AGENT_STEERING_FREE_TURNS", DEFAULT_STEERING_FREE_TURNS))
    except (TypeError, ValueError):
        return DEFAULT_STEERING_FREE_TURNS
    return max(0, min(value, 10))


def always_forced(step: Optional[Dict[str, Any]]) -> bool:
    """True for pipeline steps advisory mode must never defer."""
    if not isinstance(step, dict):
        return False
    name = str(step.get("tool_name") or "")
    if name in ALWAYS_FORCED_TOOLS:
        return True
    if name == "scoped_browser_assessment":
        args = step.get("tool_args") or {}
        operation = str(args.get("operation") or "") if isinstance(args, dict) else ""
        return operation in _ALWAYS_FORCED_BROWSER_OPERATIONS
    return False


def model_turns_since_forced(trace: Optional[Iterable[Any]]) -> int:
    """Count the model's own decisions after the most recent forced step."""
    count = 0
    for step in reversed([s for s in trace or [] if isinstance(s, dict)]):
        source = step.get("decision_source")
        if source == "forced":
            break
        if source == "model":
            count += 1
    return count


def pipeline_step_due(
    state: Optional[Dict[str, Any]],
    step: Optional[Dict[str, Any]],
    *,
    mode: Optional[str] = None,
    free_turns: Optional[int] = None,
) -> bool:
    """Whether a forced pipeline step should replace the model's decision now."""
    if not step:
        return False
    state = state or {}
    mode = steering_mode() if mode is None else mode
    if mode != "advisory" or state.get("mode") == "pilot" or always_forced(step):
        return True
    free_turns = steering_free_turns() if free_turns is None else free_turns
    return model_turns_since_forced(state.get("execution_trace")) >= free_turns


def format_pipeline_suggestion(step: Dict[str, Any], free_turns_left: int) -> str:
    """Prompt block that presents a deferred pipeline step to the model."""
    try:
        args = json.dumps(step.get("tool_args") or {}, default=str)[:600]
    except (TypeError, ValueError):
        args = str(step.get("tool_args") or {})[:600]
    return (
        "## Suggested pipeline step (advisory)\n"
        f"The assessment pipeline would run next: {step.get('tool_name')} {args}\n"
        f"Why: {step.get('thought') or 'next coverage step'}\n"
        "If a concrete lead from the evidence so far is worth more (an error that "
        "leaks a path, a parameter that behaved oddly, a chain step whose "
        "prerequisite just landed), pursue it now and say why in reasoning. "
        "Otherwise take the suggested step. "
        f"The pipeline step runs automatically after {max(0, free_turns_left)} more "
        "of your own decisions, and completion stays blocked until coverage is met."
    )
