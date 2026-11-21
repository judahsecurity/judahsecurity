"""Regex block-list checked immediately before an agent tool executes.

Scope enforcement (``assessment_scope``) is an allow-list: it decides which
hosts an assessment may touch. This guard is the opposite, defence-in-depth
layer: a short list of destinations that must never be touched, whatever the
scope says, matched against the *whole* call. It inspects the tool name, the
serialized arguments, every nested key and string (including JSON-encoded
strings such as ``execute_*`` ``args``), and up to three rounds of URL
percent-decoding, so ``x%252Egov`` and a host buried in a nested body are both
caught.

The guard never executes anything. A blocked call returns a ``blocked`` result
that is distinct from a tool failure, so ledgers and metrics can count it on
its own.

Configuration (``app.core.config.settings``):

* ``AGENT_TOOL_GUARD_ENABLED`` — master switch (default on).
* ``AGENT_TOOL_GUARD_DEFAULT_RULES`` — include the built-in government /
  military domain rule (default on). Turn off for engagements that are
  authorized against such targets.
* ``AGENT_TOOL_GUARD_RULES`` — JSON list of extra rules:
  ``[{"name": "...", "pattern": "...", "reminder": "...", "enabled": true}]``.
  The first matching enabled rule wins. ``reminder`` may use ``{match}``,
  ``{tool}`` and ``{rule}``; a named group ``(?P<match>...)`` selects the
  reported text.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Iterable, Iterator, List, Optional, Sequence
from urllib.parse import unquote_plus

logger = logging.getLogger(__name__)

MAX_RULES = 100
MAX_PATTERN_BYTES = 4096
MAX_REMINDER_BYTES = 4096
DECODE_ROUNDS = 3
# Bound the work per call: nested walks stop after this many strings, and a
# single string longer than this is checked only on its leading slice.
MAX_STRINGS = 2000
MAX_STRING_CHARS = 200_000

DEFAULT_REMINDER = (
    "TOOL GUARD: '{tool}' was blocked before execution by rule '{rule}' "
    "(matched '{match}'). The request was not sent. Do not retry it or "
    "re-encode the destination; choose an in-scope target instead."
)

# Government and military domains: x.gov, a.b.gov.uk, *.mil, gov.cn.
# The trailing lookahead rejects longer hosts such as gov.uk.example.com and
# words such as "government".
GOVERNMENT_DOMAIN_PATTERN = (
    r"(?i)(?<![a-z0-9-])(?P<match>"
    r"(?:(?:\*|[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)\.)+(?:gov|mil)(?:\.[a-z]{2})?"
    r"|(?:gov|mil)\.[a-z]{2}"
    r")(?!\.?[a-z0-9-])"
)

DEFAULT_RULES: tuple = (
    {
        "name": "government-domains",
        "pattern": GOVERNMENT_DOMAIN_PATTERN,
        "reminder": "",
        "enabled": True,
    },
)

# Tools that only read platform data (inventory, notes, memory) emit no
# target traffic, so a .gov asset name in a query is not blocked.
EXEMPT_TOOLS = frozenset({
    "get_tool_execution",
    "wait_tool_execution",
    "cancel_tool_execution",
    "list_tool_executions",
})


class ToolGuardConfigError(ValueError):
    pass


@dataclass(frozen=True)
class GuardRule:
    name: str
    pattern: "re.Pattern[str]"
    reminder: str = ""
    enabled: bool = True


@dataclass(frozen=True)
class GuardDecision:
    blocked: bool
    rule: str = ""
    match: str = ""
    message: str = ""

    def to_result(self, tool_name: str) -> dict:
        return {
            "success": False,
            "blocked": True,
            "error": "blocked_by_guard",
            "reason": self.rule,
            "output": self.message,
        }


def compile_rules(raw_rules: Iterable[dict]) -> List[GuardRule]:
    """Validate and compile rule dicts. Raises ``ToolGuardConfigError``."""
    rules: List[GuardRule] = []
    for index, raw in enumerate(raw_rules or []):
        if len(rules) >= MAX_RULES:
            raise ToolGuardConfigError(f"at most {MAX_RULES} tool guard rules are allowed")
        if not isinstance(raw, dict):
            raise ToolGuardConfigError(f"rule {index} must be an object")
        name = str(raw.get("name") or f"rule-{index + 1}").strip()[:120]
        pattern = raw.get("pattern")
        if not isinstance(pattern, str) or not pattern.strip():
            raise ToolGuardConfigError(f"rule '{name}' needs a non-empty pattern")
        if len(pattern.encode("utf-8")) > MAX_PATTERN_BYTES:
            raise ToolGuardConfigError(f"rule '{name}' pattern exceeds {MAX_PATTERN_BYTES} bytes")
        reminder = str(raw.get("reminder") or "")
        if len(reminder.encode("utf-8")) > MAX_REMINDER_BYTES:
            raise ToolGuardConfigError(f"rule '{name}' reminder exceeds {MAX_REMINDER_BYTES} bytes")
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            raise ToolGuardConfigError(f"rule '{name}' has an invalid pattern: {exc}") from exc
        rules.append(GuardRule(name=name, pattern=compiled, reminder=reminder,
                               enabled=bool(raw.get("enabled", True))))
    return rules


def _decoded_variants(text: str) -> Iterator[str]:
    yield text
    current = text
    for _ in range(DECODE_ROUNDS):
        if "%" not in current and "+" not in current:
            return
        decoded = unquote_plus(current)
        if decoded == current:
            return
        current = decoded
        yield current


def _walk_strings(value: Any, budget: List[int], depth: int = 0) -> Iterator[str]:
    if budget[0] <= 0 or depth > 32:
        return
    if isinstance(value, dict):
        for key, item in value.items():
            budget[0] -= 1
            yield str(key)
            yield from _walk_strings(item, budget, depth + 1)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _walk_strings(item, budget, depth + 1)
    elif isinstance(value, str):
        budget[0] -= 1
        text = value[:MAX_STRING_CHARS]
        yield text
        stripped = text.strip()
        if stripped[:1] in ("{", "[") and depth < 8:
            try:
                parsed = json.loads(stripped)
            except (ValueError, TypeError):
                parsed = None
            if isinstance(parsed, (dict, list)):
                yield from _walk_strings(parsed, budget, depth + 1)


def candidate_texts(tool_name: str, tool_args: Any) -> Iterator[str]:
    """Every text the guard inspects for one call, decoded variants included."""
    try:
        serialized = json.dumps(tool_args, sort_keys=True, default=str)[:MAX_STRING_CHARS]
    except (TypeError, ValueError):
        serialized = str(tool_args)[:MAX_STRING_CHARS]
    sources = [str(tool_name or ""), serialized]
    budget = [MAX_STRINGS]
    seen = set()
    for text in [*sources, *_walk_strings(tool_args, budget)]:
        for variant in _decoded_variants(text):
            if variant and variant not in seen:
                seen.add(variant)
                yield variant


def _render(rule: GuardRule, tool_name: str, matched: str) -> str:
    template = rule.reminder or DEFAULT_REMINDER
    safe = {"match": matched[:200], "tool": tool_name, "rule": rule.name}
    try:
        return template.format(**safe)
    except (KeyError, IndexError, ValueError):
        return DEFAULT_REMINDER.format(**safe)


def evaluate(
    tool_name: str,
    tool_args: Any,
    rules: Sequence[GuardRule],
    *,
    ignore_enabled: bool = False,
) -> GuardDecision:
    """Return the first enabled rule that matches this call, if any."""
    active = [rule for rule in rules if ignore_enabled or rule.enabled]
    if not active:
        return GuardDecision(blocked=False)
    for text in candidate_texts(tool_name, tool_args):
        for rule in active:
            found = rule.pattern.search(text)
            if not found:
                continue
            try:
                matched = found.group("match")
            except IndexError:
                matched = found.group(0)
            matched = matched or found.group(0)
            return GuardDecision(
                blocked=True, rule=rule.name, match=matched,
                message=_render(rule, tool_name, matched),
            )
    return GuardDecision(blocked=False)


_cache_key: Optional[tuple] = None
_cache_rules: List[GuardRule] = []


def configured_rules() -> List[GuardRule]:
    """Rules from settings, compiled once per distinct configuration.

    An invalid custom rule set is logged and ignored, so a configuration
    mistake never disables the built-in rule.
    """
    global _cache_key, _cache_rules
    from app.core.config import settings

    enabled = bool(getattr(settings, "AGENT_TOOL_GUARD_ENABLED", True))
    defaults = bool(getattr(settings, "AGENT_TOOL_GUARD_DEFAULT_RULES", True))
    custom_raw = getattr(settings, "AGENT_TOOL_GUARD_RULES", "") or ""
    key = (enabled, defaults, custom_raw)
    if key == _cache_key:
        return _cache_rules
    rules: List[GuardRule] = []
    if enabled:
        if defaults:
            rules.extend(compile_rules(DEFAULT_RULES))
        if custom_raw:
            try:
                parsed = json.loads(custom_raw) if isinstance(custom_raw, str) else custom_raw
                rules.extend(compile_rules(parsed if isinstance(parsed, list) else []))
            except (ValueError, ToolGuardConfigError) as exc:
                logger.error("AGENT_TOOL_GUARD_RULES ignored: %s", exc)
    _cache_key, _cache_rules = key, rules[:MAX_RULES]
    return _cache_rules


def check_tool_call(tool_name: str, tool_args: Any) -> GuardDecision:
    """Guard entry point used by the agent tool manager."""
    if tool_name in EXEMPT_TOOLS:
        return GuardDecision(blocked=False)
    try:
        from app.services.agent.confirmation_service import READONLY_TOOLS
    except Exception:  # pragma: no cover - import guard
        READONLY_TOOLS = frozenset()
    if tool_name in READONLY_TOOLS:
        return GuardDecision(blocked=False)
    return evaluate(tool_name, tool_args, configured_rules())
