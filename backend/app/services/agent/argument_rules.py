"""Argument rules: approval decisions that look at *how* a tool is called.

The per-tool confirmation policy (``tool_confirmation_policy``) only sees the
tool name. Argument rules refine it per call, from the org agent config key
``tool_argument_rules``::

    [
      # curl GETs and HEADs may run without asking ...
      {"tool": "execute_curl", "decision": "auto",
       "argv_prefix": ["-X", "GET"], "allow_flags": ["-s", "-i", "-H", "-k"]},
      # ... but anything that deletes is refused outright.
      {"tool": "execute_curl", "decision": "deny", "contains": ["-X", "DELETE"]},
      # Structured tools are matched on their fields.
      {"tool": "replay_http_request", "decision": "auto",
       "fields": {"method": ["GET", "HEAD"]}},
    ]

Matching is fail-closed:

* ``auto`` rules are narrow. ``argv_prefix`` must match the start of the
  parsed command, and every remaining flag must be listed in ``allow_flags``
  (a rule for ``git push`` does not cover ``git push --force``). ``fields``
  must all be present and hold one of the allowed values.
* ``deny`` and ``confirm`` rules are broad. ``contains`` matches the token
  sequence anywhere in the command, and ``argv_prefix`` matches regardless of
  extra flags.
* If the tool has any argument rule and its command cannot be parsed (bad
  quoting, shell substitution or chaining), the call is sent to an analyst.
  It is never allowed on the strength of a rule it could not be checked
  against.

Pure functions only; :mod:`confirmation_service` decides how the result
combines with RoE, pilot and login-crawl escalations.
"""

from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass
from fnmatch import fnmatch
from typing import Any, Iterable, Optional

DECISIONS = ("auto", "confirm", "deny")
_SHELL_META = re.compile(r"\$\(|`|;|&&|\|\||\||>|<|\n")
_COMMAND_KEYS = ("args", "command", "cmd", "argv")


@dataclass(frozen=True)
class ArgumentVerdict:
    """Outcome for one call. ``decision`` is None when no rule applies."""

    decision: Optional[str] = None
    rule_index: Optional[int] = None
    reason: str = ""

    @property
    def unparseable(self) -> bool:
        return self.reason == "unparseable"


def parse_argv(tool_args: Any) -> Optional[list[str]]:
    """Return the call's argv tokens, ``[]`` when it has none, None if unsafe."""
    if not isinstance(tool_args, dict):
        return []
    raw = None
    for key in _COMMAND_KEYS:
        if key in tool_args:
            raw = tool_args[key]
            break
    if raw is None:
        return []
    if isinstance(raw, list):
        if not all(isinstance(tok, str) for tok in raw):
            return None
        tokens = list(raw)
        return None if any(_SHELL_META.search(tok) for tok in tokens) else tokens
    if not isinstance(raw, str):
        return None
    stripped = raw.strip()
    if stripped.startswith(("{", "[")):
        # Structured options (e.g. browser action JSON) are matched via fields.
        try:
            json.loads(stripped)
            return []
        except ValueError:
            return None
    if _SHELL_META.search(raw):
        return None
    try:
        return shlex.split(raw)
    except ValueError:
        return None


def _norm(value: Any) -> str:
    return str(value).strip().lower()


def _contains_seq(tokens: list[str], seq: list[str]) -> bool:
    if not seq:
        return False
    lowered = [_norm(t) for t in tokens]
    target = [_norm(t) for t in seq]
    n = len(target)
    return any(lowered[i:i + n] == target for i in range(len(lowered) - n + 1))


def _flag_name(token: str) -> str:
    return token.split("=", 1)[0]


def _fields_match(tool_args: dict, fields: dict, *, strict: bool) -> bool:
    for key, allowed in fields.items():
        if key not in tool_args:
            if strict:
                return False
            continue
        values = allowed if isinstance(allowed, (list, tuple, set)) else [allowed]
        if _norm(tool_args[key]) not in {_norm(v) for v in values}:
            return False
    return True


def _auto_matches(rule: dict, tool_args: dict, argv: list[str]) -> bool:
    prefix = [str(t) for t in rule.get("argv_prefix") or []]
    fields = rule.get("fields") or {}
    if not prefix and not fields:
        return False  # an auto rule must say what it allows
    if fields and not (isinstance(tool_args, dict) and _fields_match(tool_args, fields, strict=True)):
        return False
    if prefix:
        if [_norm(t) for t in argv[:len(prefix)]] != [_norm(t) for t in prefix]:
            return False
        allowed = {_norm(f) for f in rule.get("allow_flags") or []}
        rest = argv[len(prefix):]
        for tok in rest:
            if tok.startswith("-") and _norm(_flag_name(tok)) not in allowed:
                return False
    return True


def _broad_matches(rule: dict, tool_args: dict, argv: list[str]) -> bool:
    prefix = [str(t) for t in rule.get("argv_prefix") or []]
    contains = [str(t) for t in rule.get("contains") or []]
    fields = rule.get("fields") or {}
    if not (prefix or contains or fields):
        return True  # a bare deny/confirm rule applies to every call of the tool
    if prefix and [_norm(t) for t in argv[:len(prefix)]] == [_norm(t) for t in prefix]:
        return True
    if contains and _contains_seq(argv, contains):
        return True
    if fields and isinstance(tool_args, dict) and any(
        key in tool_args and _fields_match(tool_args, {key: val}, strict=True)
        for key, val in fields.items()
    ):
        return True
    return False


def valid_rules(rules: Any) -> list[tuple[int, dict]]:
    if not isinstance(rules, list):
        return []
    out = []
    for idx, rule in enumerate(rules):
        if (isinstance(rule, dict) and isinstance(rule.get("tool"), str)
                and rule.get("decision") in DECISIONS):
            out.append((idx, rule))
    return out


def evaluate(tool_name: str, tool_args: Any, rules: Iterable[Any] | Any) -> ArgumentVerdict:
    """Strongest matching rule wins: deny > confirm > auto."""
    applicable = [(i, r) for i, r in valid_rules(rules) if fnmatch(tool_name, r["tool"])]
    if not applicable:
        return ArgumentVerdict()
    argv = parse_argv(tool_args)
    if argv is None:
        return ArgumentVerdict("confirm", None, "unparseable")
    args = tool_args if isinstance(tool_args, dict) else {}
    for wanted in ("deny", "confirm"):
        for idx, rule in applicable:
            if rule["decision"] == wanted and _broad_matches(rule, args, argv):
                return ArgumentVerdict(wanted, idx, f"argument rule {idx}")
    for idx, rule in applicable:
        if rule["decision"] == "auto" and _auto_matches(rule, args, argv):
            return ArgumentVerdict("auto", idx, f"argument rule {idx}")
    return ArgumentVerdict()


__all__ = ["ArgumentVerdict", "DECISIONS", "evaluate", "parse_argv", "valid_rules"]
