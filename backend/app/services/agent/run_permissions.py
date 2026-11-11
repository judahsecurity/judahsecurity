"""Permissions derived from the operator's run request, never a model mission."""

from __future__ import annotations

import re
from typing import Iterable


_CREDENTIAL_ACTION = re.compile(
    r"\b(?:credential(?:s)?\s+(?:guessing|testing|spray(?:ing)?|stuffing|assault)"
    r"|password\s+(?:guessing|spray(?:ing)?|testing|brute\s*forc(?:e|ing))"
    r"|default\s+(?:credentials|passwords)|weak\s+credentials)\b",
    re.IGNORECASE,
)
_NEGATIVE = re.compile(
    r"(?:\b(?:no|avoid|without|exclude|never|do\s+not|don['’]t)\b.{0,80}"
    r"\b(?:credential|password|default\s+login|brute\s*force)\b"
    r"|\b(?:credential|password|default\s+login|brute\s*force)\b.{0,50}"
    r"\b(?:not\s+allowed|prohibited|forbidden|excluded)\b)",
    re.IGNORECASE,
)
_POSITIVE = re.compile(
    r"\b(?:authorize|allow|permit|include|run|perform|test)\b.{0,80}"
    r"\b(?:credential|password|default\s+login|weak\s+login|brute\s*force)\b",
    re.IGNORECASE,
)
_OOB_ACTION = re.compile(
    r"\b(?:out[- ]of[- ]band|oob|interactsh|collaborator|third[- ]party callbacks?|callbacks?)\b",
    re.IGNORECASE,
)
_OOB_NEGATIVE = re.compile(
    r"\b(?:no|avoid|without|exclude|never|do\s+not|don['’]t)\b.{0,80}"
    r"\b(?:out[- ]of[- ]band|oob|interactsh|collaborator|callbacks?)\b",
    re.IGNORECASE,
)
_OOB_POSITIVE = re.compile(
    r"\b(?:authorize|allow|permit|use|run|perform)\b.{0,80}"
    r"\b(?:out[- ]of[- ]band|oob|interactsh|collaborator|callbacks?)\b",
    re.IGNORECASE,
)


_EXPLOIT_DEV_NEGATIVE = re.compile(
    r"\b(?:no|avoid|without|exclude|never|do\s+not|don['’]t)\b.{0,80}"
    r"\b(?:exploit\s+dev(?:elopment)?|sandbox|exploit\s+workspace|custom\s+exploit)\b",
    re.IGNORECASE,
)
_POST_EXPLOIT_NEGATIVE = re.compile(
    r"\b(?:no|avoid|without|exclude|never|do\s+not|don['’]t)\b.{0,80}"
    r"\b(?:post[- ]exploit(?:ation)?|post[- ]ex)\b",
    re.IGNORECASE,
)


def exploit_dev_allowed(objective: str, operator_policy: dict | None = None) -> bool:
    """Open, sandboxed exploit-development tier. Off unless a structured grant.

    Unlike the probe lanes this is never inferred from objective wording: the
    only way in is an explicit operator flag, and a negative objective still
    vetoes it. Whatever the open tier finds is a lead, not a finding.
    """
    if _EXPLOIT_DEV_NEGATIVE.search(str(objective or "")):
        return False
    return bool(isinstance(operator_policy, dict)
                and operator_policy.get("exploit_dev_allowed") is True)


def post_exploit_allowed(objective: str, operator_policy: dict | None = None) -> bool:
    """Explicit post-exploitation tier (e.g. read a canary, list permissions).

    Requires the structured operator grant *and* the exploit-development tier,
    since post-exploitation presumes a sandbox foothold. A negative objective
    vetoes it. Default off.
    """
    if _POST_EXPLOIT_NEGATIVE.search(str(objective or "")):
        return False
    if not (isinstance(operator_policy, dict)
            and operator_policy.get("post_exploit_allowed") is True):
        return False
    return exploit_dev_allowed(objective, operator_policy)


def credential_testing_allowed(objective: str, operator_policy: dict | None = None) -> bool:
    """Require a clear operator grant; an ordinary full assessment is not one."""
    text = str(objective or "")
    if _NEGATIVE.search(text):
        return False
    if isinstance(operator_policy, dict) and operator_policy.get("credential_testing_allowed") is True:
        return True
    return bool(_CREDENTIAL_ACTION.search(text) and _POSITIVE.search(text))


def oob_callbacks_allowed(objective: str, operator_policy: dict | None = None) -> bool:
    """Do not provision or call an external callback service by default."""
    text = str(objective or "")
    if _OOB_NEGATIVE.search(text):
        return False
    if isinstance(operator_policy, dict) and operator_policy.get("oob_callbacks_allowed") is True:
        return True
    return bool(_OOB_ACTION.search(text) and _OOB_POSITIVE.search(text))


def permitted_specialists(names: Iterable[str], *, allow_credential_testing: bool) -> list[str]:
    """Keep a credential assault hypothesis from silently entering an auto wave."""
    return [
        name for name in names
        if allow_credential_testing or name != "credential_assault"
    ]
