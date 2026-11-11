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


_EXPLOIT_DEV_ACTION = re.compile(
    r"\b(?:exploit\s+develop(?:ment)?|develop(?:ing)?\s+(?:an?\s+)?exploit"
    r"|proof[- ]of[- ]concept\s+exploit|custom\s+(?:python\s+)?(?:probe|poc|exploit)"
    r"|write\s+(?:an?\s+)?exploit|poc\s+develop(?:ment)?)\b",
    re.IGNORECASE,
)
_EXPLOIT_DEV_NEGATIVE = re.compile(
    r"\b(?:no|avoid|without|exclude|never|do\s+not|don['’]t)\b.{0,80}"
    r"\b(?:exploits?|custom\s+prob\w*|pocs?|proof[- ]of[- ]concept)",
    re.IGNORECASE,
)
_EXPLOIT_DEV_POSITIVE = re.compile(
    r"\b(?:authorize|allow|permit|enable|use|run|perform)\b.{0,80}"
    r"\b(?:exploit\s+develop|custom\s+(?:python\s+)?(?:probe|poc|exploit)|poc\s+develop)\b",
    re.IGNORECASE,
)


def exploit_dev_allowed(objective: str, operator_policy: dict | None = None) -> bool:
    """Gate the free-form Python PoC sandbox behind an explicit operator grant.

    The sandbox executes model-authored Python against in-scope hosts. An
    ordinary assessment does not authorize it; the operator opts in with a
    structured ``exploit_dev_allowed`` flag (or an unambiguous objective).
    """
    text = str(objective or "")
    if _EXPLOIT_DEV_NEGATIVE.search(text):
        return False
    if isinstance(operator_policy, dict) and operator_policy.get("exploit_dev_allowed") is True:
        return True
    return bool(_EXPLOIT_DEV_ACTION.search(text) and _EXPLOIT_DEV_POSITIVE.search(text))


def permitted_specialists(names: Iterable[str], *, allow_credential_testing: bool) -> list[str]:
    """Keep a credential assault hypothesis from silently entering an auto wave."""
    return [
        name for name in names
        if allow_credential_testing or name != "credential_assault"
    ]
