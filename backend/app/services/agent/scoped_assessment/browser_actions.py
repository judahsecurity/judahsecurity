"""Small, reviewable controls for browser discovery actions."""

from __future__ import annotations

import re


MAX_DISCOVERY_ACTIONS = 6
_OPERATOR_ACTION = re.compile(
    r"(?:check|get|view)\s+(?:stock|availability)|search|filter|subscribe",
    re.I,
)
_DESTRUCTIVE = re.compile(
    r"\b(delete|remove|sign\s*out|log\s*out|purchase|pay|submit|save|send|create|update|reset|confirm|unsubscribe)\b",
    re.I,
)
_UNSAFE_PATH_SEGMENT = re.compile(
    r"^(?:delete|remove|logout|signout|purchase|pay|submit|save|send|create|update|reset|confirm|unsubscribe)(?:$|[-_])",
    re.I,
)


def allowed_discovery_path(path: str) -> bool:
    """Avoid GET links whose route name suggests a state change."""
    return not any(_UNSAFE_PATH_SEGMENT.match(segment) for segment in path.split("/") if segment)


def allowed_discovery_control(*, kind: str, label: str, in_form: bool,
                              button_type: str = "") -> bool:
    """Allow only tab or disclosure controls outside forms during discovery."""
    return (
        kind in {"tab", "disclosure", "summary"}
        and not in_form
        and button_type.lower() != "submit"
        and bool(label.strip())
        and not _DESTRUCTIVE.search(label)
    )


def allowed_operator_action(label: str) -> bool:
    """Narrow set of controls eligible for an explicitly approved page path."""
    return bool(_OPERATOR_ACTION.fullmatch(" ".join(label.split())))
