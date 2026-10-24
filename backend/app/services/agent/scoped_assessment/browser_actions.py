"""Small, reviewable controls for browser discovery actions."""

from __future__ import annotations

import re
from urllib.parse import urlsplit


MAX_DISCOVERY_ACTIONS = 6
MAX_GET_FORM_ACTIONS = 4
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


def safe_get_form_field(form: dict) -> str:
    """Select one inert search field; never submit a write or credential form."""
    if str(form.get("method") or "").upper() != "GET":
        return ""
    path = urlsplit(str(form.get("action") or "")).path or "/"
    if (not allowed_discovery_path(path)
            or re.search(r"(?:^|/)(?:subscribe|signup|register|checkout|cart)(?:/|$)", path, re.I)):
        return ""
    fields = form.get("fields") or []
    if not isinstance(fields, list) or len(fields) > 8:
        return ""
    visible = []
    for field in fields:
        if not isinstance(field, dict):
            return ""
        name = str(field.get("name") or "")
        kind = str(field.get("control_type") or "").lower()
        if (not name or re.search(r"csrf|xsrf|nonce|token|password|secret|action|delete|remove", name, re.I)
                or kind in {"password", "file", "checkbox", "radio"}):
            return ""
        if kind == "hidden":
            continue
        if kind not in {"search", "text"}:
            return ""
        visible.append(name)
    return visible[0] if len(visible) == 1 else ""
