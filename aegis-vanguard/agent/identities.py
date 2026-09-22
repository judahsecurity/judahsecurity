"""Test identity loading and backwards-compatible credential normalization.

Identity files are JSON arrays (or ``{"identities": [...]}``) containing test
accounts.  Keeping account metadata structured lets authorization and workflow
hunters distinguish users, roles, and tenants instead of treating credentials
as one global login.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional


def load_identities(
    path: Optional[str] = None,
    *,
    username: Optional[str] = None,
    password: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Load and validate a test identity pool.

    ``username``/``password`` remain supported as a single ``default`` identity
    so existing CLI and automation integrations keep working.
    """
    raw: Any = []
    if path:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            raw = raw.get("identities")
        if not isinstance(raw, list):
            raise ValueError("identity file must contain a JSON array or an 'identities' array")

    identities: List[Dict[str, Any]] = []
    for index, item in enumerate(raw or []):
        if not isinstance(item, dict):
            raise ValueError(f"identity #{index + 1} must be a JSON object")
        user = str(item.get("username") or "").strip()
        secret = item.get("password")
        headers = item.get("headers") or {}
        if not user and not headers:
            raise ValueError(
                f"identity #{index + 1} needs a username or session headers"
            )
        if headers and not isinstance(headers, dict):
            raise ValueError(f"identity #{index + 1} headers must be an object")
        login = item.get("login") or {}
        if login and not isinstance(login, dict):
            raise ValueError(f"identity #{index + 1} login must be an object")
        extra_fields = login.get("extra_fields") or {}
        if extra_fields and not isinstance(extra_fields, dict):
            raise ValueError(
                f"identity #{index + 1} login.extra_fields must be an object"
            )
        identities.append({
            "label": str(item.get("label") or f"identity-{index + 1}"),
            "username": user,
            "password": "" if secret is None else str(secret),
            "role": str(item.get("role") or "unknown"),
            "tenant": str(item.get("tenant") or "default"),
            "headers": {str(k): str(v) for k, v in headers.items()},
            "login": {
                "url": str(login.get("url") or ""),
                "action_url": str(login.get("action_url") or ""),
                "method": str(login.get("method") or "").upper(),
                "content_type": str(login.get("content_type") or ""),
                "username_field": str(login.get("username_field") or ""),
                "password_field": str(login.get("password_field") or ""),
                "extra_fields": {
                    str(k): str(v) for k, v in extra_fields.items()
                },
                "verify_url": str(login.get("verify_url") or ""),
                "success_marker": str(login.get("success_marker") or ""),
                "failure_marker": str(login.get("failure_marker") or ""),
                "token_field": str(login.get("token_field") or ""),
            },
        })

    if username:
        identities.insert(0, {
            "label": "default",
            "username": str(username),
            "password": "" if password is None else str(password),
            "role": "unknown",
            "tenant": "default",
            "headers": {},
            "login": {},
        })

    labels = [item["label"] for item in identities]
    if len(labels) != len(set(labels)):
        raise ValueError("identity labels must be unique")
    return identities


def identity_summary(identities: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Return account metadata safe for logs (never passwords or headers)."""
    return [
        {
            "label": str(item.get("label") or "identity"),
            "username": str(item.get("username") or "header-session"),
            "role": str(item.get("role") or "unknown"),
            "tenant": str(item.get("tenant") or "default"),
            "auth_source": (
                "session_headers" if item.get("headers")
                else "credentials" if item.get("username")
                else "unconfigured"
            ),
            "login_configured": str(bool((item.get("login") or {}).get("url"))).lower(),
        }
        for item in identities
    ]


__all__ = ["load_identities", "identity_summary"]
