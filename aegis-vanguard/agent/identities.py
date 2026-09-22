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
        identities.append({
            "label": str(item.get("label") or f"identity-{index + 1}"),
            "username": user,
            "password": "" if secret is None else str(secret),
            "role": str(item.get("role") or "unknown"),
            "tenant": str(item.get("tenant") or "default"),
            "headers": {str(k): str(v) for k, v in headers.items()},
        })

    if username:
        identities.insert(0, {
            "label": "default",
            "username": str(username),
            "password": "" if password is None else str(password),
            "role": "unknown",
            "tenant": "default",
            "headers": {},
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
        }
        for item in identities
    ]


__all__ = ["load_identities", "identity_summary"]
