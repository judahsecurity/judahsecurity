"""Opaque, per-run tool-call identities for ledger efficiency metrics."""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any


def _canonical(value: Any) -> Any:
    if isinstance(value, dict):
        # Execution trace is bookkeeping, not part of the requested action.
        return {str(key): _canonical(item) for key, item in value.items()
                if key != "_execution_trace"}
    if isinstance(value, (list, tuple)):
        return [_canonical(item) for item in value]
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith(("{", "[")):
            try:
                return _canonical(json.loads(stripped))
            except (TypeError, ValueError):
                pass
        return value
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)


def action_fingerprint(
    *, run_id: str | None, tool_name: str, target: str,
    tool_args: dict, secret_key: str, verifier_run_id: str = "",
) -> str:
    """HMAC raw action details without exposing URLs, payloads or credentials.

    The verifier run is part of the identity because a fresh proof is a
    separate action even when it replays the same request template.
    """
    if not run_id or not tool_name or not secret_key:
        return ""
    material = json.dumps({
        "tool": tool_name, "target": target, "args": _canonical(tool_args),
        "verifier_run": verifier_run_id,
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    key = hmac.new(secret_key.encode(), run_id.encode(), hashlib.sha256).digest()
    return hmac.new(key, material, hashlib.sha256).hexdigest()
