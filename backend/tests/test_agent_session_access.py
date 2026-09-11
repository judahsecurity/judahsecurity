from __future__ import annotations

from types import SimpleNamespace

import pytest
from app.api.routes.agent import _require_agent_session_access
from app.services.agent import runtime_store
from fastapi import HTTPException


class _Query:
    def __init__(self, value=None):
        self.value = value

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return self.value


class _DB:
    def __init__(self, conversation=None):
        self.conversation = conversation

    def query(self, *args, **kwargs):
        return _Query(self.conversation)


def test_run_owner_can_issue_control_commands(monkeypatch) -> None:
    monkeypatch.setattr(
        runtime_store,
        "safe_call",
        lambda *args, **kwargs: {"organization_id": 7, "user_id": 42},
    )
    user = SimpleNamespace(id=42, is_superuser=False)
    _require_agent_session_access("run-1", user, 7, _DB())


def test_other_user_cannot_control_or_register_existing_session(monkeypatch) -> None:
    monkeypatch.setattr(
        runtime_store,
        "safe_call",
        lambda *args, **kwargs: {"organization_id": 7, "user_id": 42},
    )
    other = SimpleNamespace(id=99, is_superuser=False)
    with pytest.raises(HTTPException) as raised:
        _require_agent_session_access("run-1", other, 7, _DB(), require_exists=False)
    assert raised.value.status_code == 404


def test_new_websocket_session_is_allowed_after_authentication(monkeypatch) -> None:
    monkeypatch.setattr(runtime_store, "safe_call", lambda *args, **kwargs: None)
    user = SimpleNamespace(id=42, is_superuser=False)
    _require_agent_session_access("new-run", user, 7, _DB(), require_exists=False)
