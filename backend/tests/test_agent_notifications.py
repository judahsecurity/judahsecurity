from __future__ import annotations

import socket

import pytest
from app.api.routes.agent_notifications import EndpointCreate
from app.services.agent.notifications import _severity_allowed, _validate_webhook_url
from pydantic import ValidationError


def test_notification_severity_filter() -> None:
    assert _severity_allowed("critical", "high") is True
    assert _severity_allowed("low", "medium") is False
    assert _severity_allowed(None, None) is True


def test_webhooks_require_https_without_userinfo() -> None:
    with pytest.raises(ValueError, match="https"):
        _validate_webhook_url("http://example.com/hook")
    with pytest.raises(ValueError, match="userinfo"):
        _validate_webhook_url("https://user:pass@example.com/hook")


def test_webhooks_reject_private_dns(monkeypatch) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))],
    )
    with pytest.raises(ValueError, match="non-public"):
        _validate_webhook_url("https://hooks.example.test/event")


def test_endpoint_stores_an_environment_reference_not_a_destination() -> None:
    endpoint = EndpointCreate(
        name="security-slack",
        channel="slack",
        config_ref="AGENT_SLACK_WEBHOOK",
    )
    assert endpoint.config_ref == "AGENT_SLACK_WEBHOOK"
    with pytest.raises(ValidationError, match="environment-variable"):
        EndpointCreate(
            name="bad",
            channel="webhook",
            config_ref="https://hooks.example.test/secret",
        )
