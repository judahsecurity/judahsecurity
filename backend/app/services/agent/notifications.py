"""Event-driven, opt-in agent notifications.

Endpoint records contain only an environment-variable reference. Webhook URLs,
SMTP credentials, and signing secrets remain outside the database.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import os
import socket
import urllib.parse
import urllib.request
from datetime import datetime
from typing import Any

from app.db.database import SessionLocal
from app.models.agent_runtime import (
    AgentNotificationDelivery,
    AgentNotificationEndpoint,
)

logger = logging.getLogger(__name__)

ACTIONABLE_EVENTS = {
    "run.waiting",
    "run.completed",
    "run.failed",
    "run.cancelled",
    "finding.verified",
    "finding.published",
}

_SEVERITY = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise ValueError("notification webhook redirects are not allowed")


def dispatch_event(event: Any) -> int:
    raw = event.to_dict() if hasattr(event, "to_dict") else dict(event)
    if raw.get("event_type") not in ACTIONABLE_EVENTS:
        return 0
    db = SessionLocal()
    delivered = 0
    try:
        endpoints = (
            db.query(AgentNotificationEndpoint)
            .filter(
                AgentNotificationEndpoint.organization_id == int(raw["organization_id"]),
                AgentNotificationEndpoint.enabled.is_(True),
            )
            .all()
        )
        for endpoint in endpoints:
            if endpoint.event_types and raw["event_type"] not in endpoint.event_types:
                continue
            if not _severity_allowed(raw.get("severity"), endpoint.minimum_severity):
                continue
            prior = (
                db.query(AgentNotificationDelivery)
                .filter(
                    AgentNotificationDelivery.endpoint_id == endpoint.id,
                    AgentNotificationDelivery.event_id == raw["event_id"],
                )
                .first()
            )
            if prior and prior.status == "delivered":
                continue
            delivery = prior or AgentNotificationDelivery(
                endpoint_id=endpoint.id,
                event_id=raw["event_id"],
                status="pending",
            )
            if prior is None:
                db.add(delivery)
                db.flush()
            delivery.attempts = int(delivery.attempts or 0) + 1
            try:
                _deliver(endpoint.channel, endpoint.config_ref, raw)
                delivery.status = "delivered"
                delivery.delivered_at = datetime.utcnow()
                delivery.error_message = None
                delivered += 1
            except Exception as exc:
                delivery.status = "failed"
                delivery.error_message = str(exc)[:2000]
                logger.warning(
                    "agent notification failed endpoint=%s event=%s: %s",
                    endpoint.id,
                    raw.get("event_id"),
                    exc,
                )
        db.commit()
        return delivered
    except Exception:
        db.rollback()
        logger.debug("agent notification dispatch skipped", exc_info=True)
        return delivered
    finally:
        db.close()


def _severity_allowed(actual: Any, minimum: Any) -> bool:
    if not minimum:
        return True
    return _SEVERITY.get(str(actual or "info").lower(), 0) >= _SEVERITY.get(
        str(minimum).lower(), 0
    )


def _deliver(channel: str, config_ref: str, event: dict[str, Any]) -> None:
    destination = (os.environ.get(config_ref) or "").strip()
    if not destination:
        raise ValueError(f"notification destination env {config_ref!r} is not configured")
    channel = (channel or "").strip().lower()
    if channel == "email":
        from app.services.agent.scheduled_hunt import notify_emails

        addresses = [item.strip() for item in destination.split(",") if item.strip()]
        subject = f"Judah agent: {event['event_type']} ({event['run_id'][:12]})"
        if not notify_emails(addresses, subject, _event_text(event)):
            raise RuntimeError("email delivery was not accepted")
        return
    if channel in ("webhook", "slack", "teams"):
        _post_webhook(destination, channel, event)
        return
    raise ValueError(f"unsupported notification channel: {channel!r}")


def _post_webhook(url: str, channel: str, event: dict[str, Any]) -> None:
    _validate_webhook_url(url)
    if channel == "slack":
        payload: dict[str, Any] = {"text": _event_text(event)}
    elif channel == "teams":
        payload = {"text": _event_text(event)}
    else:
        payload = event
    body = json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "judah-agent-notifier/1.0",
        "X-Judah-Event": str(event["event_type"]),
        "X-Judah-Event-Id": str(event["event_id"]),
    }
    secret = os.environ.get("AGENT_NOTIFICATION_SIGNING_SECRET") or ""
    if secret:
        headers["X-Judah-Signature-256"] = "sha256=" + hmac.new(
            secret.encode("utf-8"), body, hashlib.sha256
        ).hexdigest()
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    opener = urllib.request.build_opener(_NoRedirect)
    with opener.open(request, timeout=5) as response:
        if not 200 <= getattr(response, "status", 500) < 300:
            raise RuntimeError(f"webhook returned HTTP {response.status}")


def _validate_webhook_url(url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("notification webhooks require an https URL without userinfo")
    allow_private = os.environ.get("AGENT_NOTIFICATION_ALLOW_PRIVATE", "").lower() in (
        "1",
        "true",
        "yes",
    )
    if allow_private:
        return
    for info in socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM):
        address = ipaddress.ip_address(info[4][0])
        if not address.is_global:
            raise ValueError("notification webhook resolves to a non-public address")


def _event_text(event: dict[str, Any]) -> str:
    payload = dict(event.get("payload") or {})
    summary = payload.get("error") or payload.get("message") or payload.get("phase") or ""
    return (
        f"Judah agent event {event.get('event_type')}\n"
        f"Run: {event.get('run_id')}\n"
        f"Severity: {event.get('severity') or 'info'}\n"
        f"{str(summary)[:1500]}"
    ).strip()
