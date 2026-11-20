"""Chat notifications (Telegram first): run finished, new agent finding.

Notifications only — the bot accepts no commands. Each organization lists its
own chat IDs in the ``notifications`` project-settings module, so one tenant's
events never reach another tenant's chat. The bot token is a platform secret
(``TELEGRAM_BOT_TOKEN``) and is never logged.

Messages carry a summary (title, severity, asset, status, link), never
evidence, payloads or credentials: chat providers store messages unencrypted.
Delivery runs on a small background pool so a slow or failing chat API never
delays an agent run or a finding write.
"""

from __future__ import annotations

import logging
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, Iterable, List, Optional, Protocol

import httpx

logger = logging.getLogger(__name__)

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
RUN_STATUS_TEXT = {
    "completed": "finished",
    "partial": "finished with partial coverage",
    "paused": "is waiting for your input",
    "cancelled": "was stopped",
    "timeout": "hit its time limit",
    "error": "failed",
}
MAX_MESSAGE_CHARS = 3500  # Telegram limit is 4096
_TOKEN_IN_TEXT = re.compile(r"bot\d+:[A-Za-z0-9_-]+")
_CHAT_ID = re.compile(r"^-?\d{1,20}$|^@[A-Za-z0-9_]{5,32}$")

_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="chat-notify")


class Notifier(Protocol):
    name: str

    def send(self, chat_id: str, text: str) -> None: ...


class NotifierError(RuntimeError):
    pass


class TelegramNotifier:
    name = "telegram"

    def __init__(self, token: str, *, api_base: str = "https://api.telegram.org",
                 timeout: float = 10.0, client: Optional[httpx.Client] = None):
        self._token = token
        self._api_base = api_base.rstrip("/")
        self._timeout = timeout
        self._client = client

    def send(self, chat_id: str, text: str) -> None:
        url = f"{self._api_base}/bot{self._token}/sendMessage"
        payload = {"chat_id": chat_id, "text": text[:MAX_MESSAGE_CHARS],
                   "disable_web_page_preview": True}
        try:
            if self._client is not None:
                response = self._client.post(url, json=payload, timeout=self._timeout)
            else:
                response = httpx.post(url, json=payload, timeout=self._timeout)
        except httpx.HTTPError as exc:
            # httpx messages can include the URL, which contains the token.
            raise NotifierError(f"telegram transport error: {type(exc).__name__}") from None
        if response.status_code != 200:
            try:
                description = str(response.json().get("description") or "")
            except ValueError:
                description = ""
            raise NotifierError(redact(f"telegram HTTP {response.status_code}: {description}"[:300]))


def redact(text: str) -> str:
    return _TOKEN_IN_TEXT.sub("bot[redacted]", str(text or ""))


def valid_chat_ids(raw: Any) -> List[str]:
    """Numeric chat IDs (groups are negative) or @channel usernames."""
    if isinstance(raw, str):
        raw = [part for part in re.split(r"[\s,]+", raw) if part]
    ids = []
    for item in raw or []:
        value = str(item).strip()
        if _CHAT_ID.match(value) and value not in ids:
            ids.append(value)
    return ids[:10]


def default_notifier() -> Optional[Notifier]:
    from app.core.config import settings

    token = (getattr(settings, "TELEGRAM_BOT_TOKEN", "") or "").strip()
    return TelegramNotifier(token) if token else None


def org_config(organization_id: Optional[int]) -> Dict[str, Any]:
    if not organization_id:
        return {}
    from app.db.database import SessionLocal
    from app.models.project_settings import MODULE_NOTIFICATIONS, ProjectSettings

    with SessionLocal() as db:
        return ProjectSettings.get_config(db, int(organization_id), MODULE_NOTIFICATIONS)


def _app_link(path: str) -> str:
    from app.core.config import settings

    base = (getattr(settings, "PUBLIC_APP_URL", "") or "").strip().rstrip("/")
    return f"\n{base}{path}" if base else ""


def _deliver(notifier: Notifier, chat_ids: Iterable[str], text: str) -> Dict[str, str]:
    results = {}
    for chat_id in chat_ids:
        try:
            notifier.send(chat_id, text)
            results[chat_id] = "sent"
        except Exception as exc:  # one bad chat must not stop the others
            results[chat_id] = redact(str(exc))[:300]
            logger.warning("Chat notification to %s failed: %s", chat_id, results[chat_id])
    return results


def dispatch(organization_id: Optional[int], event: str, text: str, *,
             notifier: Optional[Notifier] = None, background: bool = True,
             config: Optional[Dict[str, Any]] = None) -> Optional[Any]:
    """Send ``text`` to the org's chats if the org enabled ``event``.

    Never raises: notification problems are logged, not surfaced to callers.
    """
    try:
        notifier = notifier or default_notifier()
        if notifier is None:
            return None
        cfg = config if config is not None else org_config(organization_id)
        if not cfg.get("telegram_enabled") or not cfg.get(f"notify_{event}", True):
            return None
        chat_ids = valid_chat_ids(cfg.get("telegram_chat_ids"))
        if not chat_ids:
            return None
        if background:
            return _pool.submit(_deliver, notifier, chat_ids, text)
        return _deliver(notifier, chat_ids, text)
    except Exception:
        logger.exception("Chat notification dispatch failed")
        return None


def finding_message(*, finding_id: Any, title: str, severity: str, asset: str,
                    verified: bool) -> str:
    sev = (severity or "info").lower()
    proof = "independently verified" if verified else "published by the agent"
    return (f"{SEVERITY_ICON.get(sev, '⚪')} New {sev.upper()} finding ({proof})\n"
            f"{(title or 'Untitled')[:300]}\n"
            f"Asset: {(asset or '-')[:200]}"
            + _app_link("/findings"))


def notify_finding(organization_id: Optional[int], *, finding_id: Any, title: str,
                   severity: str, asset: str, verified: bool, **kwargs) -> Optional[Any]:
    if kwargs.get("notifier") is None and default_notifier() is None:
        return None
    cfg = kwargs.pop("config", None)
    try:
        cfg = cfg if cfg is not None else org_config(organization_id)
    except Exception:
        logger.exception("Chat notification config unavailable")
        return None
    minimum = str(cfg.get("min_severity") or "high").lower()
    if SEVERITY_RANK.get((severity or "info").lower(), 0) < SEVERITY_RANK.get(minimum, 3):
        return None
    text = finding_message(finding_id=finding_id, title=title, severity=severity,
                           asset=asset, verified=verified)
    return dispatch(organization_id, "findings", text, config=cfg, **kwargs)


def run_message(*, objective: str, status: str, reason: str, session_id: str) -> str:
    what = RUN_STATUS_TEXT.get(status, status)
    target = (objective or "the assessment")[:200]
    text = f"Prowl run on {target} {what}."
    if reason and status not in {"completed"}:
        text += f"\nReason: {reason[:300]}"
    return text + _app_link("/agent")


def notify_run_finished(organization_id: Optional[int], *, objective: str, status: str,
                        reason: str, session_id: str, **kwargs) -> Optional[Any]:
    if status == "running":
        return None
    text = run_message(objective=objective, status=status, reason=reason,
                       session_id=session_id)
    return dispatch(organization_id, "run_finished", text, **kwargs)
