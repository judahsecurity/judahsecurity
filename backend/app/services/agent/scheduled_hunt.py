"""Scheduled /skill tester-process hunts (ScanSchedule scan_type=tester_process)."""

from __future__ import annotations

import logging
import os
import smtplib
from email.message import EmailMessage
from typing import Any, Iterable, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def _as_url(raw: str) -> str:
    text = (raw or "").strip()
    if not text:
        return ""
    if text.startswith("http://") or text.startswith("https://"):
        return text.split()[0]
    parsed = urlparse("https://" + text.split()[0])
    if parsed.netloc and "." in parsed.netloc:
        return f"https://{parsed.netloc}"
    return ""


def web_targets(raw: Iterable[str], *, limit: int = 3) -> List[str]:
    out: List[str] = []
    seen = set()
    for item in raw or []:
        url = _as_url(str(item))
        if not url or url in seen:
            continue
        seen.add(url)
        out.append(url)
        if len(out) >= limit:
            break
    return out


def notify_emails(addresses: Iterable[str], subject: str, body: str) -> bool:
    addrs = [a.strip() for a in (addresses or []) if a and "@" in str(a)]
    if not addrs:
        return False
    host = (os.environ.get("SMTP_HOST") or "").strip()
    if not host:
        logger.info("tester-process digest (no SMTP_HOST): %s\n%s", subject, body[:2000])
        return False
    port = int(os.environ.get("SMTP_PORT") or 587)
    user = os.environ.get("SMTP_USER") or ""
    password = os.environ.get("SMTP_PASSWORD") or ""
    sender = os.environ.get("SMTP_FROM") or user or addrs[0]
    msg = EmailMessage()
    msg["Subject"] = subject[:180]
    msg["From"] = sender
    msg["To"] = ", ".join(addrs)
    msg.set_content(body[:12000])
    try:
        with smtplib.SMTP(host, port, timeout=20) as smtp:
            smtp.starttls()
            if user:
                smtp.login(user, password)
            smtp.send_message(msg)
        return True
    except Exception:
        logger.warning("tester-process email failed", exc_info=True)
        return False


async def run_tester_process_targets(
    *,
    organization_id: int,
    user_id: str,
    targets: List[str],
    price_limit_usd: float = 8.0,
    schedule_name: str = "",
) -> dict[str, Any]:
    from app.services.agent.orchestrator import get_agent_orchestrator
    from app.services.agent.playbooks import build_initial_objective

    orch = await get_agent_orchestrator()
    results = []
    for target in targets:
        objective, todos = build_initial_objective("tester_process", target)
        session_id = f"sched-{organization_id}-{abs(hash(target)) % 10_000_000}"
        try:
            resp = await orch.invoke(
                question=objective or f"Run tester-process on {target}",
                user_id=str(user_id),
                organization_id=int(organization_id),
                session_id=session_id,
                initial_todos=todos,
                mode="agent",
                price_limit_usd=price_limit_usd,
            )
            results.append({
                "target": target,
                "error": getattr(resp, "error", None),
                "complete": bool(getattr(resp, "task_complete", False)),
                "cost_usd": getattr(resp, "cost_usd", None),
                "answer": (getattr(resp, "answer", None) or "")[:800],
            })
        except Exception as exc:
            logger.exception("scheduled tester-process failed for %s", target)
            results.append({"target": target, "error": str(exc)[:400]})
    body_lines = [f"Scheduled hunt: {schedule_name or 'tester_process'}"]
    for row in results:
        body_lines.append(
            f"- {row.get('target')}: complete={row.get('complete')} "
            f"cost={row.get('cost_usd')} err={row.get('error') or '-'}"
        )
        if row.get("answer"):
            body_lines.append(str(row["answer"])[:500])
    return {"results": results, "digest": "\n".join(body_lines)}
