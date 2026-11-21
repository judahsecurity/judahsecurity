"""Telegram notifications: per-org routing, thresholds, token safety, admin-only config."""

import httpx
import pytest

from app.services import chat_notifier
from app.services.chat_notifier import (
    TelegramNotifier, dispatch, notify_finding, notify_run_finished, redact, valid_chat_ids,
)

TOKEN = "123456:ABC-secret_token"


class Recorder:
    name = "fake"

    def __init__(self, fail=()):
        self.sent, self.fail = [], set(fail)

    def send(self, chat_id, text):
        if chat_id in self.fail:
            raise RuntimeError(f"chat {chat_id} blocked the bot")
        self.sent.append((chat_id, text))


CFG = {"telegram_enabled": True, "telegram_chat_ids": ["-1001", "42"],
       "notify_findings": True, "notify_run_finished": True, "min_severity": "high"}


def test_chat_id_validation():
    assert valid_chat_ids(["-1001", "42", "@prowl_alerts", "42", "nope", "1; drop"]) == [
        "-1001", "42", "@prowl_alerts"]
    assert valid_chat_ids("1, -2 3") == ["1", "-2", "3"]


def test_disabled_or_unconfigured_sends_nothing():
    rec = Recorder()
    assert dispatch(1, "findings", "x", notifier=rec, background=False,
                    config={**CFG, "telegram_enabled": False}) is None
    assert dispatch(1, "findings", "x", notifier=rec, background=False,
                    config={**CFG, "telegram_chat_ids": []}) is None
    assert dispatch(1, "findings", "x", notifier=rec, background=False,
                    config={**CFG, "notify_findings": False}) is None
    assert rec.sent == []


def test_no_token_skips_without_db_lookup(monkeypatch):
    def boom(_org):
        raise AssertionError("config must not be loaded without a bot token")

    monkeypatch.setattr(chat_notifier, "default_notifier", lambda: None)
    monkeypatch.setattr(chat_notifier, "org_config", boom)
    assert notify_finding(1, finding_id=1, title="t", severity="critical", asset="a",
                          verified=True) is None
    assert notify_run_finished(1, objective="o", status="completed", reason="",
                               session_id="s") is None


def test_finding_threshold_and_summary_only(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "PUBLIC_APP_URL", "https://prowl.example.com/", raising=False)
    rec = Recorder()
    assert notify_finding(1, finding_id=7, title="Low thing", severity="low", asset="a",
                          verified=False, notifier=rec, background=False, config=CFG) is None
    result = notify_finding(1, finding_id=8, title="SQL injection in /search", severity="critical",
                            asset="app.example.com", verified=True, notifier=rec,
                            background=False, config=CFG)
    assert result == {"-1001": "sent", "42": "sent"}
    text = rec.sent[0][1]
    assert "CRITICAL finding (independently verified)" in text
    assert "SQL injection in /search" in text and "Asset: app.example.com" in text
    assert text.endswith("https://prowl.example.com/findings")


def test_one_failing_chat_does_not_block_others():
    rec = Recorder(fail={"-1001"})
    result = dispatch(1, "run_finished", "hi", notifier=rec, background=False, config=CFG)
    assert result["42"] == "sent" and "blocked" in result["-1001"]


def test_run_message_statuses():
    rec = Recorder()
    notify_run_finished(1, objective="https://app.example.com", status="partial",
                        reason="external time limit", session_id="s", notifier=rec,
                        background=False, config=CFG)
    assert "finished with partial coverage" in rec.sent[0][1]
    assert "Reason: external time limit" in rec.sent[0][1]
    assert notify_run_finished(1, objective="o", status="running", reason="", session_id="s",
                               notifier=rec, background=False, config=CFG) is None


def test_background_delivery():
    rec = Recorder()
    future = dispatch(1, "findings", "bg", notifier=rec, config=CFG)
    assert future.result(timeout=5) == {"-1001": "sent", "42": "sent"}


def test_telegram_request_shape_and_token_never_in_errors():
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        seen["body"] = request.read()
        if b'"chat_id":"bad"' in seen["body"].replace(b" ", b""):
            return httpx.Response(400, json={"ok": False, "description": "Bad Request: chat not found"})
        return httpx.Response(200, json={"ok": True})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    notifier = TelegramNotifier(TOKEN, client=client)
    notifier.send("42", "hello")
    assert seen["url"] == f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    assert b'"disable_web_page_preview":true' in seen["body"].replace(b" ", b"")
    with pytest.raises(chat_notifier.NotifierError) as err:
        notifier.send("bad", "hello")
    assert "chat not found" in str(err.value) and TOKEN not in str(err.value)

    def down(_request):
        raise httpx.ConnectError(f"cannot reach https://api.telegram.org/bot{TOKEN}/sendMessage")

    broken = TelegramNotifier(TOKEN, client=httpx.Client(transport=httpx.MockTransport(down)))
    with pytest.raises(chat_notifier.NotifierError) as err:
        broken.send("42", "x")
    assert TOKEN not in str(err.value)
    assert redact(f"url /bot{TOKEN}/x") == "url /bot[redacted]/x"


def test_finish_run_triggers_notification(monkeypatch):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app.models.agent_run_ledger import AgentActionReceipt, AgentRunLedger
    from app.services.agent import action_ledger

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    AgentRunLedger.__table__.create(engine)
    AgentActionReceipt.__table__.create(engine)
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr(action_ledger, "SessionLocal", factory)
    with factory() as db:
        db.add(AgentRunLedger(id="run-1", session_id="sess-1", organization_id=5, user_id=1,
                              objective="https://app.example.com"))
        db.commit()
    calls = []
    monkeypatch.setattr(chat_notifier, "notify_run_finished",
                        lambda org, **kw: calls.append((org, kw)))
    action_ledger.finish_run("run-1", "completed", "done")
    assert calls == [(5, {"objective": "https://app.example.com", "status": "completed",
                          "reason": "done", "session_id": "sess-1"})]
