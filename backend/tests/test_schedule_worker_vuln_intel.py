"""
Tests for the schedule worker's vulnerability-intel refresh cadence.

The worker loop ticks every 60s by default, so each feed must be gated by its
own interval rather than refreshed on every tick.
"""

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from app.workers.schedule_worker import ScheduleWorker


@pytest.fixture()
def worker(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "")
    w = ScheduleWorker()
    # No DB in these tests; token resolution must not need one.
    monkeypatch.setattr(w, "_resolve_vulncheck_token", lambda: "")
    return w


def _record_refreshes(monkeypatch):
    calls = []

    def _fake_refresh(feed, *, vulncheck_token=""):
        calls.append(feed)
        return 1

    monkeypatch.setattr("app.services.vuln_intel_feeds.refresh_feed", _fake_refresh)
    return calls


def test_first_tick_refreshes_every_feed(worker, monkeypatch):
    from app.services.vuln_intel_feeds import DEFAULT_FEED_INTERVAL_MINUTES

    calls = _record_refreshes(monkeypatch)
    asyncio.run(worker.run_vuln_intel_refresh())
    assert sorted(calls) == sorted(DEFAULT_FEED_INTERVAL_MINUTES)


def test_second_tick_refreshes_nothing(worker, monkeypatch):
    _record_refreshes(monkeypatch)
    asyncio.run(worker.run_vuln_intel_refresh())

    calls = _record_refreshes(monkeypatch)
    asyncio.run(worker.run_vuln_intel_refresh())
    assert calls == [], "feeds must be gated by their interval, not refreshed every tick"


def test_only_due_feeds_refresh(worker, monkeypatch):
    _record_refreshes(monkeypatch)
    asyncio.run(worker.run_vuln_intel_refresh())

    # Age the fast feeds past their 30-minute interval; leave the rest fresh.
    stale = datetime.now(timezone.utc) - timedelta(minutes=45)
    worker._vuln_intel_last_run["circl_shadowserver"] = stale
    worker._vuln_intel_last_run["kevintel"] = stale

    calls = _record_refreshes(monkeypatch)
    asyncio.run(worker.run_vuln_intel_refresh())
    assert sorted(calls) == ["circl_shadowserver", "kevintel"]


def test_failing_feed_does_not_retry_next_tick(worker, monkeypatch):
    """A feed that raises must still have its timestamp recorded."""

    def _boom(feed, *, vulncheck_token=""):
        raise RuntimeError("upstream down")

    monkeypatch.setattr("app.services.vuln_intel_feeds.refresh_feed", _boom)
    asyncio.run(worker.run_vuln_intel_refresh())  # must not propagate

    calls = _record_refreshes(monkeypatch)
    asyncio.run(worker.run_vuln_intel_refresh())
    assert calls == [], "a failing feed must not be retried on every 60s tick"


def test_interval_override_is_honoured(worker, monkeypatch):
    monkeypatch.setenv("VULN_INTEL_INTERVAL_CISA_KEV", "1")
    _record_refreshes(monkeypatch)
    asyncio.run(worker.run_vuln_intel_refresh())

    worker._vuln_intel_last_run["cisa_kev"] = datetime.now(timezone.utc) - timedelta(minutes=2)
    calls = _record_refreshes(monkeypatch)
    asyncio.run(worker.run_vuln_intel_refresh())
    assert calls == ["cisa_kev"]
