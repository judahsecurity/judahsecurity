"""Target traffic slows down when the target pushes back."""

import asyncio
import io
import urllib.error
import urllib.request
import urllib.response

import httpx
import pytest

from app.services.agent import target_pacing as tp
from app.services.agent.autonomy_limits import limits_from_config

BALANCED = tp.PROFILES["balanced"]
QUIET = tp.PROFILES["quiet"]


@pytest.fixture(autouse=True)
def _fresh():
    tp.reset_pacing()
    yield
    tp.reset_pacing()


def test_burst_is_free_then_requests_follow_the_profile_rate() -> None:
    waits = [tp.reserve("app.test", now=100.0, profile=BALANCED) for _ in range(12)]
    assert waits[:10] == [0.0] * 10
    assert waits[10] == pytest.approx(0.2)
    assert waits[11] == pytest.approx(0.4)


def test_hosts_have_separate_budgets() -> None:
    for _ in range(5):
        tp.reserve("a.test", now=0.0, profile=QUIET)
    assert tp.reserve("b.test", now=0.0, profile=QUIET) == 0.0


def test_429_with_retry_after_cools_down_and_halves_rate() -> None:
    tp.observe("app.test", 429, "7", now=50.0, profile=BALANCED)
    assert tp.reserve("app.test", now=50.0, profile=BALANCED) == pytest.approx(7.0)
    report = tp.throttle_report(["app.test"], now=50.0)
    assert report[0]["rate_factor"] == 0.5
    assert report[0]["throttled_responses"] == 1


def test_backoff_without_retry_after_grows_and_is_capped() -> None:
    for i in range(10):
        tp.observe("app.test", 503, None, now=0.0, profile=BALANCED)
    wait = tp.reserve("app.test", now=0.0, profile=BALANCED)
    assert wait == pytest.approx(BALANCED.max_backoff_seconds)
    assert tp.throttle_report(["app.test"], now=0.0)[0]["rate_factor"] == tp.MIN_RATE_FACTOR


def test_successes_restore_the_rate() -> None:
    tp.observe("app.test", 429, "1", now=0.0, profile=BALANCED)
    for _ in range(tp.RECOVERY_SUCCESSES):
        tp.observe("app.test", 200, None, now=1.0, profile=BALANCED)
    assert tp.throttle_report(["app.test"], now=1.0)[0]["rate_factor"] == 0.75


def test_off_profile_never_waits_or_records() -> None:
    assert tp.reserve("app.test", now=0.0, profile=None) == 0.0
    tp.observe("app.test", 429, "30", now=0.0, profile=None)
    assert tp.throttle_report(["app.test"], now=0.0) == []


def test_http_date_retry_after_is_understood() -> None:
    assert tp._retry_after_seconds("Thu, 01 Jan 1970 00:01:40 GMT", now_wall=40.0) == 60.0
    assert tp._retry_after_seconds("garbage") is None


def test_note_is_scoped_to_the_sessions_own_hosts() -> None:
    for _ in range(tp.HEAVY_THROTTLE_COUNT):
        tp.observe("api.app.test", 429, "1", now=0.0, profile=BALANCED)
    tp.observe("other-tenant.example", 429, "1", now=0.0, profile=BALANCED)

    note = tp.format_throttle_note(["app.test"], now=0.0)
    assert "api.app.test" in note
    assert "other-tenant.example" not in note
    assert "Do not start brute-force" in note
    assert tp.format_throttle_note([""], now=0.0) == ""
    assert tp.format_throttle_note(["unrelated.test"], now=0.0) == ""


def test_httpx_hooks_observe_throttled_responses(monkeypatch) -> None:
    monkeypatch.setattr(tp, "active_profile", lambda: BALANCED)

    def handler(request):
        return httpx.Response(429, headers={"Retry-After": "3"})

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                     event_hooks=tp.pacing_event_hooks()) as client:
            await client.get("https://app.test/login")

    asyncio.run(run())
    assert tp.throttle_report(["app.test"])[0]["throttled_responses"] == 1


def test_urllib_handler_sees_429_before_it_becomes_an_error(monkeypatch) -> None:
    monkeypatch.setattr(tp, "active_profile", lambda: BALANCED)

    class Throttled(urllib.request.BaseHandler):
        handler_order = 100  # answer before urllib's real HTTPHandler

        def http_open(self, request):
            response = urllib.response.addinfourl(
                io.BytesIO(b""), {"Retry-After": "2"}, request.full_url, 429,
            )
            response.msg = "Too Many Requests"
            return response

    opener = urllib.request.build_opener(Throttled(), tp.PacingHandler())
    with pytest.raises(urllib.error.HTTPError):
        opener.open("http://app.test/search")
    assert tp.throttle_report(["app.test"])[0]["throttled_responses"] == 1


def test_autonomy_config_accepts_only_known_profiles() -> None:
    assert limits_from_config({"pacing_profile": "Quiet"}).pacing_profile == "quiet"
    assert limits_from_config({"pacing_profile": "turbo"}).pacing_profile == ""
    assert limits_from_config({}).pacing_profile == ""
