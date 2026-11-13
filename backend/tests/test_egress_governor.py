"""Request-boundary pacing and hard count for autonomous target traffic."""

import asyncio
import time

import httpx
import pytest

from app.services.agent.egress_governor import (
    RequestBudgetExceeded, RequestGovernor, current_request_governor,
    install_httpx_governor, parse_retry_after,
)

install_httpx_governor()


def _client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def _with(governor, coro):
    token = current_request_governor.set(governor)
    try:
        return await coro
    finally:
        current_request_governor.reset(token)


@pytest.mark.asyncio
async def test_no_governor_means_no_pacing():
    async with _client(lambda r: httpx.Response(200)) as client:
        started = time.monotonic()
        for _ in range(5):
            await client.get("https://app.test/")
        assert time.monotonic() - started < 0.5


@pytest.mark.asyncio
async def test_in_scope_requests_are_paced_per_host_and_counted():
    governor = RequestGovernor(["app.test"], rate_per_second=20)

    async def run():
        async with _client(lambda r: httpx.Response(200)) as client:
            started = time.monotonic()
            await asyncio.gather(*(client.get("https://app.test/") for _ in range(5)))
            return time.monotonic() - started

    elapsed = await _with(governor, run())
    assert elapsed >= 4 * (1 / 20) * 0.9   # four gaps of 50 ms
    assert governor.summary()["per_host"] == {"app.test": 5}


@pytest.mark.asyncio
async def test_out_of_scope_hosts_such_as_model_providers_are_untouched():
    governor = RequestGovernor(["app.test"], rate_per_second=0.5, max_requests=1)

    async def run():
        async with _client(lambda r: httpx.Response(200)) as client:
            for _ in range(3):
                await client.post("https://api.provider.test/v1/messages")
    started = time.monotonic()
    await _with(governor, run())
    assert time.monotonic() - started < 0.5
    assert governor.total == 0


@pytest.mark.asyncio
async def test_hard_count_stops_sending_and_counts_redirect_hops():
    sent = []

    def handler(request):
        sent.append(request.url.path)
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": "https://app.test/next"})
        return httpx.Response(200)

    governor = RequestGovernor(["*.app.test", "app.test"], rate_per_second=100, max_requests=3)

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler), follow_redirects=True,
        ) as client:
            await client.get("https://app.test/start")      # two requests
            await client.get("https://api.app.test/x")       # wildcard scope
            with pytest.raises(RequestBudgetExceeded):
                await client.get("https://app.test/again")
    await _with(governor, run())
    assert sent == ["/start", "/next", "/x"]
    assert governor.summary()["denied"] == 1
    # Callers that handle transport errors handle the budget stop too.
    assert issubclass(RequestBudgetExceeded, httpx.TransportError)


@pytest.mark.asyncio
async def test_retry_after_on_429_delays_the_next_request_to_that_host():
    statuses = iter([429, 200])

    def handler(request):
        status = next(statuses)
        return httpx.Response(status, headers={"retry-after": "0.3"} if status == 429 else {})

    governor = RequestGovernor(["app.test"], rate_per_second=100)

    async def run():
        async with _client(handler) as client:
            await client.get("https://app.test/")
            started = time.monotonic()
            await client.get("https://app.test/")
            return time.monotonic() - started
    assert await _with(governor, run()) >= 0.25
    assert governor.backoffs == 1


def test_backoff_without_retry_after_grows_and_is_capped():
    governor = RequestGovernor(["app.test"])
    before = time.monotonic()
    for _ in range(10):
        governor.observe("app.test", 503)
    assert governor._next_at["app.test"] - before <= 60.5
    governor.observe("app.test", 200)
    assert governor._streak["app.test"] == 0


def test_parse_retry_after_forms():
    assert parse_retry_after("5") == 5
    assert parse_retry_after(None) is None
    assert parse_retry_after("soon") is None
    assert parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT", now=1445412480 - 10) == pytest.approx(10)


def test_install_is_idempotent():
    method = httpx.AsyncClient._send_single_request
    install_httpx_governor()
    assert httpx.AsyncClient._send_single_request is method
