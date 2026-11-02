"""Bounded concurrency (TOCTOU) proof on an operator-approved action.

A single-use or limited action that the server enforces when requests arrive in
series, but not when they arrive together, is a race condition. The probe
establishes the sequential enforcement with a control canary, then fires a
bounded concurrent burst with a fresh canary and counts, through an independent
readback, how many times the burst canary persisted. One sequential survivor
and two or more concurrent survivors is the overrun signal. Both canaries are
cleaned up. Nothing here is model supplied: the action path, readback, and
cleanup path are operator policy, and the canaries are nonce bound.
"""

from __future__ import annotations

import asyncio

import httpx

from app.services.agent.assessment_proxy import assessment_httpx_options

from .browser import assert_in_scope
from .http_observe import _cookie_header

MAX_CONCURRENCY = 20
MIN_CONCURRENCY = 2
_READBACK_SCAN_BYTES = 256 * 1024


def _seq_canary(nonce: str) -> str:
    return f"aegis-race-seq-{nonce}"


def _burst_canary(nonce: str) -> str:
    return f"aegis-race-burst-{nonce}"


async def _submit(client: httpx.AsyncClient, url: str, *, method: str,
                  field: str, canary: str, headers: dict) -> int:
    try:
        response = await client.request(method, url, json={field: canary},
                                        headers=headers)
        return response.status_code
    except httpx.HTTPError:
        return 0


async def _readback_count(client: httpx.AsyncClient, url: str, *, canary: str,
                          headers: dict) -> int:
    try:
        response = await client.get(url, headers=headers)
    except httpx.HTTPError:
        return -1
    body = response.text[:_READBACK_SCAN_BYTES]
    return body.count(canary)


async def _cleanup(client: httpx.AsyncClient, template: str, *, canary: str,
                   headers: dict) -> bool:
    url = template.replace("__PROWL_NONCE__", canary)
    for method in ("DELETE", "PUT", "PATCH"):
        try:
            response = await client.request(method, url, headers=headers)
        except httpx.HTTPError:
            continue
        if 200 <= response.status_code < 300:
            return True
    return False


async def probe_race(action_url: str, readback_url: str, cleanup_template: str, *,
                     method: str, field: str, allowed_origin: str,
                     state: dict | None, nonce: str, concurrency: int) -> dict:
    """Prove a limit the server enforces in series but not under concurrency."""
    if not nonce or len(nonce) > 40 or not nonce.isalnum():
        raise ValueError("A bounded alphanumeric nonce is required")
    if method not in {"POST", "PUT", "PATCH"}:
        raise ValueError("A state-changing action method is required")
    if not field or len(field) > 128:
        raise ValueError("A bounded action field is required")
    if "__PROWL_NONCE__" not in cleanup_template:
        raise ValueError("The cleanup template must carry __PROWL_NONCE__")
    for url in (action_url, readback_url, cleanup_template.replace("__PROWL_NONCE__", "x")):
        assert_in_scope(url, [allowed_origin])
    concurrency = max(MIN_CONCURRENCY, min(MAX_CONCURRENCY, int(concurrency or 10)))

    headers = {"Accept": "application/json, */*;q=0.8"}
    cookie = _cookie_header(state, action_url)
    if cookie:
        headers["Cookie"] = cookie

    seq, burst = _seq_canary(nonce), _burst_canary(nonce)
    options = assessment_httpx_options()
    async with httpx.AsyncClient(timeout=30, follow_redirects=False, **options) as client:
        # Sequential control: the same canary twice, in series.
        seq_statuses = [await _submit(client, action_url, method=method, field=field,
                                      canary=seq, headers=headers) for _ in range(2)]
        sequential_count = await _readback_count(client, readback_url, canary=seq,
                                                 headers=headers)
        # Concurrent burst: a fresh canary, fired together.
        burst_statuses = list(await asyncio.gather(*[
            _submit(client, action_url, method=method, field=field,
                    canary=burst, headers=headers)
            for _ in range(concurrency)
        ]))
        burst_count = await _readback_count(client, readback_url, canary=burst,
                                            headers=headers)
        seq_cleanup = await _cleanup(client, cleanup_template, canary=seq, headers=headers)
        burst_cleanup = await _cleanup(client, cleanup_template, canary=burst, headers=headers)

    def _ok(statuses: list[int]) -> int:
        return sum(1 for status in statuses if 200 <= status < 300)

    confirmed = bool(
        sequential_count == 1
        and burst_count >= 2
        and _ok(seq_statuses) >= 1
        and _ok(burst_statuses) >= 2
        and seq_cleanup and burst_cleanup
    )
    return {
        "operation": "scoped_race_probe", "test_type": "race_condition",
        "field": field, "method": method,
        "requests_sent": len(seq_statuses) + len(burst_statuses),
        "concurrency": concurrency,
        "control": {"canary": seq, "successes": _ok(seq_statuses),
                    "readback_count": sequential_count, "single_use_enforced":
                    sequential_count == 1},
        "probe": {"canary": burst, "successes": _ok(burst_statuses),
                  "readback_count": burst_count, "overrun": burst_count >= 2},
        "cleanup_confirmed": bool(seq_cleanup and burst_cleanup),
        "proof_confirmed": confirmed,
        "finding": False,
    }
