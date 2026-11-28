"""Hard per-run request ceiling, its testing reserve, and pipeline order under it."""

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import build_opener

import httpx
import pytest

from app.services.agent import request_budget as rb
from app.services.agent.assessment_proxy import assessment_httpx_options, assessment_urllib_handlers


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    monkeypatch.delenv("AEGIS_ASSESSMENT_PROXY_URL", raising=False)
    rb.reset_for_tests()
    yield
    rb.reset_for_tests()


@pytest.fixture
def budget():
    def make(limit=10, reserve_fraction=0.6):
        b = rb.RequestBudget(limit=limit, reserve=int(round(limit * reserve_fraction)))
        token = rb.current_request_budget.set(b)
        make.tokens.append(token)
        return b
    make.tokens = []
    yield make
    for token in reversed(make.tokens):
        try:
            rb.current_request_budget.reset(token)
        except ValueError:  # set inside an async test's own context
            rb.current_request_budget.set(None)


def test_discovery_cannot_spend_the_testing_reserve(budget):
    b = budget(limit=10)
    assert b.discovery_limit == 4
    for _ in range(4):
        b.acquire(rb.DISCOVERY)
    with pytest.raises(rb.RequestBudgetExhausted, match="reserved for input testing"):
        b.acquire(rb.DISCOVERY)
    assert b.discovery_exhausted and not b.exhausted
    for _ in range(6):
        b.acquire(rb.TESTING)
    with pytest.raises(rb.RequestBudgetExhausted, match="10/10"):
        b.acquire(rb.TESTING)
    assert b.exhausted and b.snapshot()["refused"] == 2


def test_session_budget_survives_resume_and_limit_change():
    first = rb.budget_for_session(12, "s1", 100)
    first.acquire()
    again = rb.budget_for_session(12, "s1", 200)
    assert again is first and again.used == 1 and again.limit == 200
    assert rb.existing_budget(12, "s1") is first
    assert rb.existing_budget(12, "other") is None


def test_peak_request_rate_is_enforced_across_one_second(monkeypatch):
    now = [100.0]
    delays = []

    def sleep(delay):
        delays.append(delay)
        now[0] += delay

    monkeypatch.setattr(rb, "_clock", lambda: now[0])
    monkeypatch.setattr(rb, "_sleep", sleep)
    b = rb.RequestBudget(limit=12, reserve=0, rate_per_second=10)
    for _ in range(10):
        b.acquire()
    assert now[0] == 100.0
    b.acquire()
    assert delays == [1.0]
    assert b.used == 11
    assert b.snapshot()["rate_per_second"] == 10


def test_session_budget_uses_deployment_rate(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "AGENT_TARGET_REQUESTS_PER_SECOND", 10)
    b = rb.budget_for_session(12, "rate", 500)
    assert b.rate_per_second == 10
    monkeypatch.setattr(settings, "AGENT_TARGET_REQUESTS_PER_SECOND", 5)
    assert rb.budget_for_session(12, "rate", 500) is b
    assert b.rate_per_second == 5


def test_limit_comes_from_policy_then_settings(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "AGENT_MAX_TARGET_REQUESTS", 0)
    assert rb.resolve_limit(None) == 0
    assert rb.resolve_limit({"max_target_requests": 500}) == 500
    monkeypatch.setattr(settings, "AGENT_MAX_TARGET_REQUESTS", 300)
    assert rb.resolve_limit({}) == 300


def test_unmetered_tools_are_refused_only_under_a_ceiling(budget):
    assert rb.unmetered_refusal("execute_nuclei") is None
    budget(limit=50)
    for name in ("execute_nuclei", "execute_ffuf", "spawn_recon_workers",
                 "execute_interceptor", "mcp_call"):
        refusal = rb.unmetered_refusal(name)
        assert refusal and refusal["error"] == "request_ceiling_unmetered_tool", name
        assert "not run" in refusal["output"]
    # The probe sandbox is metered (reserve_block + probe-egress per-job cap).
    for name in ("execute_deep_crawl", "execute_browser", "scoped_browser_assessment",
                 "probe_observed_input_batch", "replay_http_request",
                 "sandbox_shell", "run_custom_probe"):
        assert rb.unmetered_refusal(name) is None, name


def test_automatic_recon_workers_are_refused_under_a_ceiling(budget):
    from app.services.agent import recon_workers

    budget(limit=50)
    spawned = asyncio.run(recon_workers.spawn_workers(
        url="https://example.test/", session_id="capped-recon-test", pack="early",
    ))
    assert spawned == []
    assert asyncio.run(recon_workers.list_workers("capped-recon-test")) == []


@pytest.mark.asyncio
async def test_httpx_requests_are_counted_and_stopped():
    b = rb.RequestBudget(limit=3, reserve=0)
    rb.current_request_budget.set(b)
    options = assessment_httpx_options()
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200)),
                                 **options) as client:
        for _ in range(3):
            await client.get("https://app.test/")
        with pytest.raises(rb.RequestBudgetExhausted):
            await client.get("https://app.test/")
    assert b.used == 3


@pytest.mark.asyncio
async def test_no_budget_means_no_hooks():
    options = assessment_httpx_options()
    assert "event_hooks" not in options


def test_urllib_requests_are_counted(budget):
    b = budget(limit=2, reserve_fraction=0)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        opener = build_opener(*assessment_urllib_handlers())
        url = f"http://127.0.0.1:{server.server_port}/"
        opener.open(url, timeout=5).read()
        opener.open(url, timeout=5).read()
        with pytest.raises(rb.RequestBudgetExhausted):
            opener.open(url, timeout=5)
    finally:
        server.shutdown()
    assert b.used == 2


# ---------------------------------------------------------- pipeline order

def _web_state(**extra):
    state = {
        "mode": "agent",
        "target_info": {"primary_target": "https://shop.test/"},
        "original_objective": "Assess https://shop.test/",
        "capability_map": {"target": "https://shop.test/"},
        "execution_trace": [
            {"tool_name": "execute_deep_crawl", "success": True, "decision_source": "forced"},
        ],
    }
    state.update(extra)
    return state


def test_first_pass_runs_before_background_enrichment(monkeypatch):
    from app.services.agent import tester_loop

    monkeypatch.setattr(tester_loop, "observed_input_signature", lambda state: "sig-1")
    monkeypatch.setattr(tester_loop, "_observed_input_batch_step",
                        lambda state, trace, sig: {"tool_name": "probe_observed_input_batch",
                                                   "tool_args": {}})
    state = _web_state()
    step = tester_loop.forced_next_step(state)
    assert step["tool_name"] == "sync_engagement_brain"
    state["execution_trace"].append({"tool_name": "sync_engagement_brain", "success": True})
    assert tester_loop.forced_next_step(state)["tool_name"] == "probe_observed_input_batch"


def test_ceiling_skips_enrichment_and_ends_discovery(monkeypatch, budget):
    from app.services.agent import tester_loop

    monkeypatch.setattr(tester_loop, "observed_input_signature", lambda state: "sig-1")
    monkeypatch.setattr(tester_loop, "_observed_input_batch_step", lambda *a: None)
    monkeypatch.setattr(tester_loop, "_input_wave_made_progress", lambda *a: False)
    b = budget(limit=10)
    state = _web_state(execution_trace=[
        {"tool_name": "execute_deep_crawl", "success": True},
        {"tool_name": "sync_engagement_brain", "success": True},
    ])
    step = tester_loop.forced_next_step(state)
    assert step is None or step["tool_name"] not in rb.UNMETERED_TOOLS
    # A crawl that never finished still counts as done once discovery's share is spent.
    for _ in range(b.discovery_limit):
        b.acquire(rb.DISCOVERY)
    no_crawl = _web_state(execution_trace=[])
    step = tester_loop.forced_next_step(no_crawl)
    assert not step or step["tool_name"] not in {"execute_deep_crawl", "execute_interceptor"}


# ------------------------------------------------------------ run stop

def test_spent_ceiling_ends_the_run(monkeypatch, budget):
    import asyncio

    from app.services.agent.orchestrator import AgentOrchestrator

    b = budget(limit=10, reserve_fraction=0)
    for _ in range(10):
        b.acquire()
    orch = AgentOrchestrator()

    async def think(state, config=None):
        return {"_decision": {"action": "use_tool", "tool_name": "replay_http_request"}}

    orch._think_node = think
    out = asyncio.run(orch._guarded_think_node({"session_id": "s"}))
    assert out["task_complete"] is True
    assert out["completion_reason"].startswith("Request ceiling reached: 10/10")
    assert orch._route_after_think({**out}) == "generate_response"


def test_async_acquire_waits_without_blocking_the_event_loop(monkeypatch):
    """A full rate window used to time.sleep on the event loop, stalling every
    session. acquire_async must yield so other tasks keep running."""
    def no_thread_sleep(_seconds):
        raise AssertionError("acquire_async must not block the thread")

    monkeypatch.setattr(rb, "_sleep", no_thread_sleep)
    b = rb.RequestBudget(limit=50, reserve=0, rate_per_second=2)

    async def scenario():
        ticks = []

        async def heartbeat():
            for _ in range(20):
                ticks.append(1)
                await asyncio.sleep(0.02)

        beat = asyncio.create_task(heartbeat())
        started = asyncio.get_running_loop().time()
        for _ in range(3):  # the third request must wait for the window
            await b.acquire_async()
        waited = asyncio.get_running_loop().time() - started
        await beat
        return waited, len(ticks)

    waited, ticks = asyncio.run(scenario())
    assert waited >= 0.5 and b.used == 3
    assert ticks == 20  # the loop kept running while the budget waited


def test_httpx_hook_uses_the_async_path(budget, monkeypatch):
    b = budget(limit=5)
    monkeypatch.setattr(b, "acquire", lambda *_: (_ for _ in ()).throw(
        AssertionError("sync acquire called from async hook")))
    hook = rb.httpx_event_hooks()["request"][0]
    asyncio.run(hook(None))
    assert b.used == 1


def test_reserve_block_and_refund_are_exact(budget):
    b = budget(limit=10, reserve_fraction=0.0)
    assert b.reserve_block(6) == 6 and b.used == 6
    assert b.reserve_block(6) == 4 and b.used == 10   # only what is left
    assert b.reserve_block(1) == 0 and b.refused == 1
    b.refund(4)                                        # the job sent 0 of its 4
    assert b.used == 6
    b.refund(100)
    assert b.used == 0
