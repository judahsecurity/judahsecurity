import scanners
from agent.execution_budget import (
    ExecutionBudget,
    activate_execution_budget,
    deactivate_execution_budget,
    get_execution_budget,
    request_signature,
)


def test_signature_is_query_order_insensitive_but_value_sensitive():
    a = request_signature("GET", "https://t.test/c?b=2&a=1")
    b = request_signature("GET", "https://t.test/c?a=1&b=2")
    assert a == b
    # A mutated payload is a different signature and must never be suppressed.
    assert request_signature("GET", "https://t.test/c?a=1") != request_signature(
        "GET", "https://t.test/c?a=1' --"
    )
    # Method matters.
    assert request_signature("GET", "https://t.test/c") != request_signature(
        "POST", "https://t.test/c"
    )


def test_exact_repeat_suppressed_after_cap():
    budget = ExecutionBudget(get_budget=100, max_exact_repeats=3)
    url = "https://t.test/catalog?category=1"
    assert all(budget.check("GET", url).allowed for _ in range(3))
    blocked = budget.check("GET", url)
    assert not blocked.allowed
    assert "exact-repeat" in blocked.reason
    snap = budget.snapshot()
    assert snap["allowed"] == 3
    assert snap["suppressed_exact_repeat"] == 1


def test_distinct_payloads_not_suppressed_by_repeat_cap():
    budget = ExecutionBudget(get_budget=100, max_exact_repeats=2)
    base = "https://t.test/catalog?category="
    for i in range(10):  # ten distinct payloads
        assert budget.check("GET", base + str(i)).allowed
    assert budget.snapshot()["suppressed_exact_repeat"] == 0


def test_get_budget_reserves_first_pass_for_unseen_inputs():
    # Budget of 2 GETs. First passes on two inputs consume it; a *repeat* of a
    # seen input is then blocked, but a brand-new input's first pass still runs.
    budget = ExecutionBudget(get_budget=2, max_exact_repeats=10)
    assert budget.check("GET", "https://t.test/a?x=1").allowed  # first pass A
    assert budget.check("GET", "https://t.test/b?x=1").allowed  # first pass B (budget now spent)
    repeat = budget.check("GET", "https://t.test/a?x=1")        # repeat of A
    assert not repeat.allowed and "GET budget exhausted" in repeat.reason
    # A never-seen input still gets its one first pass even past the ceiling.
    assert budget.check("GET", "https://t.test/c?x=1").allowed
    assert budget.snapshot()["suppressed_over_budget"] == 1


def test_scanner_suppresses_when_budget_active(monkeypatch):
    activate_execution_budget(get_budget=100, max_exact_repeats=1)
    try:
        class Result:
            stdout = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello"

        calls = {"n": 0}

        def fake_run(*args, **kwargs):
            calls["n"] += 1
            return Result()

        monkeypatch.setattr(scanners, "_tool_available", lambda name: True)
        monkeypatch.setattr(scanners, "_run", fake_run)

        url = "https://example.test/catalog?category=1"
        first = scanners.run_send_http_request("GET", url, "{}", "", True, None)
        assert first.get("status") == 200
        second = scanners.run_send_http_request("GET", url, "{}", "", True, None)
        assert second.get("suppressed") is True
        assert calls["n"] == 1  # the suppressed repeat never reached the network
    finally:
        deactivate_execution_budget()


def test_scanner_unaffected_when_budget_inactive(monkeypatch):
    deactivate_execution_budget()
    assert get_execution_budget() is None

    class Result:
        stdout = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello"

    monkeypatch.setattr(scanners, "_tool_available", lambda name: True)
    monkeypatch.setattr(scanners, "_run", lambda *a, **k: Result())
    url = "https://example.test/catalog?category=1"
    for _ in range(5):
        assert scanners.run_send_http_request("GET", url, "{}", "", True, None)["status"] == 200
