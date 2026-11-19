"""Cold trails: the same direction tried repeatedly with nothing to show."""

from app.services.agent.cold_trails import cold_trails, direction_key, format_cold_trails


def _step(tool, url, **extra):
    return {"tool_name": tool, "tool_args": {"url": url}, "success": True, **extra}


def test_payload_variations_on_one_endpoint_are_one_direction():
    trace = [_step("scoped_injection_probe_assigned", f"https://app.test/item/{i}?q=x{i}") for i in range(3)]
    trails = cold_trails(trace)
    assert len(trails) == 1 and trails[0]["attempts"] == 3
    assert "app.test/item/{id}" in trails[0]["direction"]
    assert "Cold trails" in format_cold_trails(trails)


def test_productive_direction_is_not_cold():
    trace = [_step("execute_curl", "https://app.test/a") for _ in range(4)]
    trace[2]["actionable_findings"] = ["reflected input"]
    assert cold_trails(trace) == []


def test_bookkeeping_and_anchorless_steps_are_ignored():
    assert direction_key({"tool_name": "sync_engagement_brain", "tool_args": {"url": "https://a"}}) is None
    assert direction_key({"tool_name": "execute_nmap", "tool_args": {}}) is None
    trace = [_step("execute_curl", "https://app.test/a"), _step("execute_curl", "https://app.test/b")] * 1
    assert cold_trails(trace) == []
    assert format_cold_trails([]) == ""


def test_coverage_cell_anchor_separates_directions():
    trace = [{"tool_name": "scoped_race_assigned",
              "tool_args": {"coverage_cell_id": f"cell-{i % 2}"}} for i in range(6)]
    assert {t["attempts"] for t in cold_trails(trace)} == {3}
