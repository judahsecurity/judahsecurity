"""Penetration Task Graph + auto-prompter swarm scheduler."""

from types import SimpleNamespace

from app.services.agent.auto_prompter import (
    SOLILOQUY,
    classify_failure,
    rewrite_note,
    should_rewrite,
)
from app.services.agent.capability_map import build_capability_map_from_crawl
from app.services.agent.engagement_brain import (
    engagement_brain_from_dict,
    ensure_spawned_hypotheses,
    seed_hypotheses_from_capability_map,
)
from app.services.agent.penetration_task_graph import (
    ExecutorSummary,
    NODE_BLOCKED,
    NODE_READY,
    apply_executor_summary,
    compact_scheduler_mission,
    parse_executor_summary,
    ready_wave,
    sync_graph_from_brain,
)


def _fake_crawl(**overrides):
    base = dict(
        target="https://tenant-a.app.example.com",
        scope="example.com",
        authenticated=True,
        pages_visited=[
            "https://tenant-a.app.example.com/",
            "https://tenant-a.app.example.com/login",
            "https://tenant-b.app.example.com/",
            "https://tenant-a.app.example.com/admin",
        ],
        forms=[
            {
                "method": "POST",
                "action": "/login",
                "inputs": ["username", "password"],
                "page": "https://tenant-a.app.example.com/login",
            },
            {
                "method": "POST",
                "action": "/checkout",
                "inputs": ["quantity", "price"],
                "page": "https://tenant-a.app.example.com/checkout",
            },
        ],
        api_calls={
            "tenant-a.app.example.com": {
                "GET /api/users?id=1",
                "GET /api/orders/100",
            },
            "tenant-b.app.example.com": {
                "GET /api/users?id=2",
            },
        },
        js_files={"https://tenant-a.app.example.com/static/app.js"},
        endpoints_from_js={"/api/v1/items"},
        websockets=set(),
        sse=set(),
        source_maps=set(),
        third_party=set(),
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def _seeded_brain():
    cmap = build_capability_map_from_crawl(_fake_crawl())
    return seed_hypotheses_from_capability_map(
        engagement_brain_from_dict(None), cmap.to_dict()
    )


def test_seed_promotes_cards_onto_task_graph():
    brain = _seeded_brain()
    assert brain.task_graph
    graph = sync_graph_from_brain(brain)
    assert graph.nodes
    assert any(n.methodology_id or n.source in ("methodology", "map") for n in graph.nodes.values())


def test_coverage_blocked_until_logic_attempted():
    brain = _seeded_brain()
    graph = sync_graph_from_brain(brain)
    coverage = [n for n in graph.nodes.values() if n.specialist == "coverage"]
    assert coverage, "expected a coverage leftover node"
    assert all(n.status == NODE_BLOCKED for n in coverage)
    wave = ready_wave(graph)
    assert "coverage" not in wave
    assert wave, "high-pri logic cards should be ready"


def test_ready_wave_is_specialists_not_every_card():
    brain = _seeded_brain()
    graph = sync_graph_from_brain(brain)
    wave = ready_wave(graph, max_specialists=6)
    assert len(wave) <= 6
    assert len(wave) == len(set(wave))


def test_executor_summary_soliloquy_is_not_proven():
    report = SimpleNamespace(
        specialist="injection",
        summary="SQLi confirmed on /api/users",
        key_findings=["SQLi"],
        tool_calls=[],
        error=None,
        verdict="proven",
        hypothesis_ids=["abc"],
        evidence="imagined",
        spawn=[],
        rewrite_hint="",
    )
    summary = parse_executor_summary(report)
    assert summary.soliloquy is True
    assert summary.verdict == "retry"


def test_apply_summary_proves_matching_cards():
    brain = _seeded_brain()
    graph = sync_graph_from_brain(brain)
    specialist = ready_wave(graph)[0]
    node = next(n for n in graph.nodes.values() if n.specialist == specialist)
    node.status = "running"
    summary = ExecutorSummary(
        specialist=specialist,
        hypothesis_ids=[node.id],
        verdict="proven",
        evidence="compare_requests LIKELY_IMPACT on /api/users",
        tools_run=["compare_requests"],
    )
    apply_executor_summary(graph, brain, summary)
    hyp = next(h for h in brain.hypotheses if h.id == node.id)
    assert hyp.status == "proven"
    assert graph.nodes[node.id].status == "proven"


def test_compact_mission_strips_scan_dumps():
    raw = (
        "Hunt the app.\n"
        "CAPABILITY MAP (use these concrete surfaces):\n- pages: " + ("x" * 400) + "\n"
        "ENGAGEMENT BRAIN:\n" + ("open hypothesis " * 80)
    )
    compact = compact_scheduler_mission(raw, ready_count=3, target="https://a.example")
    assert "CAPABILITY MAP" not in compact
    assert "ENGAGEMENT BRAIN" not in compact
    assert "short-lived executor" in compact
    assert len(compact) < len(raw)


def test_auto_prompter_rewrites_soliloquy():
    summary = ExecutorSummary(
        specialist="api_authz",
        verdict="retry",
        soliloquy=True,
        summary="IDOR exists",
        tools_run=[],
    )
    report = SimpleNamespace(tool_calls=[], error=None, summary="IDOR exists")
    assert classify_failure(summary, report) == SOLILOQUY
    note = rewrite_note(SOLILOQUY, summary)
    assert "tool" in note.lower()
    graph = sync_graph_from_brain(_seeded_brain())
    for n in graph.nodes.values():
        if n.specialist == "api_authz":
            n.status = "retry"
            n.attempts = 1
    rewrite = should_rewrite(graph, summary, report)
    assert rewrite is not None
    assert rewrite.failure == SOLILOQUY


def test_auto_prompter_stops_after_max_attempts():
    summary = ExecutorSummary(specialist="api_authz", verdict="retry", soliloquy=True)
    report = SimpleNamespace(tool_calls=[], error=None, summary="")
    graph = sync_graph_from_brain(_seeded_brain())
    for n in graph.nodes.values():
        if n.specialist == "api_authz":
            n.status = "retry"
            n.attempts = n.max_attempts
    assert should_rewrite(graph, summary, report) is None


def test_spawn_adds_graphql_card():
    brain = _seeded_brain()
    before = {h.specialist for h in brain.hypotheses}
    created = ensure_spawned_hypotheses(brain, ["graphql_api"])
    if "graphql_api" in before:
        assert created == []
    else:
        assert created
        assert any(h.specialist == "graphql_api" and h.source == "spawn" for h in brain.hypotheses)
