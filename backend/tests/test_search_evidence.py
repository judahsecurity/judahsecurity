"""search_evidence: read-only cross-exchange marker search over the evidence store."""

import json

import pytest

from app.services.agent.evidence_store import evidence_store
from app.services.agent.prompts import is_tool_allowed_in_phase
from app.services.agent.tools import ASMToolsManager


def _seed(manager):
    store = evidence_store(manager)
    hit = store.record(
        "scoped_http_get",
        {"operation": "http_get", "status": 200,
         "response": {"body": "<div>welcome mark3r_CANARY_7 back</div>"}},
        target="https://app.example.test/profile", identity="user_a",
    )
    other = store.record(
        "scoped_http_get",
        {"operation": "http_get", "status": 200,
         "response": {"body": "<div>nothing here</div>"}},
        target="https://app.example.test/home", identity="anonymous",
    )
    return hit, other


@pytest.mark.asyncio
async def test_search_evidence_finds_reflected_marker():
    manager = ASMToolsManager()
    hit, _other = _seed(manager)

    result = json.loads(await manager.search_evidence(value="mark3r_CANARY_7"))

    assert result["match_count"] == 1
    assert result["scanned"] == 2
    assert result["more_results"] is False
    match = result["matches"][0]
    assert match["evidence_id"] == hit
    assert match["identity"] == "user_a"
    assert match["occurrences"] == 1
    assert "mark3r_CANARY_7" in match["snippet"]


@pytest.mark.asyncio
async def test_search_evidence_is_case_insensitive_and_reports_no_match():
    manager = ASMToolsManager()
    _seed(manager)

    reflected = json.loads(await manager.search_evidence(value="MARK3R_canary_7"))
    assert reflected["match_count"] == 1

    absent = json.loads(await manager.search_evidence(value="not-present-token"))
    assert absent["match_count"] == 0
    assert absent["matches"] == []
    assert absent["scanned"] == 2


@pytest.mark.asyncio
async def test_search_evidence_filters_by_kind_and_identity():
    manager = ASMToolsManager()
    _seed(manager)

    by_identity = json.loads(
        await manager.search_evidence(value="div", identity="user_a")
    )
    assert by_identity["scanned"] == 1
    assert by_identity["match_count"] == 1

    wrong_kind = json.loads(
        await manager.search_evidence(value="div", kind="scoped_body_probe")
    )
    assert wrong_kind["scanned"] == 0
    assert wrong_kind["match_count"] == 0


@pytest.mark.asyncio
async def test_search_evidence_rejects_short_queries():
    manager = ASMToolsManager()
    with pytest.raises(ValueError):
        await manager.search_evidence(value="ab")
    with pytest.raises(ValueError):
        await manager.search_evidence(value="   ")


@pytest.mark.asyncio
async def test_search_evidence_caps_results_and_flags_more():
    manager = ASMToolsManager()
    store = evidence_store(manager)
    for _ in range(4):
        store.record(
            "scoped_http_get",
            {"response": {"body": "repeated_token_xyz"}},
            target="https://app.example.test/x", identity="anonymous",
        )

    result = json.loads(await manager.search_evidence(value="repeated_token_xyz", max_matches=2))
    assert result["match_count"] == 2
    assert result["more_results"] is True


def test_search_evidence_registered_and_phase_gated():
    manager = ASMToolsManager()
    assert "search_evidence" in manager.tools
    assert is_tool_allowed_in_phase("search_evidence", "informational")
    assert is_tool_allowed_in_phase("search_evidence", "exploitation")
