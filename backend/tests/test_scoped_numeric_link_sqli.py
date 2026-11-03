"""Numeric SQLi proof from an observed link must keep provenance and controls."""

import asyncio
import hashlib
import json
from urllib.parse import parse_qs, urlsplit

import pytest

from app.services.agent.assessment_scope import register_scope
from app.services.agent.scoped_assessment import sqli_boolean
from app.services.agent.scoped_assessment import browser_post_replay
from app.services.agent.scoped_assessment.browser_traffic import package_exchange
from app.services.agent.evidence_store import VerificationRun, evidence_store, verification_run
from app.services.agent.engagement_brain import EngagementBrain
from app.services.agent.independent_verify import FindingCandidate, _verify_scoped_sql_candidate
from app.services.agent.tools import ASMToolsManager


ORIGIN = "https://app.example.test"
TARGET = ORIGIN + "/item"
OBSERVED = TARGET + "?id=7&view=compact"


def _response(url, allowed_origins, storage_state, *, vulnerable=False, reflect=False):
    assert allowed_origins == [ORIGIN]
    fields = parse_qs(urlsplit(url).query)
    assert fields["view"] == ["compact"]
    value = fields["id"][0]
    if vulnerable and " AND " in value:
        body = b"item 7" if value.split(" AND ")[1].split("=")[0] == value.split("=")[1] else b"no item"
    elif reflect:
        body = value.encode()
    else:
        body = b"item 7"
    return {"status": 200, "content_type": "text/html", "bytes_captured": len(body),
            "truncated": False, "redirected": False,
            "body_sha256": hashlib.sha256(body).hexdigest()}


def test_numeric_link_planner_requires_bounded_ordinary_observed_value():
    baseline, true_url, false_url, nonce = sqli_boolean.plan_numeric_boolean_url(
        OBSERVED, parameter="id", allowed_origins=[ORIGIN],
    )
    assert baseline == OBSERVED
    assert parse_qs(urlsplit(true_url).query)["view"] == ["compact"]
    assert parse_qs(urlsplit(true_url).query)["id"] == [f"7 AND {nonce}={nonce}"]
    assert true_url != false_url
    for url in (TARGET + "?id=7&id=8", TARGET + "?id=7%27", TARGET + "?id=0"):
        with pytest.raises(ValueError):
            sqli_boolean.plan_numeric_boolean_url(
                url, parameter="id", allowed_origins=[ORIGIN],
            )
    with pytest.raises(ValueError):
        sqli_boolean.plan_numeric_boolean_url(
            "https://other.example.test/item?id=7", parameter="id", allowed_origins=[ORIGIN],
        )


@pytest.mark.parametrize("vulnerable,reflect,expected", [
    (True, False, True), (False, False, False), (False, True, False),
])
def test_numeric_link_proof_distinguishes_sql_evaluation_from_lookalikes(
    monkeypatch, vulnerable, reflect, expected,
):
    monkeypatch.setattr(sqli_boolean, "observe_get", lambda *args: _response(
        *args, vulnerable=vulnerable, reflect=reflect,
    ))
    baseline, true_url, false_url, nonce = sqli_boolean.plan_numeric_boolean_url(
        OBSERVED, parameter="id", allowed_origins=[ORIGIN],
    )
    result = sqli_boolean.probe_numeric_boolean(
        baseline, true_url, false_url, nonce, parameter="id",
        allowed_origins=[ORIGIN], storage_state=None, before_request=lambda: None,
    )
    assert result["requests_sent"] == 6
    assert result["proof_confirmed"] is expected


def test_numeric_link_tool_requires_private_observation_and_exact_query(monkeypatch):
    manager = ASMToolsManager()
    manager._fallback_target = ORIGIN
    register_scope(manager, "app.example.test")
    manager._capability_map = {"scope": ORIGIN, "pages_visited": [OBSERVED]}

    def fake_probe(baseline, true_url, false_url, nonce, **kwargs):
        assert baseline == OBSERVED
        return {"target": TARGET, "operation": "sqli_boolean_numeric",
                "proof_confirmed": True, "nonce": nonce, "parameter": "id"}

    monkeypatch.setattr(sqli_boolean, "probe_numeric_boolean", fake_probe)
    result = json.loads(asyncio.run(manager.scoped_numeric_sqli(
        url=TARGET, parameter="id",
    )))
    assert result["proof_confirmed"] and result["baseline_source"] == "observed_url"
    assert "source_artifact_id" not in result
    assert "id=7" not in json.dumps(result)
    with pytest.raises(ValueError, match="observed positive numeric GET value"):
        asyncio.run(manager.scoped_numeric_sqli(
            url=TARGET + "?id=8&view=compact", parameter="id",
        ))
    with pytest.raises(ValueError, match="mapped GET query parameter"):
        asyncio.run(manager.scoped_numeric_sqli(url=TARGET, parameter="other"))


@pytest.mark.asyncio
async def test_captured_numeric_get_browser_replay_reaches_independent_verifier(monkeypatch):
    manager = ASMToolsManager()
    manager._fallback_target = ORIGIN
    register_scope(manager, "app.example.test")
    public, private = package_exchange(
        url=OBSERVED, expected_origin=ORIGIN, page_url=ORIGIN + "/catalog",
        action_ref="navigate", method="GET", resource_type="fetch", status=200,
        content_type="text/html", request_body=b"", response_body=b"item 7",
    )
    store = evidence_store(manager)
    capture_id = store.record("scoped_browser_exchange", public, target=TARGET,
                              identity="anonymous")
    manager._scoped_browser_exchanges = {
        capture_id: {"identity": "anonymous", "private": private,
                     "public": public, "verifier_run_id": None},
    }
    calls = []

    async def replay(capture, *, parameter, variants, allowed_origins, storage_state):
        assert capture == private and parameter == "id" and allowed_origins == [ORIGIN]
        calls.append(list(variants))
        return {key: _response(url, [ORIGIN], storage_state, vulnerable=True)
                for key, url in variants.items()}

    monkeypatch.setattr(browser_post_replay, "replay_observed_get_controls", replay)
    hunter = json.loads(await manager.scoped_numeric_sqli(artifact_id=capture_id, parameter="id"))
    assert hunter["proof_confirmed"] is True
    assert hunter["replay_mode"] == "browser_live_get"
    assert hunter["source_artifact_id"] == capture_id

    brain = EngagementBrain(target=TARGET)
    brain.coverage_cells = [{
        "id": "cell-1", "source": "parameter_inventory",
        "observation_source": "browser_traffic", "test_type": "sqli",
        "method": "GET", "host": "app.example.test", "path": "/item",
        "parameter": "query:id", "identity": "anonymous", "capture_id": capture_id,
    }]
    candidate = FindingCandidate(
        id="candidate-1", title="SQL injection in id", target=TARGET,
        vulnerability_class="sql_injection", coverage_cell_id="cell-1",
        parameter="query:id", evidence_ids=[hunter["evidence_id"]],
    )
    brain.candidates = [candidate.to_dict()]
    manager._engagement_brain = brain.to_dict()
    run = VerificationRun("fresh-get-run", "candidate-1", 1, "nonce")
    token = verification_run.set(run)
    try:
        verdict = await _verify_scoped_sql_candidate(manager, candidate, run)
    finally:
        verification_run.reset(token)
    assert verdict["status"] == "confirmed"
    assert len(calls) == 2
    assert manager._scoped_verify_get_count == 6
