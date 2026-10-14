"""Numeric SQLi proof from an observed link must keep provenance and controls."""

import asyncio
import hashlib
import json
from urllib.parse import parse_qs, urlsplit

import pytest

from app.services.agent.assessment_scope import register_scope
from app.services.agent.scoped_assessment import sqli_boolean
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
