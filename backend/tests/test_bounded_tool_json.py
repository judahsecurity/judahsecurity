"""Tool output stays valid JSON when it exceeds the output cap."""

import json

from app.services.agent.tools import _bounded_json


def test_small_result_is_unchanged():
    assert json.loads(_bounded_json({"verdict": "confirmed"}, 100)) == {"verdict": "confirmed"}


def test_oversized_result_is_shortened_not_sliced():
    result = {"verdict": "candidate", "body": "x" * 50_000,
              "rows": [{"text": "y" * 3000} for _ in range(30)]}
    out = _bounded_json(result, 20_000)
    assert len(out) <= 20_000
    parsed = json.loads(out)
    assert parsed["verdict"] == "candidate" and parsed["_truncated"] is True
    assert "chars truncated" in parsed["body"]


def test_unshrinkable_result_falls_back_to_valid_preview():
    out = _bounded_json({str(i): i for i in range(5000)}, 2_000)
    assert len(out) <= 2_000
    assert json.loads(out)["_truncated"] is True
