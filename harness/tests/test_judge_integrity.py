import json

from local_harness.benchmark.judge import judge_heuristic, judge_llm
from local_harness.findings import normalize


def test_one_generic_finding_cannot_solve_two_defects():
    findings = [
        normalize(
            {"type": "vulnerability", "title": "Possible IDOR", "severity": "high"}
        )
    ]
    expected = [{"id": "a", "category": "idor"}, {"id": "b", "category": "idor"}]
    result = judge_heuristic(findings, expected)
    assert result.true_positive_count == 1
    assert result.metrics()["recall"] == 0.5
    assert result.metrics()["verified_recall"] == 0


def test_same_tail_different_route_does_not_match():
    finding = normalize(
        {
            "type": "vulnerability",
            "title": "IDOR",
            "url": "https://app.test/public/users",
        }
    )
    assert not judge_heuristic(
        [finding], [{"id": "a", "category": "idor", "endpoint": "/admin/users"}]
    ).detected


def test_judge_rejects_invented_ids_duplicate_matches_and_invalid_indices():
    findings = [
        normalize(
            {
                "type": "vulnerability",
                "title": "IDOR",
                "url": "https://app.test/private",
                "confidence": "confirmed",
            }
        )
    ]
    expected = [
        {"id": "a", "category": "idor", "endpoint": "/private"},
        {"id": "b", "category": "idor"},
    ]

    def fake(*_):
        return json.dumps(
            {
                "matches": [
                    {"expected_id": "a", "finding_index": 0},
                    {"expected_id": "a", "finding_index": 0},
                    {"expected_id": "b", "finding_index": 0},
                    {"expected_id": "invented", "finding_index": 88},
                ],
                "missed": [],
                "false_positives": [],
            }
        )

    result = judge_llm(findings, expected, fake)
    assert result.detected == ["a"]
    assert result.missed == ["b"]
    assert result.metrics()["verified_recall"] == 0.5


def test_placeholder_path_is_one_segment_only():
    expected = [{"id": "a", "category": "idor", "endpoint": "/objects/{id}"}]
    match = normalize(
        {
            "type": "vulnerability",
            "title": "IDOR",
            "url": "https://app.test/objects/123",
        }
    )
    unrelated = normalize(
        {
            "type": "vulnerability",
            "title": "IDOR",
            "url": "https://app.test/objects/123/export",
        }
    )
    assert judge_heuristic([match], expected).detected == ["a"]
    assert not judge_heuristic([unrelated], expected).detected
