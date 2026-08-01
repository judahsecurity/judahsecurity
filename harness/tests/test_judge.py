import json

from local_harness.benchmark.judge import judge, judge_heuristic, judge_llm
from local_harness.findings import normalize

EXPECTED = [
    {"id": "E-SQLI", "category": "sqli", "endpoint": "/rest/user/login"},
    {"id": "E-XSS", "category": "xss", "endpoint": "/search"},
    {"id": "E-IDOR", "category": "idor", "endpoint": "/rest/basket"},
]


def _findings():
    return [
        normalize({"type": "vulnerability", "title": "SQL Injection in login",
                   "severity": "critical",
                   "raw_data": {"poc": {"endpoint": "https://x/rest/user/login"}}}),
        normalize({"type": "vulnerability", "title": "Reflected XSS",
                   "severity": "high", "url": "https://x/search?q=1", "tags": ["xss"]}),
        normalize({"type": "vulnerability", "title": "server-status exposed",
                   "severity": "low", "tags": ["info-disclosure"]}),
    ]


def test_heuristic_judge_recall_and_fp():
    r = judge_heuristic(_findings(), EXPECTED)
    assert set(r.detected) == {"E-SQLI", "E-XSS"}
    assert r.missed == ["E-IDOR"]
    m = r.metrics()
    assert m["true_positives"] == 2
    assert m["false_negatives"] == 1
    assert m["false_positives"] == 1  # the info-disclosure finding
    assert round(m["recall"], 2) == 0.67
    assert round(m["precision"], 2) == 0.67


def test_judge_dispatch_falls_back_to_heuristic_without_llm():
    r = judge(_findings(), EXPECTED, backend="anthropic", llm_call=None)
    assert set(r.detected) == {"E-SQLI", "E-XSS"}


def test_judge_llm_with_fake_call():
    def fake_llm(system, user):
        return json.dumps({
            "matches": [
                {"expected_id": "E-SQLI", "finding_index": 0},
                {"expected_id": "E-XSS", "finding_index": 1},
                {"expected_id": "E-IDOR", "finding_index": 2},
            ],
            "missed": [],
            "false_positives": [],
        })

    r = judge_llm(_findings(), EXPECTED, fake_llm)
    assert set(r.detected) == {"E-SQLI", "E-XSS", "E-IDOR"}
    assert r.metrics()["recall"] == 1.0


def test_judge_llm_tolerates_fenced_json():
    def fake_llm(system, user):
        return "```json\n" + json.dumps(
            {"matches": [{"expected_id": "E-SQLI", "finding_index": 0}],
             "missed": ["E-XSS", "E-IDOR"], "false_positives": [1, 2]}
        ) + "\n```"

    r = judge_llm(_findings(), EXPECTED, fake_llm)
    assert r.detected == ["E-SQLI"]
    assert r.false_positive_count == 2
