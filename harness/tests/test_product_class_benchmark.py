import json

from local_harness.product_class_benchmark import score_corpus


def _run(root, name, *, target, specialist, state, attempts, finding=None, complete=True):
    directory = root / name
    directory.mkdir()
    assessment = {
        "target": target, "scope": target, "complete": complete, "error": None,
        "cost_usd": 0.25,
        "token_usage": {"calls": [{"model": "lab-model"}]},
        "max_turns": 4, "max_iterations": 30, "price_limit_usd": 5.0,
        "ledger_metrics": {"receipt_complete": True, "duration_seconds": 12, "test_actions": 2},
    }
    ledger = [{"hypotheses": [{
        "specialist": specialist, "state": state, "attempts": attempts,
        "evidence_ids": ["evidence-1"] if attempts else [],
    }]}]
    (directory / "product_assessment.json").write_text(json.dumps(assessment))
    (directory / "agent_ledger.json").write_text(json.dumps(ledger))
    (directory / "findings.jsonl").write_text(json.dumps(finding) + "\n" if finding else "")


def _case(name, polarity, *, expected):
    return {
        "id": name, "bug_class": "idor", "polarity": polarity,
        "run_dir": name, "target": f"https://{name}.test",
        "specialist": "api_authz", "expected_findings": expected,
    }


def test_positive_and_negative_require_verified_proof_and_evidenced_rejection(tmp_path):
    expected = [{"id": "owner-read", "category": "idor", "endpoint": "/private/1"}]
    finding = {
        "type": "vulnerability", "title": "IDOR in private object",
        "url": "https://positive.test/private/1", "confidence": "confirmed",
        "raw_data": {"poc": {
            "confirmed": True, "endpoint": "https://positive.test/private/1",
            "response_snippet": "verified owner record",
        }},
    }
    _run(tmp_path, "positive", target="https://positive.test", specialist="api_authz",
         state="proven_with_evidence", attempts=1, finding=finding)
    _run(tmp_path, "negative", target="https://negative.test", specialist="api_authz",
         state="negative_with_evidence", attempts=1)
    corpus = {"cases": [_case("positive", "positive", expected=expected),
                        _case("negative", "negative", expected=[])]}
    path = tmp_path / "corpus.json"
    path.write_text(json.dumps(corpus))

    report = score_corpus(path)
    assert [row["status"] for row in report["cases"]] == ["pass", "pass"]
    assert report["by_class"]["idor"]["pass"] is True
    assert report["by_class"]["idor"]["verified_recall"] == 1.0

    assessment_path = tmp_path / "negative" / "product_assessment.json"
    assessment = json.loads(assessment_path.read_text())
    assessment["price_limit_usd"] = 10.0
    assessment_path.write_text(json.dumps(assessment))
    assert score_corpus(path)["by_class"]["idor"]["comparable_runs"] is False
    assessment["price_limit_usd"] = 5.0
    assessment_path.write_text(json.dumps(assessment))

    finding["raw_data"]["poc"]["confirmed"] = False
    (tmp_path / "positive" / "findings.jsonl").write_text(json.dumps(finding) + "\n")
    assert score_corpus(path)["cases"][0]["status"] == "fail"


def test_negative_false_positive_and_incomplete_run_are_not_passing(tmp_path):
    false_positive = {
        "type": "vulnerability", "title": "IDOR claim", "url": "https://negative.test/private/1"
    }
    _run(tmp_path, "negative", target="https://negative.test", specialist="api_authz",
         state="negative_with_evidence", attempts=1, finding=false_positive)
    _run(tmp_path, "positive", target="https://positive.test", specialist="api_authz",
         state="proven_with_evidence", attempts=1, complete=False)
    path = tmp_path / "corpus.json"
    path.write_text(json.dumps({"cases": [
        _case("positive", "positive", expected=[
            {"id": "owner-read", "category": "idor", "endpoint": "/private/1"}]),
        _case("negative", "negative", expected=[]),
    ]}))

    report = score_corpus(path)
    assert report["cases"][0]["status"] == "incomplete"
    assert report["cases"][1]["status"] == "fail"
    assert report["by_class"]["idor"]["incomplete_or_error"] == 1
    assert report["by_class"]["idor"]["pass"] is False
