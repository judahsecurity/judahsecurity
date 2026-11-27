"""Gin & Juice Shop scorecard: buckets, likely causes, generic findings, comparison."""

import json

from local_harness.benchmark import ginandjuice_scorecard as sc


def _prowl_export(tmp_path, candidates, **extra):
    data = {
        "schema": "prowl-run-export/1", "session_id": "s1",
        "run": {"status": "timeout", "reason": "Request ceiling reached", "duration_s": 1800},
        "candidates": candidates,
        "coverage": {"by_test_type": {"sqli": 4, "xss": 6},
                     "tested_test_types": ["sqli", "xss"]},
        "tools": {"runs": {"execute_deep_crawl": 1, "probe_observed_input_batch": 2}},
    }
    data.update(extra)
    path = tmp_path / "prowl_run.json"
    path.write_text(json.dumps(data))
    return path


CANDIDATES = [
    {"id": "c1", "title": "SQLI proof on GET /catalog (category)", "vulnerability_class": "sql_injection",
     "target": "https://ginandjuice.shop/catalog?category=Gin", "status": "confirmed"},
    {"id": "c2", "title": "Reflected XSS in search", "vulnerability_class": "xss",
     "target": "https://ginandjuice.shop/blog?search=x", "status": "inconclusive"},
    {"id": "c3", "title": "AngularJS template injection", "vulnerability_class": "client_template_injection",
     "target": "https://ginandjuice.shop/blog", "status": "refuted"},
    {"id": "c4", "title": "Git repository metadata exposed: /.git/config", "vulnerability_class": "exposure",
     "target": "https://ginandjuice.shop/.git/config", "status": "confirmed"},
    {"id": "c5", "title": "Guessed SSTI", "vulnerability_class": "ssti",
     "target": "https://ginandjuice.shop/x", "status": "refuted"},
]


def _rows(card):
    return {row["id"]: row for row in card["rows"]}


def test_ground_truth_is_valid_and_uses_real_prowl_classes():
    import os

    os.environ.setdefault("SECRET_KEY", "x" * 40)
    from app.services.agent.proof_policy import PROOFS_BY_CLASS

    truth = sc.load_ground_truth()
    ids = [item["id"] for item in truth["expected_findings"]]
    assert len(ids) == len(set(ids))
    for item in truth["expected_findings"]:
        assert item["tier"] in ("core", "hygiene") and item["confidence"] in ("high", "medium", "low")
        assert set(item["classes"]) <= set(PROOFS_BY_CLASS), item["id"]
        assert item["classes"] or item["keywords"], item["id"]


def test_prowl_run_buckets_and_extras(tmp_path):
    card = sc.score_run(sc.load_run(_prowl_export(tmp_path, CANDIDATES)), sc.load_ground_truth())
    rows = _rows(card)
    assert rows["GJ-SQLI-CATALOG"]["bucket"] == "verified"
    assert rows["GJ-XSS-REFLECTED"]["bucket"] == "unverified"
    assert rows["GJ-CSTI"]["bucket"] == "refuted"
    assert rows["GJ-XXE-STOCK"]["bucket"] == "missed"
    assert card["core_detected"] == 2 and card["core"]["verified"] == 1
    # The exposure is real but not in the ground truth; the SSTI was a caught false positive.
    assert card["extras"]["confirmed"] == ["Git repository metadata exposed: /.git/config"]
    assert card["extras"]["refuted"] == ["Guessed SSTI"]


def test_misses_name_a_likely_cause(tmp_path):
    card = sc.score_run(sc.load_run(_prowl_export(tmp_path, CANDIDATES)), sc.load_ground_truth())
    xxe = _rows(card)["GJ-XXE-STOCK"]["likely_cause"]
    assert "no coverage cell was planned" in xxe
    assert "needs post_xml" in xxe and "needs oast" in xxe
    assert "request ceiling reached" in xxe
    assert "verifier refuted" in _rows(card)["GJ-CSTI"]["likely_cause"]


def test_class_beats_keywords_and_endpoint_breaks_ties(tmp_path):
    candidates = [{"id": "a", "title": "Open redirect via returnUrl", "vulnerability_class": "",
                   "target": "https://ginandjuice.shop/x", "status": "pending"}]
    card = sc.score_run(sc.load_run(_prowl_export(tmp_path, candidates)), sc.load_ground_truth())
    assert _rows(card)["GJ-DOM-OPEN-REDIRECT"]["bucket"] == "unverified"


def test_generic_findings_list_scores_as_unverified_unless_marked(tmp_path):
    path = tmp_path / "antifox.json"
    path.write_text(json.dumps({"findings": [
        {"title": "SQL Injection in category parameter", "url": "https://ginandjuice.shop/catalog"},
        {"title": "XXE in stock check", "verified": True},
        {"title": "Strict-Transport-Security header missing (HSTS)"},
    ]}))
    card = sc.score_run(sc.load_run(path), sc.load_ground_truth())
    rows = _rows(card)
    assert rows["GJ-SQLI-CATALOG"]["bucket"] == "unverified"
    assert rows["GJ-XXE-STOCK"]["bucket"] == "verified"
    assert rows["GJ-HSTS"]["bucket"] == "unverified" and card["hygiene_detected"] == 1
    assert "likely_cause" not in rows["GJ-CSTI"]  # no run record to explain a generic miss


def test_cli_prints_scorecards_and_comparison(tmp_path, capsys):
    prowl = _prowl_export(tmp_path, CANDIDATES)
    other = tmp_path / "antifox.json"
    other.write_text(json.dumps([{"title": "XXE in stock check"}]))
    assert sc.main([str(prowl), "--compare", str(other)]) == 0
    out = capsys.readouterr().out
    assert "Core issues: 2/9 detected (1 verified, 1 unverified)" in out
    assert "GJ-XXE-STOCK" in out and "core detected" in out
    assert sc.main([str(prowl), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["run"]["core_detected"] == 2
