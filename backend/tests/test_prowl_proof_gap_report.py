"""The proof-gap report counts stuck candidates and cells without leaking targets."""

import importlib.util
import json
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "prowl_proof_gap_report",
    Path(__file__).resolve().parents[1] / "scripts" / "prowl_proof_gap_report.py",
)
report_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(report_mod)


def test_summary_flags_unconfirmable_classes_and_open_cells():
    snapshots = [{"engagement_brain": {
        "candidates": [
            {"id": "a", "status": "inconclusive", "vulnerability_class": "csrf",
             "title": "CSRF on https://secret.example.test/files",
             "proof_gap": {"reason": "Missing proof cannot confirm csrf"}},
            {"id": "b", "status": "confirmed", "title": "SQL injection in id"},
            {"id": "c", "status": "inconclusive", "title": "SQL injection in q",
             "proof_gap": {"reason": "Verifier recorded no verdict after 2 attempts"}},
        ],
        "coverage_cells": [
            {"test_type": "reflected_xss", "status": "tested_clean"},
            {"test_type": "reflected_xss", "status": "inconclusive"},
            {"test_type": "sqli", "status": "untested"},
            {"test_type": "sqli", "status": "blocked",
             "first_pass_blocked_reason": "post_path_not_approved"},
        ],
    }}]
    works = [{"status": "completed", "stop_reason": "no new hypothesis or coverage progress"}]
    report = report_mod.summarize(snapshots, works)
    rows = {row["class"]: row for row in report["candidates_by_class"]}
    assert rows["csrf"]["can_confirm"] is False
    assert rows["sql_injection"]["confirmed"] == 1 and rows["sql_injection"]["inconclusive"] == 1
    xss = next(r for r in report["coverage_cells_by_test_type"] if r["test_type"] == "reflected_xss")
    assert xss["open"] == 1 and report["runs_with_open_cells"] == 1
    assert report["coverage_gaps"] == {"needs_operator:post_path_not_approved": 1}
    assert report["stop_reasons"][0]["reason"] == "no new hypothesis or coverage progress"
    assert any("no verdict after N attempts" in r["reason"] for r in report["top_inconclusive_reasons"])
    assert "secret.example.test" not in json.dumps(report)
