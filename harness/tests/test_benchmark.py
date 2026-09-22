import json

from local_harness.benchmark import run as bench_run
from local_harness.config import default_config


def test_load_ground_truth_drops_metadata(sample_ground_truth):
    corpus = bench_run.load_ground_truth(sample_ground_truth)
    assert "_comment" not in corpus
    assert "demo" in corpus


def test_benchmark_full_run(stub_env, sample_ground_truth):
    rc = bench_run.main(["--ground-truth", str(sample_ground_truth)])
    assert rc == 0

    cfg = default_config()
    report = json.loads((cfg.benchmark_dir / "benchmark_report.json").read_text())

    demo = report["targets"]["demo"]
    # Stub finds sqli + xss (match D-SQLI, D-XSS); D-IDOR is missed.
    assert demo["true_positives"] == 2
    assert demo["false_negatives"] == 1
    # info-disclosure finding is an unmatched candidate FP.
    assert demo["false_positives"] == 1
    assert report["detail"]["demo"]["missed"] == ["D-IDOR"]

    agg = report["aggregate"]["findings"]
    assert agg["true_positives"] == 2
    assert round(agg["recall"], 2) == 0.67
    assert report["targets"]["demo"]["cost_usd"] == 0.375
    assert report["aggregate"]["cost"]["cost_usd"] == 0.375


def test_benchmark_tally_only_reuses_artifacts(stub_env, sample_ground_truth):
    # First a real (stub) scan to produce artifacts.
    assert bench_run.main(["--ground-truth", str(sample_ground_truth)]) == 0
    # Then tally-only should succeed without rescanning.
    assert bench_run.main(
        ["--ground-truth", str(sample_ground_truth), "--tally-only"]
    ) == 0


def test_tally_only_preserves_artifact_manifest(stub_env, sample_ground_truth, monkeypatch):
    monkeypatch.setenv("AEGIS_MODEL", "artifact-model")
    assert bench_run.main(["--ground-truth", str(sample_ground_truth)]) == 0
    cfg = default_config()
    original = json.loads((cfg.benchmark_dir / "manifest.json").read_text())

    monkeypatch.setenv("AEGIS_MODEL", "judge-model")
    assert bench_run.main(
        ["--ground-truth", str(sample_ground_truth), "--tally-only"]
    ) == 0

    preserved = json.loads((cfg.benchmark_dir / "manifest.json").read_text())
    tally = json.loads((cfg.benchmark_dir / "tally_manifest.json").read_text())
    report = json.loads((cfg.benchmark_dir / "benchmark_report.json").read_text())
    assert preserved == original
    assert preserved["agent_model"] == "artifact-model"
    assert tally["agent_model"] == "judge-model"
    assert report["manifest"] == original


def test_tally_only_keeps_prior_scanner_failure(stub_env, sample_ground_truth, monkeypatch):
    monkeypatch.setenv("AEGIS_STUB_EXIT_CODE", "1")
    assert bench_run.main(["--ground-truth", str(sample_ground_truth)]) == 3
    monkeypatch.delenv("AEGIS_STUB_EXIT_CODE")
    assert bench_run.main(
        ["--ground-truth", str(sample_ground_truth), "--tally-only"]
    ) == 3
    report = json.loads(
        (default_config().benchmark_dir / "benchmark_report.json").read_text()
    )
    assert report["targets"]["demo"]["error"] == "scanner exited with code 1"


def test_tally_only_rejects_changed_ground_truth(stub_env, sample_ground_truth):
    assert bench_run.main(["--ground-truth", str(sample_ground_truth)]) == 0
    corpus = json.loads(sample_ground_truth.read_text())
    corpus["demo"]["expected_findings"].append({
        "id": "NEW", "category": "ssrf", "endpoint": "/fetch",
    })
    sample_ground_truth.write_text(json.dumps(corpus))
    assert bench_run.main(
        ["--ground-truth", str(sample_ground_truth), "--tally-only"]
    ) == 3
    report = json.loads(
        (default_config().benchmark_dir / "benchmark_report.json").read_text()
    )
    assert "ground truth does not match" in report["targets"]["demo"]["error"]


def test_late_scanner_error_preserves_findings_for_diagnostic_scoring(
    stub_env, sample_ground_truth, monkeypatch
):
    monkeypatch.setenv("AEGIS_STUB_EXIT_CODE", "1")

    assert bench_run.main(["--ground-truth", str(sample_ground_truth)]) == 3

    report = json.loads(
        (default_config().benchmark_dir / "benchmark_report.json").read_text()
    )
    demo = report["targets"]["demo"]
    assert demo["error"] == "scanner exited with code 1"
    assert demo["true_positives"] == 2
    assert demo["false_negatives"] == 1
    assert report["aggregate"]["completion"]["completed"] == 0


def test_benchmark_repos_filter(stub_env, sample_ground_truth):
    rc = bench_run.main(
        ["--ground-truth", str(sample_ground_truth), "--repos", "nonexistent"]
    )
    assert rc == 1


def test_requested_flag_metric_must_exist(stub_env, sample_ground_truth):
    rc = bench_run.main([
        "--ground-truth", str(sample_ground_truth),
        "--min-success-rate", "0.8",
    ])
    assert rc == 2


def test_tally_only_missing_artifact_is_scan_error(stub_env, tmp_path):
    gt = tmp_path / "flags.json"
    gt.write_text(json.dumps({
        "missing": {
            "target": "http://localhost:3000",
            "flag": "FLAG{" + "e" * 64 + "}",
        }
    }))

    rc = bench_run.main(["--ground-truth", str(gt), "--tally-only"])

    assert rc == 3
    report = json.loads(
        (default_config().benchmark_dir / "benchmark_report.json").read_text()
    )
    assert report["aggregate"]["flag"]["total"] == 1
    assert report["aggregate"]["flag"]["solved"] == 0
    assert report["scan_errors"] == ["missing"]
