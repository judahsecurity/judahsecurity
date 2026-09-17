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
