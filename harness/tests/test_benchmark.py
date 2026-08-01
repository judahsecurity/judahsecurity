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
