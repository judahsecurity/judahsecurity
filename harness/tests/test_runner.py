import json

from local_harness.config import default_config
from local_harness.runner import build_command, run_scan, slugify


def test_slugify():
    assert slugify("https://app.example.com/path") == "app.example.com"
    assert slugify("http://localhost:3000") == "localhost_3000"
    assert slugify("example.com") == "example.com"


def test_build_command_appends_target_scope_and_extra_args():
    cfg = default_config()
    cfg.scanner_cmd = ["python3", "run_pentest.py"]
    cfg.scanner_extra_args = ["--fast"]
    cmd = build_command(cfg, "https://x.com", "x.com")
    assert cmd == ["python3", "run_pentest.py", "--target", "https://x.com",
                   "--scope", "x.com", "--fast"]


def test_build_command_preserves_dynamic_localhost_port_in_scope():
    cfg = default_config()
    cfg.scanner_cmd = ["scanner"]
    cmd = build_command(cfg, "http://localhost:52490/", "localhost")
    assert cmd == [
        "scanner", "--target", "http://localhost:52490/",
        "--scope", "localhost:52490",
    ]


def test_run_scan_captures_findings_via_injected_runner(tmp_path):
    cfg = default_config()
    cfg.work_dir = tmp_path

    def fake_runner(cmd, cwd, env, timeout):
        # Emulate a scanner that writes to the sink the runner configured.
        sink = env["AEGIS_FINDINGS_SINK"]
        with open(sink, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"type": "vulnerability", "title": "SQLi",
                                 "severity": "critical"}) + "\n")
        return 0, "ok"

    result = run_scan("https://x.com", cfg, tmp_path / "out",
                      subprocess_runner=fake_runner)
    assert result.status == "done"
    assert result.finding_count == 1
    assert result.findings[0].category == "sqli"
    assert result.log_path.exists()


def test_run_scan_can_use_a_stable_artifact_name(tmp_path):
    cfg = default_config()
    cfg.work_dir = tmp_path

    def fake_runner(cmd, cwd, env, timeout):
        return 0, "ok"

    result = run_scan(
        "http://localhost:54321/",
        cfg,
        tmp_path / "out",
        subprocess_runner=fake_runner,
        artifact_name="XBEN-071-24",
    )

    assert result.slug == "XBEN-071-24"
    assert result.out_dir == tmp_path / "out" / "XBEN-071-24"


def test_run_scan_loads_trace_cost_and_guardrail_summary(tmp_path):
    cfg = default_config()
    cfg.work_dir = tmp_path

    def fake_runner(cmd, cwd, env, timeout):
        trace_dir = env["AEGIS_TRACES_DIR"]
        with open(f"{trace_dir}/trace_test.json", "w", encoding="utf-8") as fh:
            json.dump({
                "summary": {
                    "estimated_cost_usd": 1.25,
                    "tokens": {"input": 100, "output": 25},
                    "guardrail_blocks": 3,
                }
            }, fh)
        return 0, "ok"

    result = run_scan(
        "https://x.com", cfg, tmp_path / "out", subprocess_runner=fake_runner
    )

    assert result.cost_usd == 1.25
    assert result.trace_summary["guardrail_blocks"] == 3


def test_run_scan_does_not_reuse_a_stale_trace(tmp_path):
    cfg = default_config()
    cfg.work_dir = tmp_path
    out_dir = tmp_path / "out" / "stable-id"
    out_dir.mkdir(parents=True)
    (out_dir / "trace_old.json").write_text(json.dumps({
        "summary": {
            "estimated_cost_usd": 9.99,
            "guardrail_blocks": 7,
        }
    }))

    def failing(cmd, cwd, env, timeout):
        return 2, "argument error"

    result = run_scan(
        "https://x.com",
        cfg,
        tmp_path / "out",
        subprocess_runner=failing,
        artifact_name="stable-id",
    )

    assert result.status == "error"
    assert result.trace_summary is None
    assert result.cost_usd is None
    assert not list(out_dir.glob("trace_*.json"))


def test_run_scan_nonzero_exit_is_error(tmp_path):
    cfg = default_config()

    def failing(cmd, cwd, env, timeout):
        return 3, "boom"

    result = run_scan("https://x.com", cfg, tmp_path / "out",
                      subprocess_runner=failing)
    assert result.status == "error"
    assert "code 3" in result.error


def test_run_scan_with_real_stub_subprocess(stub_env):
    # stub_env sets scanner cmd/cwd/work dir via env; default_config reads them.
    cfg = default_config()
    result = run_scan("http://localhost:3000", cfg, cfg.work_dir / "out")
    assert result.status == "done"
    # 4 findings emitted by the stub (1 recon + 3 vulns).
    assert result.finding_count == 4
    cats = {f.category for f in result.findings if f.is_vulnerability}
    assert "sqli" in cats and "xss" in cats
