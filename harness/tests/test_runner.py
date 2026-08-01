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
