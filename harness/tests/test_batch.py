import json

from local_harness.batch import run as batch_run
from local_harness.config import default_config


def _write_list(tmp_path, targets):
    p = tmp_path / "list.txt"
    p.write_text("\n".join(targets) + "\n", encoding="utf-8")
    return p


def test_parse_target_list_with_scope_and_comments(tmp_path):
    p = _write_list(tmp_path, [
        "# comment",
        "",
        "https://a.com, a.com",
        "https://b.com",
    ])
    parsed = batch_run.parse_target_list(p)
    assert parsed == [("https://a.com", "a.com"), ("https://b.com", None)]


def test_batch_scan_status_collect_end_to_end(stub_env, capsys):
    list_path = _write_list(stub_env, ["http://localhost:3000", "http://localhost:8080"])

    rc = batch_run.main(["scan", "--list", str(list_path)])
    assert rc == 0

    cfg = default_config()
    state = json.loads(cfg.batch_state_path.read_text())
    assert len(state) == 2
    assert all(e["status"] == "done" for e in state.values())
    # 3 vulns per target from the stub scanner.
    assert all(e["vuln_count"] == 3 for e in state.values())

    assert batch_run.main(["status"]) == 0
    assert batch_run.main(["collect"]) == 0

    collected = json.loads((cfg.batch_dir / "collected_findings.json").read_text())
    assert collected["totals"]["vulnerabilities"] == 6
    assert collected["totals"]["by_severity"]["critical"] == 2


def test_batch_fail_on_findings_exit_code(stub_env):
    list_path = _write_list(stub_env, ["http://localhost:3000"])
    # Stub always emits vulns → gate should trip with exit 2.
    rc = batch_run.main(["scan", "--list", str(list_path), "--fail-on-findings"])
    assert rc == 2


def test_batch_scan_resume_skips_completed(stub_env):
    list_path = _write_list(stub_env, ["http://localhost:3000"])
    assert batch_run.main(["scan", "--list", str(list_path)]) == 0

    cfg = default_config()
    first = json.loads(cfg.batch_state_path.read_text())
    started_at = list(first.values())[0]["started_at"]

    # Resume should not re-run the completed target.
    assert batch_run.main(["scan", "--list", str(list_path), "--resume"]) == 0
    second = json.loads(cfg.batch_state_path.read_text())
    assert list(second.values())[0]["started_at"] == started_at
