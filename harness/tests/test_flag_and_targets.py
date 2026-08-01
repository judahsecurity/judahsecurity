import json

from local_harness.benchmark import run as bench_run
from local_harness.benchmark.judge import judge_flag_capture
from local_harness.benchmark.targets import SetupResult, TargetManager
from local_harness.benchmark.xben_import import build_corpus, compute_flag
from local_harness.config import default_config
from local_harness.findings import normalize


# --- Flag-capture judge ---------------------------------------------------

def _finding_with_flag(flag):
    return normalize({
        "type": "vulnerability", "title": "IDOR to flag",
        "severity": "high",
        "raw_data": {"poc": {"response_snippet": f"200 OK\n\n{flag}\n"}},
    })


def test_flag_capture_exact_match():
    flag = "FLAG{" + "a" * 64 + "}"
    r = judge_flag_capture([_finding_with_flag(flag)], flag=flag)
    assert r.solved
    assert flag in r.matched_text


def test_flag_capture_regex_match():
    flag = "FLAG{" + "b" * 64 + "}"
    r = judge_flag_capture(
        [_finding_with_flag(flag)], flag_regex=r"FLAG\{[0-9a-f]{64}\}"
    )
    assert r.solved


def test_flag_capture_unsolved():
    r = judge_flag_capture(
        [normalize({"type": "vulnerability", "title": "XSS", "severity": "low"})],
        flag="FLAG{deadbeef}",
    )
    assert not r.solved


# --- Target manager (injected runners, no docker/network) -----------------

def test_target_manager_setup_teardown_with_explicit_url():
    calls = []

    def fake_run(cmd, timeout):
        calls.append(cmd)
        return 0, "ok"

    tm = TargetManager(command_runner=fake_run, http_probe=lambda url: True,
                       poll_interval=0)
    spec = {"target": "http://localhost:3000",
            "setup": {"up": "docker up", "down": "docker down"}}
    res = tm.setup(spec)
    assert res.ok and res.target_url == "http://localhost:3000"
    tm.teardown(spec)
    assert calls == ["docker up", "docker down"]


def test_target_manager_up_failure():
    tm = TargetManager(command_runner=lambda c, t: (1, "boom"),
                       http_probe=lambda url: True, poll_interval=0)
    res = tm.setup({"target": "http://x", "setup": {"up": "docker up"}})
    assert not res.ok and "up failed" in res.detail


def test_target_manager_no_setup_is_noop():
    tm = TargetManager(command_runner=lambda c, t: (0, ""),
                       http_probe=lambda url: True)
    res = tm.setup({"target": "http://x"})
    assert res.ok and res.target_url == "http://x"


def test_target_manager_compose_port_discovery():
    ps_json = json.dumps([{
        "Service": "app",
        "Publishers": [{"TargetPort": 80, "PublishedPort": 49001, "Protocol": "tcp"}],
    }])

    def fake_run(cmd, timeout):
        if "compose" in cmd and "ps" in cmd:
            return 0, ps_json
        return 0, "ok"

    tm = TargetManager(command_runner=fake_run, http_probe=lambda url: True,
                       poll_interval=0)
    spec = {"setup": {"up": "make run", "compose_file": "dc.yml",
                      "container_port": 80}}
    res = tm.setup(spec)
    assert res.ok
    assert res.target_url == "http://localhost:49001/"


# --- XBEN importer --------------------------------------------------------

def test_compute_flag_is_deterministic():
    # FLAG{sha256("XBEN-001-24")}
    import hashlib
    expected = "FLAG{" + hashlib.sha256(b"XBEN-001-24").hexdigest() + "}"
    assert compute_flag("XBEN-001-24") == expected
    assert compute_flag("xben-001-24") == expected  # upper-cased first


def test_build_corpus_from_fake_clone(tmp_path):
    bench = tmp_path / "benchmarks" / "XBEN-001-24"
    bench.mkdir(parents=True)
    (bench / "benchmark.json").write_text(json.dumps({
        "name": "IDOR - Trading Platform", "level": "2",
        "tags": ["idor"], "win_condition": "flag",
    }))
    (bench / "docker-compose.yml").write_text("services: {}")

    corpus = build_corpus(tmp_path)
    assert "XBEN-001-24" in corpus
    entry = corpus["XBEN-001-24"]
    assert entry["flag"] == compute_flag("XBEN-001-24")
    assert entry["setup"]["container_port"] == 80
    assert "make -C" in entry["setup"]["up"]


# --- Flag-mode benchmark end-to-end (stub scanner emits the flag) ---------

def test_benchmark_flag_mode_solved(stub_env, monkeypatch, tmp_path):
    flag = "FLAG{" + "c" * 64 + "}"
    monkeypatch.setenv("AEGIS_STUB_FLAG", flag)

    corpus = {
        "demo-flag": {
            "name": "demo flag challenge",
            "flag": flag,
            "target": "http://localhost:3000",
            "scope": "localhost",
        }
    }
    gt = tmp_path / "xben.json"
    gt.write_text(json.dumps(corpus))

    rc = bench_run.main(["--ground-truth", str(gt), "--min-success-rate", "1.0"])
    assert rc == 0

    cfg = default_config()
    report = json.loads((cfg.benchmark_dir / "benchmark_report.json").read_text())
    assert report["aggregate"]["flag"]["solved"] == 1
    assert report["aggregate"]["flag"]["success_rate"] == 1.0
    assert report["targets"]["demo-flag"]["solved"] is True


def test_benchmark_flag_mode_gate_fails_when_unsolved(stub_env, tmp_path):
    # No AEGIS_STUB_FLAG set → stub does not emit the flag → unsolved.
    corpus = {
        "demo-flag": {
            "name": "demo",
            "flag": "FLAG{" + "d" * 64 + "}",
            "target": "http://localhost:3000",
        }
    }
    gt = tmp_path / "xben.json"
    gt.write_text(json.dumps(corpus))

    rc = bench_run.main(["--ground-truth", str(gt), "--min-success-rate", "0.8"])
    assert rc == 2  # gate tripped
