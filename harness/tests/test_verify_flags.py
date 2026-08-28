import json

from local_harness.benchmark.verify_flags import (
    candidate_flags,
    resolve_flag,
    verify_corpus,
    main,
    _tokens_in,
)
from local_harness.benchmark.xben_import import compute_flag


def _mk_challenge(root, name, *, env_flag=None, compose_text="services: {}",
                  dockerfile=None, benchmark=None):
    d = root / "benchmarks" / name
    d.mkdir(parents=True)
    (d / "benchmark.json").write_text(json.dumps(benchmark or {"name": name, "level": "1"}))
    (d / "docker-compose.yml").write_text(compose_text)
    if env_flag is not None:
        (d / ".env").write_text(f'FLAG={env_flag}\n')
    if dockerfile is not None:
        (d / "Dockerfile").write_text(dockerfile)
    return d


# --- token scanning -------------------------------------------------------

def test_tokens_matches_both_flag_styles():
    text = "FLAG{" + "a" * 64 + "} and flag{85c0d827-5e28-4577-be2b-319bdcbf872d}"
    toks = _tokens_in(text)
    assert len(toks) == 2
    assert any(t.startswith("FLAG{") for t in toks)
    assert any(t.startswith("flag{") for t in toks)


# --- candidate / resolve --------------------------------------------------

def test_candidate_includes_sha256_default(tmp_path):
    d = _mk_challenge(tmp_path, "XBEN-001-24")
    cands = candidate_flags(d, "XBEN-001-24")
    assert cands["sha256"] == compute_flag("XBEN-001-24")


def test_env_override_wins_resolution(tmp_path):
    d = _mk_challenge(tmp_path, "XBEN-002-24", env_flag="flag{real-env-value}")
    assert resolve_flag(d, "XBEN-002-24") == "flag{real-env-value}"
    cands = candidate_flags(d, "XBEN-002-24")
    assert cands["env"] == "flag{real-env-value}"
    assert "sha256" in cands  # still offered as a candidate


def test_flag_literal_in_compose_is_a_candidate(tmp_path):
    baked = "FLAG{" + "f" * 64 + "}"
    d = _mk_challenge(tmp_path, "XBEN-003-24",
                      compose_text=f"services:\n  app:\n    environment:\n      FLAG: {baked}\n")
    cands = candidate_flags(d, "XBEN-003-24")
    assert baked in cands.values()


# --- corpus verification --------------------------------------------------

def test_verify_ok_when_gt_matches_sha256(tmp_path):
    _mk_challenge(tmp_path, "XBEN-001-24")
    gt = {"XBEN-001-24": {"flag": compute_flag("XBEN-001-24"),
                          "setup": {"compose_file": "x"}}}
    [res] = verify_corpus(gt, tmp_path)
    assert res["status"] == "OK"
    assert res["matched_source"] == "sha256"


def test_verify_mismatch_when_gt_matches_nothing(tmp_path):
    _mk_challenge(tmp_path, "XBEN-001-24", env_flag="flag{decoy}")
    gt = {"XBEN-001-24": {"flag": "FLAG{" + "9" * 64 + "}"}}  # neither env nor sha256
    [res] = verify_corpus(gt, tmp_path)
    assert res["status"] == "MISMATCH"
    assert res["matched_source"] is None


def test_verify_no_dir_reported(tmp_path):
    gt = {"XBEN-999-24": {"flag": "FLAG{x}"}}
    [res] = verify_corpus(gt, tmp_path)
    assert res["status"] == "NO_DIR"


def test_verify_skips_regex_challenges(tmp_path):
    gt = {"demo": {"flag_regex": r"FLAG\{[0-9a-f]{64}\}"}}
    [res] = verify_corpus(gt, tmp_path)
    assert res["status"] == "SKIP_REGEX"


# --- CLI gate + fix -------------------------------------------------------

def test_main_gate_trips_on_mismatch(tmp_path, capsys):
    _mk_challenge(tmp_path, "XBEN-001-24", env_flag="flag{decoy}")
    gt_path = tmp_path / "gt.json"
    gt_path.write_text(json.dumps({"XBEN-001-24": {"flag": "FLAG{" + "9" * 64 + "}"}}))
    rc = main(["--ground-truth", str(gt_path), "--corpus", str(tmp_path)])
    assert rc == 2
    assert "match no known source" in capsys.readouterr().out


def test_live_mode_is_authoritative(tmp_path, monkeypatch):
    import local_harness.benchmark.verify_flags as vf
    _mk_challenge(tmp_path, "XBEN-001-24", env_flag="flag{decoy}")
    real = "FLAG{" + "7" * 64 + "}"
    monkeypatch.setattr(vf, "live_tokens", lambda compose: [real])
    # ground truth carries the decoy; the running container serves `real`.
    gt = {"XBEN-001-24": {"flag": "flag{decoy}", "setup": {"compose_file": "dc.yml"}}}
    [res] = vf.verify_corpus(gt, tmp_path, live=True)
    assert res["status"] == "LIVE_MISMATCH"
    assert res["live_found"] == [real]


def test_setup_brings_up_and_tears_down_around_live_read(tmp_path, monkeypatch):
    import local_harness.benchmark.verify_flags as vf
    from local_harness.benchmark.targets import TargetManager

    _mk_challenge(tmp_path, "XBEN-001-24", env_flag="flag{decoy}")
    real = "FLAG{" + "3" * 64 + "}"
    monkeypatch.setattr(vf, "live_tokens", lambda compose: [real])

    calls = []
    tm = TargetManager(command_runner=lambda c, t: (calls.append(c), (0, "ok"))[1],
                       http_probe=lambda url: True, poll_interval=0)
    gt = {"XBEN-001-24": {"target": "http://localhost:3000",
                          "flag": "flag{decoy}",
                          "setup": {"up": "make run", "down": "make stop",
                                    "compose_file": "dc.yml"}}}
    [res] = vf.verify_corpus(gt, tmp_path, live=True, setup=True, target_manager=tm)
    assert res["status"] == "LIVE_MISMATCH"
    assert res["live_found"] == [real]
    assert calls == ["make run", "make stop"]  # up before, down after


def test_setup_failure_is_a_gate(tmp_path):
    import local_harness.benchmark.verify_flags as vf
    from local_harness.benchmark.targets import TargetManager

    _mk_challenge(tmp_path, "XBEN-001-24")
    tm = TargetManager(command_runner=lambda c, t: (1, "boom"),
                       http_probe=lambda url: True, poll_interval=0)
    gt = {"XBEN-001-24": {"flag": "FLAG{x}", "setup": {"up": "make run"}}}
    [res] = vf.verify_corpus(gt, tmp_path, live=True, setup=True, target_manager=tm)
    assert res["status"] == "SETUP_FAILED"


def test_main_fix_rewrites_to_resolved(tmp_path):
    _mk_challenge(tmp_path, "XBEN-001-24", env_flag="flag{real-env}")
    gt_path = tmp_path / "gt.json"
    gt_path.write_text(json.dumps({"XBEN-001-24": {"flag": "FLAG{wrong}"}}))
    out = tmp_path / "fixed.json"
    main(["--ground-truth", str(gt_path), "--corpus", str(tmp_path),
          "--fix", "--out", str(out)])
    fixed = json.loads(out.read_text())
    assert fixed["XBEN-001-24"]["flag"] == "flag{real-env}"
