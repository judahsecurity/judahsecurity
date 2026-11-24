"""A/B runner for the product-agent class lab."""

import json
import sys

from local_harness.benchmark import ab_matrix


def _args(tmp_path, **extra):
    argv = ["--out-dir", str(tmp_path), "--classes", "sqli,jwt", "--dry-run"]
    for key, value in extra.items():
        argv += [f"--{key.replace('_', '-')}", str(value)]
    parser_args = ab_matrix.argparse.Namespace(
        out_dir=tmp_path, configs=["strict", "model_led"], classes="sqli,jwt",
        organization_id=1, user_id=2, max_turns=None, max_iterations=40,
        price_limit_usd=3.0, callback_suffix=None, port=18765, case_timeout=60,
        dry_run=True, score_only=False,
    )
    return argv, parser_args


def test_presets_set_every_flag_explicitly():
    keys = set(ab_matrix.PRESETS["strict"])
    for name, preset in ab_matrix.PRESETS.items():
        assert keys <= set(preset), name
    assert ab_matrix.PRESETS["strict"]["AGENT_STEERING_MODE"] == "strict"
    assert ab_matrix.PRESETS["model_led"]["AGENT_SELF_CHALLENGE"] == "true"


def test_plan_filters_classes_and_uses_class_identities(tmp_path):
    _argv, args = _args(tmp_path)
    plan = ab_matrix.build_plan(args)
    assert {s["case"]["bug_class"] for s in plan} == {"sqli", "jwt"}
    assert len(plan) == 8  # 2 configs x 2 classes x 2 polarities
    jwt = next(s for s in plan if s["case"]["id"] == "jwt-positive")
    assert jwt["identities"].name == "class_lab_jwt_identities.json"
    command = ab_matrix._agent_command(args, jwt)
    assert command[command.index("--max-iterations") + 1] == "40"
    corpus = json.loads((tmp_path / "strict" / "corpus.json").read_text())
    assert {c["bug_class"] for c in corpus["cases"]} == {"sqli", "jwt"}


def test_run_step_starts_lab_and_passes_flags(tmp_path, monkeypatch):
    _argv, args = _args(tmp_path)
    step = next(s for s in ab_matrix.build_plan(args)
                if s["config"] == "model_led" and s["case"]["id"] == "sqli-positive")
    probe = (
        "import os, json, urllib.request; "
        "body = urllib.request.urlopen('http://127.0.0.1:18765/').status; "
        "open(os.environ['AEGIS_FINDINGS_SINK'], 'w').close(); "
        "json.dump({'steer': os.environ['AGENT_STEERING_MODE'], 'lab': body}, "
        "open(os.path.join(os.path.dirname(os.environ['AEGIS_FINDINGS_SINK']), 'seen.json'), 'w'))"
    )
    monkeypatch.setattr(ab_matrix, "_agent_command", lambda a, s: [sys.executable, "-c", probe])
    outcome = ab_matrix.run_step(args, step)
    assert outcome["status"] == "ran", outcome
    seen = json.loads((step["run_dir"] / "seen.json").read_text())
    assert seen == {"steer": "advisory", "lab": 200}
    assert ab_matrix._port_free(18765)
    assert ab_matrix.run_step(args, step)["status"] == "skipped_existing"


def test_ssrf_positive_without_oast_is_skipped(tmp_path):
    _argv, args = _args(tmp_path)
    args.classes = "ssrf"
    step = next(s for s in ab_matrix.build_plan(args) if s["case"]["id"] == "ssrf-positive")
    assert ab_matrix.run_step(args, step)["status"] == "skipped_no_oast"


def test_compare_and_render():
    reports = {
        "strict": {"by_class": {"idor": {"passed": 1, "true_positives": 0, "verified_true_positives": 0,
                                         "false_positives": 0, "false_negatives": 1, "recall": 0.0,
                                         "verified_recall": 0.0, "precision": 0.0, "pass": False,
                                         "incomplete_or_error": 0, "cost_usd": 1.0}}},
        "model_led": {"by_class": {"idor": {"passed": 2, "true_positives": 1, "verified_true_positives": 1,
                                            "false_positives": 0, "false_negatives": 0, "recall": 1.0,
                                            "verified_recall": 1.0, "precision": 1.0, "pass": True,
                                            "incomplete_or_error": 0, "cost_usd": 1.5}}},
    }
    comparison = ab_matrix.compare(reports)
    delta = comparison["by_class"]["idor"]["model_led"]["delta"]
    assert delta["verified_true_positives"] == 1 and delta["cost_usd"] == 0.5
    assert comparison["totals"]["model_led"]["classes_passed"] == 1
    text = ab_matrix.render(comparison)
    assert "idor" in text and "1/0/Y" in text and "0/0/n" in text


def test_deep_presets_pass_the_assessment_mode_flag(tmp_path):
    _argv, args = _args(tmp_path)
    plan = ab_matrix.build_plan(args)
    step = dict(plan[0])
    for config, mode in (("strict", "standard"), ("model_led", "standard"),
                         ("deep", "deep"), ("deep_sandbox", "deep")):
        step["config"] = config
        command = ab_matrix._agent_command(args, step)
        assert command[command.index("--assessment-mode") + 1] == mode, config
    # deep differs from model_led only in budget, so the A/B isolates it.
    assert ab_matrix.PRESETS["deep"] == ab_matrix.PRESETS["model_led"]
    assert ab_matrix.PRESETS["deep_sandbox"] == ab_matrix.PRESETS["model_led_sandbox"]
