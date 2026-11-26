"""Run the product-agent class lab under several agent configurations and compare.

One command replaces the manual loop in the README: for each configuration it
writes the lab manifest, starts each positive/negative lab case on loopback,
runs the in-product agent with that configuration's flags and the same budget,
scores the runs with ``product_class_benchmark``, and finally prints a
per-class comparison against the first configuration (the baseline).

Requirements are the same as a single product-agent run: a configured backend
(``SECRET_KEY``, LLM credentials), a dedicated assessment organization and
database, and ``AEGIS_EVIDENCE_DIR``. Example::

    cd harness
    python -m local_harness.benchmark.ab_matrix --out-dir runs/ab \\
        --organization-id "$LAB_ORG_ID" --user-id "$LAB_USER_ID" \\
        --configs strict,model_led --max-iterations 80 --price-limit-usd 4

Use ``--dry-run`` to print the plan without running anything.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

HARNESS = Path(__file__).resolve().parents[2]

# Each preset sets every flag explicitly, so runs never inherit a stray .env.
PRESETS: Dict[str, Dict[str, str]] = {
    "strict": {
        "AGENT_STEERING_MODE": "strict",
        "AGENT_HUNT_DISCIPLINE_PROMPT": "false",
        "AGENT_SELF_CHALLENGE": "false",
        "AGENT_RECHECK_WEAK_NEGATIVES": "false",
        "AGENT_SETTLEMENT_BACKFILL": "false",
        "AGENT_STREAMING_FIRST_PASS": "false",
        "AGENT_HUNT_ENGINE": "false",
        "AGENT_CUSTOM_PROBE_MODE": "off",
        "AGENT_SANDBOX_SHELL": "false",
    },
    # The compose defaults on this branch, without the sandbox containers.
    "model_led": {
        "AGENT_STEERING_MODE": "advisory",
        "AGENT_STEERING_FREE_TURNS": "2",
        "AGENT_HUNT_DISCIPLINE_PROMPT": "true",
        "AGENT_SELF_CHALLENGE": "true",
        "AGENT_RECHECK_WEAK_NEGATIVES": "true",
        "AGENT_SETTLEMENT_BACKFILL": "false",
        "AGENT_STREAMING_FIRST_PASS": "false",
        "AGENT_HUNT_ENGINE": "false",
        "AGENT_CUSTOM_PROBE_MODE": "off",
        "AGENT_SANDBOX_SHELL": "false",
    },
    # model_led plus sandbox_shell; needs probe-egress/probe-runner reachable
    # at AGENT_PROBE_RUNNER_URL with AGENT_PROBE_RUNNER_TOKEN set.
    "model_led_sandbox": {
        "AGENT_STEERING_MODE": "advisory",
        "AGENT_STEERING_FREE_TURNS": "2",
        "AGENT_HUNT_DISCIPLINE_PROMPT": "true",
        "AGENT_SELF_CHALLENGE": "true",
        "AGENT_RECHECK_WEAK_NEGATIVES": "true",
        "AGENT_SETTLEMENT_BACKFILL": "false",
        "AGENT_STREAMING_FIRST_PASS": "false",
        "AGENT_HUNT_ENGINE": "false",
        "AGENT_CUSTOM_PROBE_MODE": "isolated",
        "AGENT_SANDBOX_SHELL": "true",
    },
}

# Deep assessment (larger budgets, specialist seeding, advisory steering for
# the run) is a product_agent flag, not an environment default, so presets
# that use it name the mode here. Flags match the model_led presets so a
# model_led vs deep comparison isolates the budget dimension.
# model_led plus budget settlement: isolates whether saving unsubmitted
# leads at budget end raises recall without adding false positives.
PRESETS["model_led_settle"] = {**PRESETS["model_led"], "AGENT_SETTLEMENT_BACKFILL": "true"}
# model_led plus first-pass testing while the crawl maps.
PRESETS["model_led_stream"] = {**PRESETS["model_led"], "AGENT_STREAMING_FIRST_PASS": "true"}
# model_led plus streaming first pass and the event-driven hunt engine. The
# engine's explorer workers need the probe sandbox, so pair it with sandbox.
PRESETS["model_led_hunt"] = {**PRESETS["model_led_sandbox"],
                             "AGENT_STREAMING_FIRST_PASS": "true", "AGENT_HUNT_ENGINE": "true"}

PRESETS["deep"] = dict(PRESETS["model_led"])
PRESETS["deep_sandbox"] = dict(PRESETS["model_led_sandbox"])
PRESET_ASSESSMENT_MODE: Dict[str, str] = {"deep": "deep", "deep_sandbox": "deep"}

COMPARE_FIELDS = ("passed", "true_positives", "verified_true_positives", "false_positives",
                  "false_negatives", "recall", "verified_recall", "precision",
                  "incomplete_or_error", "cost_usd", "duration_seconds")


def _wait_for_port(port: int, timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def _port_free(port: int) -> bool:
    with socket.socket() as sock:
        return sock.connect_ex(("127.0.0.1", port)) != 0


def build_plan(args: argparse.Namespace) -> List[dict]:
    """Return one step per (config, case); writes each config's manifest."""
    from local_harness.benchmark.class_lab_manifest import main as write_manifest

    plan = []
    classes = {c.strip() for c in (args.classes or "").split(",") if c.strip()}
    for config in args.configs:
        config_dir = (args.out_dir / config).resolve()
        config_dir.mkdir(parents=True, exist_ok=True)
        corpus_path = config_dir / "corpus.json"
        write_manifest(["--target", f"http://127.0.0.1:{args.port}", "--out", str(corpus_path)])
        corpus = json.loads(corpus_path.read_text())
        kept = [case for case in corpus["cases"] if not classes or case["bug_class"] in classes]
        corpus_path.write_text(json.dumps({**corpus, "cases": kept}, indent=2) + "\n")
        for case in kept:
            identities = config_dir / (case.get("identities") or "class_lab_identities.json")
            plan.append({"config": config, "case": case, "corpus": corpus_path,
                         "run_dir": (config_dir / case["run_dir"]).resolve(),
                         "identities": identities})
    return plan


def _agent_command(args: argparse.Namespace, step: dict) -> List[str]:
    case = step["case"]
    command = [sys.executable, "-m", "local_harness.product_agent",
               "--target", case["target"], "--scope", case.get("scope") or case["target"],
               "--organization-id", str(args.organization_id), "--user-id", str(args.user_id),
               "--identities", str(step["identities"])]
    for flag, value in (("--max-turns", args.max_turns), ("--max-iterations", args.max_iterations),
                        ("--price-limit-usd", args.price_limit_usd)):
        if value is not None:
            command += [flag, str(value)]
    if case["bug_class"] == "ssrf" and case["polarity"] == "positive":
        command.append("--require-oast")
    command += ["--assessment-mode", PRESET_ASSESSMENT_MODE.get(step["config"], "standard")]
    return command


def _lab_command(args: argparse.Namespace, step: dict) -> List[str]:
    case = step["case"]
    command = [sys.executable, "-m", "local_harness.benchmark.class_lab",
               "--class", case["bug_class"], "--polarity", case["polarity"],
               "--port", str(args.port)]
    if case["bug_class"] == "ssrf" and case["polarity"] == "positive" and args.callback_suffix:
        command += ["--callback-suffix", args.callback_suffix]
    return command


def run_step(args: argparse.Namespace, step: dict) -> dict:
    case = step["case"]
    run_dir: Path = step["run_dir"]
    if (run_dir / "findings.jsonl").exists():
        return {"id": case["id"], "config": step["config"], "status": "skipped_existing"}
    if case["bug_class"] == "ssrf" and case["polarity"] == "positive" and not args.callback_suffix:
        return {"id": case["id"], "config": step["config"], "status": "skipped_no_oast",
                "note": "SSRF positive needs --callback-suffix"}
    if not _port_free(args.port):
        raise RuntimeError(f"Port {args.port} is busy; stop the other lab first")
    run_dir.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, **PRESETS[step["config"]],
           "AEGIS_FINDINGS_SINK": str(run_dir / "findings.jsonl"),
           "PYTHONPATH": os.pathsep.join(filter(None, [str(HARNESS), os.environ.get("PYTHONPATH")]))}
    lab_log = open(run_dir / "lab.log", "w")
    lab = subprocess.Popen(_lab_command(args, step), cwd=HARNESS, env=env,
                           stdout=lab_log, stderr=subprocess.STDOUT)
    started = time.monotonic()
    try:
        if not _wait_for_port(args.port):
            return {"id": case["id"], "config": step["config"], "status": "lab_failed"}
        with open(run_dir / "agent.log", "w") as agent_log:
            agent = subprocess.run(_agent_command(args, step), cwd=HARNESS, env=env,
                                   stdout=agent_log, stderr=subprocess.STDOUT,
                                   timeout=args.case_timeout)
        status = "ran" if agent.returncode == 0 else f"agent_exit_{agent.returncode}"
    except subprocess.TimeoutExpired:
        status = "agent_timeout"
    finally:
        lab.terminate()
        try:
            lab.wait(timeout=10)
        except subprocess.TimeoutExpired:
            lab.kill()
        lab_log.close()
    return {"id": case["id"], "config": step["config"], "status": status,
            "seconds": round(time.monotonic() - started, 1)}


def compare(reports: Dict[str, dict]) -> dict:
    """Per-class deltas of each configuration against the first one."""
    names = list(reports)
    baseline = names[0]
    classes = sorted({c for r in reports.values() for c in r.get("by_class", {})})
    rows = {}
    for cls in classes:
        row = {}
        base = reports[baseline].get("by_class", {}).get(cls, {})
        for name in names:
            data = reports[name].get("by_class", {}).get(cls, {})
            row[name] = {field: data.get(field) for field in COMPARE_FIELDS}
            row[name]["pass"] = data.get("pass")
            if name != baseline:
                row[name]["delta"] = {
                    field: (round(data[field] - base[field], 4)
                            if isinstance(data.get(field), (int, float))
                            and isinstance(base.get(field), (int, float)) else None)
                    for field in ("verified_true_positives", "false_positives",
                                  "verified_recall", "precision", "cost_usd")
                }
        rows[cls] = row
    totals = {}
    for name in names:
        by_class = reports[name].get("by_class", {}).values()
        totals[name] = {
            "classes_passed": sum(bool(c.get("pass")) for c in by_class),
            "verified_true_positives": sum(c.get("verified_true_positives", 0) for c in by_class),
            "false_positives": sum(c.get("false_positives", 0) for c in by_class),
            "incomplete_or_error": sum(c.get("incomplete_or_error", 0) for c in by_class),
            "cost_usd": round(sum(float(c.get("cost_usd") or 0) for c in by_class), 4),
        }
    return {"baseline": baseline, "totals": totals, "by_class": rows}


def render(comparison: dict) -> str:
    names = list(comparison["totals"])
    lines = ["config".ljust(20) + "classes passed  verified TP  FP  incomplete  cost $"]
    for name in names:
        t = comparison["totals"][name]
        lines.append(f"{name:<20}{t['classes_passed']:>14}{t['verified_true_positives']:>13}"
                     f"{t['false_positives']:>4}{t['incomplete_or_error']:>12}{t['cost_usd']:>8}")
    lines.append("")
    lines.append("class".ljust(22) + "  ".join(f"{n[:14]:>14}" for n in names) + "   (verified TP / FP / pass)")
    for cls, row in comparison["by_class"].items():
        cells = []
        for name in names:
            r = row[name]
            cells.append(f"{r.get('verified_true_positives') or 0}/{r.get('false_positives') or 0}/"
                         f"{'Y' if r.get('pass') else 'n'}".rjust(14))
        lines.append(f"{cls:<22}" + "  ".join(cells))
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--configs", default="strict,model_led",
                        help=f"Comma-separated presets; first is the baseline. Known: {', '.join(PRESETS)}")
    parser.add_argument("--classes", default="", help="Comma-separated bug classes (default: all)")
    parser.add_argument("--organization-id", type=int)
    parser.add_argument("--user-id", type=int)
    parser.add_argument("--max-turns", type=int)
    parser.add_argument("--max-iterations", type=int)
    parser.add_argument("--price-limit-usd", type=float)
    parser.add_argument("--callback-suffix", help="Controlled OAST suffix for the SSRF positive")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--case-timeout", type=int, default=7800)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--score-only", action="store_true", help="Skip runs; score existing run dirs")
    args = parser.parse_args(argv)
    args.configs = [c.strip() for c in args.configs.split(",") if c.strip()]
    unknown = [c for c in args.configs if c not in PRESETS]
    if unknown:
        parser.error(f"Unknown config(s): {', '.join(unknown)}")
    if not args.dry_run and not args.score_only and (args.organization_id is None or args.user_id is None):
        parser.error("--organization-id and --user-id are required to run the agent")

    plan = build_plan(args)
    if args.dry_run:
        for step in plan:
            print(f"[{step['config']}] {step['case']['id']}: "
                  f"{' '.join(_lab_command(args, step))}  &&  {' '.join(_agent_command(args, step))}")
        return 0
    results = []
    if not args.score_only:
        for step in plan:
            outcome = run_step(args, step)
            results.append(outcome)
            print(json.dumps(outcome), flush=True)
    from local_harness.product_class_benchmark import score_corpus

    reports = {}
    for config in args.configs:
        corpus = (args.out_dir / config / "corpus.json").resolve()
        reports[config] = score_corpus(corpus)
        (args.out_dir / config / "report.json").write_text(json.dumps(reports[config], indent=2) + "\n")
    comparison = compare(reports)
    (args.out_dir / "comparison.json").write_text(
        json.dumps({"runs": results, **comparison}, indent=2) + "\n")
    print(render(comparison))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
