"""Run the class lab against a baseline and a candidate checkout, then score both.

Both sides face the same lab apps (served from the candidate checkout), the
same model and the same budget. The candidate runs with its autonomy flags.
Cases run one at a time on port 8765, which the manifest and scorer expect.

  python -m local_harness.benchmark.compare_lab --baseline /path/to/old-checkout \
      --out runs/compare --database-url "$AEGIS_ASSESSMENT_DATABASE_URL" \
      --organization-id 1 --user-id 1

ANTHROPIC_API_KEY must be set in the environment; it is never passed as an
argument. Use a dedicated assessment database.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from .class_lab_manifest import build_identities, build_manifest

PORT = 8765
TARGET = f"http://127.0.0.1:{PORT}"
DEFAULT_CLASSES = ("sqli", "xss", "idor", "sqli_post_blind", "chain_leaked_key")
CANDIDATE_FLAGS = ("--autonomy", "--delegate-replay-approval")


def _env(tree: Path, run_dir: Path, database_url: str) -> dict:
    env = dict(os.environ)
    env.update({
        "PYTHONPATH": os.pathsep.join([str(tree / "backend"), str(tree / "harness"), str(tree)]),
        "AEGIS_ASSESSMENT_DATABASE_URL": database_url,
        "AEGIS_FINDINGS_SINK": str(run_dir / "findings.jsonl"),
        "AEGIS_EVIDENCE_DIR": str(run_dir / "evidence"),
    })
    env.setdefault("SECRET_KEY", "benchmark-only-secret-key-with-32-plus-characters")
    return env


def _baseline_has_class(tree: Path, bug_class: str) -> bool:
    source = tree / "harness" / "local_harness" / "benchmark" / "class_lab.py"
    return source.exists() and f'"{bug_class}"' in source.read_text()


def run_case(*, side: str, tree: Path, lab_tree: Path, out: Path, bug_class: str,
             polarity: str, flags: list[str], args) -> dict:
    name = f"{bug_class}-{polarity}"
    run_dir = out / side / "runs" / name
    run_dir.mkdir(parents=True, exist_ok=True)
    for stale in ("findings.jsonl", "product_assessment.json", "agent_ledger.json"):
        (run_dir / stale).unlink(missing_ok=True)
    identities = out / side / "class_lab_identities.json"
    identities.write_text(json.dumps(build_identities(TARGET), indent=2))
    lab = subprocess.Popen(
        [sys.executable, "-m", "local_harness.benchmark.class_lab", "--class", bug_class,
         "--polarity", polarity, "--port", str(PORT)],
        cwd=lab_tree / "harness", env=_env(lab_tree, run_dir, args.database_url),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(1.5)
    cmd = [
        sys.executable, "-m", "local_harness.product_agent", "--target", TARGET,
        "--scope", TARGET, "--organization-id", str(args.organization_id),
        "--user-id", str(args.user_id), "--identities", str(identities),
        "--max-turns", str(args.max_turns), "--max-iterations", str(args.max_iterations),
        "--price-limit-usd", str(args.price_limit_usd), *flags,
    ]
    started = time.time()
    try:
        with open(run_dir / "agent.log", "w") as log:
            code = subprocess.run(cmd, cwd=tree / "harness",
                                  env=_env(tree, run_dir, args.database_url),
                                  stdout=log, stderr=subprocess.STDOUT,
                                  timeout=args.case_timeout).returncode
    except subprocess.TimeoutExpired:
        code = "timeout"
    finally:
        lab.terminate()
        lab.wait(timeout=10)
    return {"side": side, "case": name, "exit": code, "seconds": round(time.time() - started)}


def write_corpus(out: Path, side: str, names: set[str]) -> Path:
    cases = [case for case in build_manifest(TARGET)["cases"] if case["id"] in names]
    path = out / side / "corpus.json"
    path.write_text(json.dumps({"cases": cases}, indent=2))
    return path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--baseline", type=Path, required=True, help="Checkout to compare against")
    parser.add_argument("--candidate", type=Path,
                        default=Path(__file__).resolve().parents[3])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--database-url", default=os.environ.get("AEGIS_ASSESSMENT_DATABASE_URL", ""))
    parser.add_argument("--organization-id", type=int, required=True)
    parser.add_argument("--user-id", type=int, required=True)
    parser.add_argument("--classes", nargs="*", default=list(DEFAULT_CLASSES))
    parser.add_argument("--max-turns", type=int, default=4)
    parser.add_argument("--max-iterations", type=int, default=30)
    parser.add_argument("--price-limit-usd", type=float, default=5.0)
    parser.add_argument("--case-timeout", type=int, default=5400)
    args = parser.parse_args(argv)
    if not os.environ.get("ANTHROPIC_API_KEY"):
        parser.error("ANTHROPIC_API_KEY is not set")
    if not args.database_url:
        parser.error("Pass --database-url or set AEGIS_ASSESSMENT_DATABASE_URL")
    out = args.out.resolve()
    runs: list[dict] = []
    done: dict[str, set[str]] = {"baseline": set(), "candidate": set()}
    for bug_class in args.classes:
        for polarity in ("positive", "negative"):
            sides = [("candidate", args.candidate.resolve(), list(CANDIDATE_FLAGS))]
            if _baseline_has_class(args.baseline, bug_class):
                sides.insert(0, ("baseline", args.baseline.resolve(), []))
            for side, tree, flags in sides:
                row = run_case(side=side, tree=tree, lab_tree=args.candidate.resolve(), out=out,
                               bug_class=bug_class, polarity=polarity, flags=flags, args=args)
                runs.append(row)
                done[side].add(row["case"])
                print(json.dumps(row), flush=True)
    (out / "runs.json").write_text(json.dumps(runs, indent=2))
    for side, names in done.items():
        if not names:
            continue
        corpus = write_corpus(out, side, names)
        subprocess.run(
            [sys.executable, "-m", "local_harness.product_class_benchmark", str(corpus),
             "--out", str(out / side / "report.json")],
            cwd=args.candidate.resolve() / "harness",
            env=_env(args.candidate.resolve(), out / side, args.database_url),
            stdout=subprocess.DEVNULL,
        )
    print(f"Reports: {out}/baseline/report.json and {out}/candidate/report.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
