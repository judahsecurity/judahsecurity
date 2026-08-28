"""
Measure the Vanguard XSS solver's real recall across the XBEN xss challenges —
with no LLM and no API key. Stands each challenge up in Docker, points the
standalone solver (aegis-vanguard/agent/xss_bot_solver.py) at its reflecting
endpoint, and tallies flag captures.

This isolates one capability (the 23 xss-only challenges, ~22% of the corpus)
so you get a measured number cheaply before spending budget on the full scanner
run. Endpoint / param / method are discovered from each challenge's app.py.

Usage:
    # discovery only (offline, no Docker) — see what would be probed:
    python -m local_harness.benchmark.xss_recall --corpus /tmp/xben

    # live: stand up each xss challenge, solve, tear down, tally:
    python -m local_harness.benchmark.xss_recall --corpus /tmp/xben --run
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional

from local_harness.benchmark.compose_utils import container_port_of
from local_harness.benchmark.targets import TargetManager

# aegis-vanguard/agent/xss_bot_solver.py, relative to the repo root.
def _default_solver() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        cand = parent / "aegis-vanguard" / "agent" / "xss_bot_solver.py"
        if cand.exists():
            return cand
    return Path("aegis-vanguard/agent/xss_bot_solver.py")


_ROUTE = re.compile(r"@app\.route\(\s*['\"]([^'\"]+)['\"]\s*(?:,\s*methods\s*=\s*\[([^\]]*)\])?\s*\)")
_PARAM = re.compile(r"request\.(form|args)\.get\(\s*['\"]([^'\"]+)['\"]")


def discover_targets(app_text: str) -> List[Dict[str, str]]:
    """Reflecting (path, param, method) targets from a Flask app.py.

    Splits the file per route decorator and reads the first request.form/args
    parameter in each handler. Skips the '/' index route.
    """
    targets: List[Dict[str, str]] = []
    parts = re.split(r"(@app\.route\([^)]*\))", app_text)
    for i in range(1, len(parts), 2):
        decl = parts[i]
        body = parts[i + 1] if i + 1 < len(parts) else ""
        rm = _ROUTE.search(decl)
        if not rm:
            continue
        path, methods = rm.group(1), (rm.group(2) or "")
        if path == "/":
            continue
        pm = _PARAM.search(body)
        if not pm:
            continue
        src, param = pm.group(1), pm.group(2)
        method = "POST" if (src == "form" or "POST" in methods.upper()) else "GET"
        targets.append({"path": path, "param": param, "method": method})
    return targets


def _app_py(challenge_dir: Path) -> Optional[Path]:
    for cand in (challenge_dir / "src" / "app.py", challenge_dir / "app.py"):
        if cand.exists():
            return cand
    return None


def _xss_challenges(corpus_root: Path, only: Optional[List[str]]) -> List[str]:
    out = []
    for d in sorted((corpus_root / "benchmarks").iterdir()):
        bj = d / "benchmark.json"
        if not bj.exists():
            continue
        if only and d.name not in only:
            continue
        try:
            tags = json.loads(bj.read_text(encoding="utf-8")).get("tags", [])
        except json.JSONDecodeError:
            continue
        if "xss" in tags:
            out.append(d.name)
    return out


def _solve_live(solver: Path, url: str, param: str, method: str, timeout: int = 120) -> Dict:
    try:
        p = subprocess.run(
            [sys.executable, str(solver), "--url", url, "--param", param, "--method", method],
            capture_output=True, text=True, timeout=timeout,
        )
        out = (p.stdout or "").strip()
        return json.loads(out.splitlines()[-1]) if out else {"solved": False, "error": "no output"}
    except (subprocess.SubprocessError, json.JSONDecodeError, OSError) as exc:
        return {"solved": False, "error": str(exc)}


def run(corpus_root: Path, only: Optional[List[str]] = None, live: bool = False,
        solver: Optional[Path] = None) -> Dict:
    solver = solver or _default_solver()
    tm = TargetManager()
    names = _xss_challenges(corpus_root, only)
    results: List[Dict] = []

    for name in names:
        d = corpus_root / "benchmarks" / name
        app = _app_py(d)
        targets = discover_targets(app.read_text(encoding="utf-8", errors="ignore")) if app else []
        row: Dict = {"name": name, "targets": targets, "solved": False}

        if not targets:
            row["status"] = "no-endpoint-discovered"
            results.append(row)
            continue
        if not live:
            row["status"] = "discovered"
            results.append(row)
            continue

        compose = d / "docker-compose.yml"
        cport = container_port_of(compose, default=80)
        spec = {"setup": {"up": f"make -C {d} run", "down": f"make -C {d} stop",
                          "compose_file": str(compose), "container_port": cport,
                          "ready_timeout": 180, "up_timeout": 900}}
        res = tm.setup(spec)
        try:
            if not res.ok:
                row["status"] = f"setup-failed: {res.detail}"
            else:
                base = res.target_url.rstrip("/")
                for t in targets:
                    url = base + t["path"]
                    r = _solve_live(solver, url, t["param"], t["method"])
                    if r.get("solved"):
                        row.update(solved=True, status="solved", flag=r.get("flag"),
                                   payload=r.get("payload"), hit=t)
                        break
                else:
                    row["status"] = "unsolved"
        finally:
            tm.teardown(spec)
        results.append(row)

    solved = sum(1 for r in results if r.get("solved"))
    return {"total": len(results), "solved": solved,
            "recall": round(solved / len(results), 3) if results else 0.0,
            "results": results}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="local_harness.benchmark.xss_recall",
        description="Measure the XSS solver's recall across XBEN xss challenges.",
    )
    p.add_argument("--corpus", type=Path, required=True, help="Clone of validation-benchmarks")
    p.add_argument("--repos", help="Comma-separated subset of challenge names")
    p.add_argument("--run", action="store_true", help="Stand up + solve live (needs Docker)")
    p.add_argument("--solver", type=Path, default=None, help="Path to xss_bot_solver.py")
    p.add_argument("--out", type=Path, default=None, help="Write JSON report here")
    a = p.parse_args(argv)

    if not (a.corpus / "benchmarks").is_dir():
        print(f"corpus not found: {a.corpus}/benchmarks — clone validation-benchmarks first")
        return 1
    only = [s for s in a.repos.split(",") if s] if a.repos else None
    report = run(a.corpus, only=only, live=a.run, solver=a.solver)

    mode = "live" if a.run else "discovery-only"
    print(f"\nXSS recall — {report['total']} xss challenge(s), mode={mode}:")
    for r in report["results"]:
        mark = "SOLVED" if r.get("solved") else r.get("status", "?")
        tg = ",".join(f"{t['method']} {t['path']}({t['param']})" for t in r.get("targets", [])) or "—"
        line = f"  {r['name']:<14} {mark:<24} {tg}"
        if r.get("flag"):
            line += f"  {r['flag']}"
        print(line)
    if a.run:
        print(f"\n  RECALL: {report['solved']}/{report['total']} = {report['recall']*100:.0f}%")

    if a.out:
        a.out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"  report → {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
