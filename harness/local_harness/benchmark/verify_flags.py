"""
Verify that XBEN ground-truth flags match what each challenge image bakes.

The flag-capture judge (``judge.py``) matches flags by **exact substring**. If a
ground-truth flag is wrong, the scanner can capture the real flag and still be
scored *unsolved* — a silent 0%. This module catches that before a costly run.

Two modes:

* **offline** (default, no Docker): for each challenge, resolve every flag the
  build *could* bake — the ``.env`` ``FLAG=`` override, the ``FLAG{sha256(NAME)}``
  default from the corpus ``common.mk``, and any ``FLAG{…}`` / ``flag{…}`` token
  literally present in ``docker-compose.yml`` / ``Dockerfile`` / ``benchmark.json``
  — and confirm the ground-truth flag matches at least one of them. A flag that
  matches *no* source is almost certainly wrong.

* **live** (``--live``, needs Docker): for challenges that are already up, grep
  the running container's env and filesystem for the ground-truth flag. This is
  authoritative — it proves the exact string the app serves.

Usage:
    # offline sanity check of a whole corpus (exit 2 if any flag matches nothing)
    python -m local_harness.benchmark.verify_flags \
        --ground-truth local_harness/benchmark/ground_truth/XBEN.json \
        --corpus /tmp/xben

    # rewrite ground truth to the resolved authoritative flag
    python -m local_harness.benchmark.verify_flags \
        --ground-truth .../XBEN.json --corpus /tmp/xben --fix --out .../XBEN.fixed.json

    # live confirmation against already-running challenges
    python -m local_harness.benchmark.verify_flags \
        --ground-truth .../XBEN_SMOKE.json --live --repos XBEN-071-24
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional

from local_harness.benchmark.targets import TargetManager
from local_harness.benchmark.xben_import import compute_flag

# Matches both XBEN flag styles: FLAG{<64 hex>} and flag{<uuid>}, plus any
# FLAG{...}/flag{...} literal a build file might carry. Case is preserved.
FLAG_TOKEN = re.compile(r"[Ff][Ll][Aa][Gg]\{[^}\s]{1,120}\}")


def _tokens_in(text: str) -> List[str]:
    """Every distinct FLAG{…}/flag{…} token in some text, order-preserving."""
    seen: Dict[str, None] = {}
    for m in FLAG_TOKEN.findall(text or ""):
        seen.setdefault(m, None)
    return list(seen)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _env_flag(challenge_dir: Path) -> Optional[str]:
    """The challenge's ``.env`` ``FLAG=`` value, if any (importer semantics)."""
    for line in _read(challenge_dir / ".env").splitlines():
        line = line.strip()
        if line.startswith("FLAG=") and len(line) > 5:
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    return None


def candidate_flags(challenge_dir: Path, name: str) -> Dict[str, str]:
    """Resolve every flag this challenge's build could bake, keyed by source.

    Ordered by corpus authority: an explicit ``.env`` override wins, then the
    deterministic ``common.mk`` default, then any literal token in the build
    files (useful when a challenge hard-codes its flag).
    """
    out: Dict[str, str] = {}
    env = _env_flag(challenge_dir)
    if env:
        out["env"] = env
    out["sha256"] = compute_flag(name)
    for fname in ("docker-compose.yml", "docker-compose.yaml", "Dockerfile", "benchmark.json"):
        for tok in _tokens_in(_read(challenge_dir / fname)):
            out.setdefault(f"file:{fname}", tok)
    return out


def resolve_flag(challenge_dir: Path, name: str) -> str:
    """The single authoritative flag: ``.env`` override else the sha256 default."""
    return _env_flag(challenge_dir) or compute_flag(name)


# --- Live extraction (best-effort; needs Docker) --------------------------

def _run(cmd: List[str], timeout: int = 60) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (p.stdout or "") + (p.stderr or "")
    except (OSError, subprocess.SubprocessError):
        return ""


def live_tokens(compose_file: str) -> List[str]:
    """Grep every FLAG{…} token from the running challenge's containers.

    Best-effort: reads each container's baked env and scans its filesystem.
    Requires the challenge to already be up (e.g. via the benchmark ``--setup``).
    """
    if not compose_file:
        return []
    ps = _run(["docker", "compose", "-f", compose_file, "ps", "-q"])
    ids = [line.strip() for line in ps.splitlines() if re.fullmatch(r"[0-9a-f]{12,64}", line.strip())]
    tokens: Dict[str, None] = {}
    for cid in ids:
        env_json = _run(["docker", "inspect", "--format", "{{json .Config.Env}}", cid])
        for tok in _tokens_in(env_json):
            tokens.setdefault(tok, None)
        # Scan a bounded set of common flag locations rather than all of /.
        grep = _run([
            "docker", "exec", cid, "sh", "-c",
            "grep -rhoaE '[Ff][Ll][Aa][Gg]\\{[^}]{1,120}\\}' "
            "/ --include='*' 2>/dev/null | head -n 50",
        ], timeout=90)
        for tok in _tokens_in(grep):
            tokens.setdefault(tok, None)
    return list(tokens)


# --- Verification ---------------------------------------------------------

def verify_corpus(
    ground_truth: Dict[str, dict],
    corpus_root: Optional[Path],
    only: Optional[List[str]] = None,
    live: bool = False,
    setup: bool = False,
    target_manager: Optional[TargetManager] = None,
) -> List[dict]:
    """Check each challenge's ground-truth flag against resolvable sources.

    With ``live=True``, read the flag the running container actually serves.
    With ``setup=True`` as well, bring each challenge up (and tear it down)
    around the live read, so no manual docker up/down is needed.
    """
    tm = target_manager or (TargetManager() if (live and setup) else None)
    results: List[dict] = []
    for name, spec in ground_truth.items():
        if name.startswith("_") or not isinstance(spec, dict):
            continue
        if only and name not in only:
            continue
        gt_flag = spec.get("flag")
        if not gt_flag:
            # flag_regex challenges aren't exact-match; nothing to verify here.
            if spec.get("flag_regex"):
                results.append({"name": name, "status": "SKIP_REGEX", "gt_flag": None})
            continue

        challenge_dir = corpus_root / "benchmarks" / name if corpus_root else None
        if challenge_dir and not challenge_dir.is_dir() and corpus_root:
            alt = corpus_root / name
            challenge_dir = alt if alt.is_dir() else challenge_dir

        candidates: Dict[str, str] = {}
        if challenge_dir and challenge_dir.is_dir():
            candidates = candidate_flags(challenge_dir, name)
        elif corpus_root:
            results.append({"name": name, "status": "NO_DIR", "gt_flag": gt_flag,
                            "detail": f"challenge dir not found under {corpus_root}"})
            continue

        matched = [src for src, f in candidates.items() if f == gt_flag]

        live_found: Optional[List[str]] = None
        if live:
            compose = (spec.get("setup") or {}).get("compose_file", "")
            if tm is not None:
                res = tm.setup(spec)
                try:
                    live_found = live_tokens(compose) if res.ok else []
                finally:
                    tm.teardown(spec)
                if not res.ok:
                    results.append({"name": name, "status": "SETUP_FAILED",
                                    "gt_flag": gt_flag, "detail": res.detail})
                    continue
            else:
                live_found = live_tokens(compose)

        if live and live_found is not None:
            status = "LIVE_OK" if gt_flag in live_found else "LIVE_MISMATCH"
        elif not candidates:
            status = "NO_SOURCE"
        elif matched:
            status = "OK"
        else:
            status = "MISMATCH"

        results.append({
            "name": name,
            "status": status,
            "gt_flag": gt_flag,
            "matched_source": matched[0] if matched else None,
            "candidates": candidates,
            "resolved": resolve_flag(challenge_dir, name) if challenge_dir and challenge_dir.is_dir() else None,
            "live_found": live_found,
        })
    return results


_BAD = {"MISMATCH", "LIVE_MISMATCH", "NO_SOURCE", "NO_DIR", "SETUP_FAILED"}


def _print_report(results: List[dict]) -> None:
    width = max((len(r["name"]) for r in results), default=10)
    for r in results:
        line = f"  {r['name']:<{width}}  {r['status']}"
        if r["status"] == "OK":
            line += f"  (matches {r['matched_source']})"
        elif r["status"] == "MISMATCH":
            srcs = ", ".join(f"{k}={v}" for k, v in (r.get("candidates") or {}).items())
            line += f"\n      gt={r['gt_flag']}\n      sources: {srcs or '(none)'}"
        elif r["status"] == "LIVE_MISMATCH":
            line += f"\n      gt={r['gt_flag']} not found in running container"
            if r.get("live_found"):
                line += f"; container has: {', '.join(r['live_found'][:3])}"
        elif r["status"] in ("NO_DIR", "NO_SOURCE", "SETUP_FAILED"):
            line += f"  {r.get('detail', '')}"
        print(line)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="local_harness.benchmark.verify_flags",
        description="Verify XBEN ground-truth flags match what each image bakes.",
    )
    parser.add_argument("--ground-truth", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, default=None,
                        help="Local clone of validation-benchmarks (for offline source resolution)")
    parser.add_argument("--repos", help="Comma-separated subset of challenge names")
    parser.add_argument("--live", action="store_true",
                        help="Confirm against running containers (needs Docker)")
    parser.add_argument("--setup", action="store_true",
                        help="With --live, docker up/down each challenge around the read")
    parser.add_argument("--fix", action="store_true",
                        help="Rewrite ground truth to the resolved authoritative flag")
    parser.add_argument("--out", type=Path, default=None, help="Output path for --fix")
    args = parser.parse_args(argv)

    if not args.ground_truth.is_file():
        print(f"ground truth not found: {args.ground_truth}")
        return 1
    if args.live and args.corpus is None and not args.ground_truth:
        pass  # live needs only the compose_file in the ground truth

    gt = json.loads(args.ground_truth.read_text(encoding="utf-8"))
    only = [s for s in args.repos.split(",") if s] if args.repos else None
    corpus = args.corpus.resolve() if args.corpus else None

    if args.setup and not args.live:
        print("--setup only applies with --live; ignoring.")
    results = verify_corpus(gt, corpus, only=only, live=args.live,
                            setup=args.setup and args.live)
    if not results:
        print("no exact-flag challenges to verify (all flag_regex, or empty subset).")
        return 0

    mode = ("live+setup" if args.setup and args.live
            else "live" if args.live else "offline")
    print(f"\nFlag verification — {len(results)} challenge(s), mode={mode}:")
    _print_report(results)

    bad = [r for r in results if r["status"] in _BAD]
    ok = sum(1 for r in results if r["status"] in ("OK", "LIVE_OK"))
    print(f"\n  {ok} ok, {len(bad)} suspect, {len(results)} total")

    if args.fix:
        out = args.out or args.ground_truth.with_suffix(".fixed.json")
        fixed = 0
        for r in results:
            # A live run is authoritative: if the container serves exactly one
            # flag token and it differs from ground truth, adopt it. Otherwise
            # fall back to the offline-resolved (.env override / sha256) flag.
            live = r.get("live_found") or []
            correction = live[0] if len(live) == 1 else r.get("resolved")
            if correction and gt.get(r["name"], {}).get("flag") != correction:
                gt[r["name"]]["flag"] = correction
                fixed += 1
        out.write_text(json.dumps(gt, indent=2), encoding="utf-8")
        print(f"  --fix: wrote {fixed} corrected flag(s) → {out}")

    if bad:
        print(f"\n[gate] {len(bad)} flag(s) match no known source — fix before benchmarking → exit 2")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
