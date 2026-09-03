#!/usr/bin/env python3
"""
Aegis Vanguard preflight — is this box ready to run the agent for real?

`healthcheck.py` checks the external recon CLIs (subfinder/nuclei/…). This
checks the runtime the *new* capture→prove→document→score pipeline needs:
Python deps, a real browser for the crawl, an LLM key, the proof/OOB/Caido
config, and the guardrail posture that once blocked every tool call. It prints
each check and a READY / NOT-READY verdict; exit 0 when ready, 1 when a required
check fails.

    python3 doctor.py
"""

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

REQUIRED, RECOMMENDED, OPTIONAL = "required", "recommended", "optional"


def _pkg(mod: str):
    try:
        __import__(mod)
        return "ok", f"{mod} importable"
    except Exception as e:
        return "fail", f"{mod} missing — pip install -r requirements.txt ({e})"


def check_python_deps():
    out = []
    for mod, tier in [("anthropic", REQUIRED), ("httpx", RECOMMENDED),
                      ("playwright", REQUIRED), ("yaml", OPTIONAL)]:
        status, detail = _pkg(mod)
        # httpx is optional at runtime (curl fallback exists); downgrade its fail
        if mod == "httpx" and status == "fail":
            status, tier = "warn", RECOMMENDED
        out.append((f"pkg:{mod}", tier, status, detail))
    return out


def check_browser():
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return [("browser", REQUIRED, "fail",
                 "playwright package missing — pip install playwright")]
    try:
        with sync_playwright() as p:
            path = p.chromium.executable_path
        if path and os.path.exists(path):
            return [("browser", REQUIRED, "ok", f"chromium at {path}")]
        return [("browser", REQUIRED, "warn",
                 "chromium not installed — run `playwright install chromium`")]
    except Exception as e:
        return [("browser", REQUIRED, "warn",
                 f"could not verify chromium ({e}) — try `playwright install chromium`")]


def check_llm():
    if os.environ.get("ANTHROPIC_API_KEY"):
        return [("llm", REQUIRED, "ok", "ANTHROPIC_API_KEY set")]
    if os.environ.get("AEGIS_LLM_BACKEND", "").lower() == "litellm":
        return [("llm", REQUIRED, "ok", "litellm backend configured")]
    return [("llm", REQUIRED, "fail",
             "set ANTHROPIC_API_KEY (or AEGIS_LLM_BACKEND=litellm + AEGIS_MODEL)")]


def check_capability_modules():
    mods = ["agent.flag_oracle", "agent.finding_oracle", "agent.oob_oracle",
            "agent.http_session", "agent.authz_matrix", "agent.js_recon",
            "agent.fingerprint", "agent.caido", "agent.browser_crawl",
            "agent.scorecard"]
    try:
        for m in mods:
            __import__(m)
        return [("capabilities", REQUIRED, "ok", f"{len(mods)} capability modules import")]
    except Exception as e:
        return [("capabilities", REQUIRED, "fail", f"module import failed: {e}")]


def check_secrets_db():
    p = Path(__file__).parent / "data" / "secrets_patterns.json"
    if p.exists():
        return [("secrets_db", RECOMMENDED, "ok", f"{p.name} present")]
    return [("secrets_db", RECOMMENDED, "warn",
             "data/secrets_patterns.json missing — analyze_js secret leads disabled")]


def check_caido():
    api = os.environ.get("AEGIS_CAIDO_API")
    browser_proxy = os.environ.get("AEGIS_BROWSER_PROXY")
    if not (api or browser_proxy):
        return [("caido", OPTIONAL, "optional",
                 "Caido not configured — set AEGIS_BROWSER_PROXY + AEGIS_CAIDO_API to "
                 "capture the full browse surface (browser_crawl works without it too)")]
    detail = f"AEGIS_BROWSER_PROXY={browser_proxy or '-'} AEGIS_CAIDO_API={api or '-'}"
    if api:
        try:
            import urllib.request
            urllib.request.urlopen(api.replace("/graphql", "/"), timeout=3)
            return [("caido", OPTIONAL, "ok", f"Caido reachable ({detail})")]
        except Exception as e:
            return [("caido", OPTIONAL, "warn", f"Caido configured but not reachable: {e}")]
    return [("caido", OPTIONAL, "ok", detail)]


def check_guardrail_posture():
    # The original 30-block failure: guardrails/Praetorium reject internal/benchmark
    # targets. Surface it so lab runs use --no-guardrails --max-risk critical.
    return [("guardrails", RECOMMENDED, "warn",
             "guardrails + Aegis Praetorium block internal/benchmark hosts (the "
             "original all-blocked run). For a lab/benchmark target run with "
             "`--no-guardrails --max-risk critical`; keep them ON for real external "
             "engagements. Set AEGIS_EXPECTED_FLAG to grade benchmark runs.")]


def check_selftest():
    """Behavioral smoke test: run the unit suite against the *real* runtime.

    Unlike check_capability_modules (import-only), this exercises each new
    module's logic. In the Docker image httpx/playwright/anthropic are present,
    so tests that degrade gracefully in the dev sandbox run for real here. A
    failure is a required blocker — the box has the code but it does not behave.
    """
    import io
    import unittest

    tests_dir = Path(__file__).parent / "tests"
    if not tests_dir.exists():
        return [("selftest", REQUIRED, "fail",
                 f"{tests_dir} missing — tests/ not shipped into this image")]
    try:
        suite = unittest.TestLoader().discover(str(tests_dir), pattern="test_*.py")
        buf = io.StringIO()
        result = unittest.TextTestRunner(stream=buf, verbosity=0).run(suite)
    except Exception as e:  # discovery/import blew up
        return [("selftest", REQUIRED, "fail", f"suite failed to run: {e}")]
    ran = result.testsRun
    bad = len(result.failures) + len(result.errors)
    if result.wasSuccessful():
        return [("selftest", REQUIRED, "ok", f"{ran} unit tests passed")]
    return [("selftest", REQUIRED, "fail",
             f"{bad}/{ran} unit tests failed — new logic is broken in this runtime")]


ALL_CHECKS = [check_python_deps, check_browser, check_llm,
              check_capability_modules, check_secrets_db, check_caido,
              check_guardrail_posture]


def run_checks(selftest=False):
    rows = []
    for fn in ALL_CHECKS:
        rows.extend(fn())
    if selftest:
        rows.extend(check_selftest())
    return rows


def summarize(rows):
    blockers = [r for r in rows if r[1] == REQUIRED and r[2] == "fail"]
    warnings = [r for r in rows if r[2] == "warn"]
    return {"ready": not blockers,
            "blockers": [f"{r[0]}: {r[3]}" for r in blockers],
            "warnings": [f"{r[0]}: {r[3]}" for r in warnings]}


_ICON = {"ok": "✅", "warn": "⚠️ ", "fail": "❌", "optional": "•"}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="doctor", description="Aegis Vanguard preflight.")
    p.add_argument("--json", action="store_true", help="Machine-readable output.")
    p.add_argument("--selftest", action="store_true",
                   help="Also run the unit suite to behavior-smoke-test the new "
                        "logic in this runtime (a failure blocks readiness).")
    args = p.parse_args(argv)

    rows = run_checks(selftest=args.selftest)
    summary = summarize(rows)
    if args.json:
        print(json.dumps({"checks": [dict(zip(("name", "tier", "status", "detail"), r))
                                     for r in rows], **summary}, indent=2))
        return 0 if summary["ready"] else 1

    print("Aegis Vanguard preflight\n" + "=" * 60)
    for name, tier, status, detail in rows:
        print(f"  {_ICON.get(status, '?')} {name:<16} [{tier}] {detail}")
    print("=" * 60)
    if summary["ready"]:
        print("READY — required checks pass. Address ⚠️  warnings for full coverage.")
    else:
        print("NOT READY — fix these required checks:")
        for b in summary["blockers"]:
            print(f"  ❌ {b}")
    return 0 if summary["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
