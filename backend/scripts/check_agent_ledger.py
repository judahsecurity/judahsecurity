"""Read-only staging check for a saved Aegis agent run.

Usage:
  AEGIS_API_TOKEN=<token> python -m scripts.check_agent_ledger \
    --base-url https://staging.example.com --session-id <session> --wait 90

The token is read from the environment so it never appears in command arguments.
"""

from __future__ import annotations

import argparse
import json
import os
import time
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

TERMINAL = {"completed", "partial", "timeout", "cancelled", "error", "interrupted"}


def validate_ledger(report: dict, *, min_actions: int = 1,
                    require_terminal: bool = True) -> tuple[bool, list[str], dict]:
    """Check that a run has a useful, internally consistent work record."""
    errors: list[str] = []
    actions = report.get("actions") or []
    coverage = report.get("coverage") or {}
    status = str(report.get("status") or "")
    if not report.get("run_id"):
        errors.append("missing run_id")
    if not isinstance(actions, list):
        errors.append("actions is not a list")
        actions = []
    if len(actions) < min_actions:
        errors.append(f"only {len(actions)} actions; expected at least {min_actions}")
    if coverage.get("actions") != len(actions):
        errors.append("coverage action count differs from action list")
    if require_terminal and status not in TERMINAL:
        errors.append(f"run status is not terminal: {status or 'missing'}")
    if status in TERMINAL and any(item.get("status") == "running" for item in actions):
        errors.append("terminal run still has an open action")
    summary = {
        "run_id": report.get("run_id"),
        "status": status,
        "actions": len(actions),
        "model_calls": coverage.get("model_calls", 0),
        "test_actions": coverage.get("test_actions", 0),
        "published_findings": coverage.get("published_findings", 0),
        "hypotheses_by_state": coverage.get("hypotheses_by_state") or {},
    }
    return not errors, errors, summary


def fetch_ledger(base_url: str, session_id: str, token: str) -> dict:
    parsed = urlsplit(base_url)
    if parsed.scheme != "https" and not (parsed.scheme == "http" and
                                          parsed.hostname in ("localhost", "127.0.0.1")):
        raise ValueError("Use HTTPS for staging, or HTTP only for localhost")
    path = f"/api/v1/agent/conversations/{quote(session_id, safe='')}/ledger"
    request = Request(
        base_url.rstrip("/") + path,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
    )
    with urlopen(request, timeout=10) as response:  # noqa: S310 - operator-supplied staging URL
        return json.load(response)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--wait", type=float, default=0,
                        help="Seconds to poll for a terminal run; 0 checks once")
    parser.add_argument("--min-actions", type=int, default=1)
    args = parser.parse_args(argv)
    token = os.environ.get("AEGIS_API_TOKEN")
    if not token:
        parser.error("AEGIS_API_TOKEN is required")
    deadline = time.monotonic() + max(0, args.wait)
    while True:
        report = fetch_ledger(args.base_url, args.session_id, token)
        if report.get("status") in TERMINAL or time.monotonic() >= deadline:
            break
        time.sleep(5)
    ok, errors, summary = validate_ledger(
        report, min_actions=max(0, args.min_actions), require_terminal=True,
    )
    print(json.dumps({"ok": ok, "summary": summary, "errors": errors}, indent=2))
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
