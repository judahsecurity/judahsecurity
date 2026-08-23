#!/usr/bin/env python3
"""
Offline stub scanner used by the harness test-suite.

Mimics ``aegis-vanguard/run_pentest.py`` just enough for the harness: it accepts
``--target``/``--scope`` (plus any extra flags), then writes a fixed set of
findings to the ``AEGIS_FINDINGS_SINK`` JSONL file exactly as the real
``ASMBridge`` would. No API key, network, or security tools required.
"""

import argparse
import json
import os
from datetime import datetime, timezone


def _finding(**kwargs) -> dict:
    kwargs["timestamp"] = datetime.now(timezone.utc).isoformat()
    return kwargs


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", "-u", required=True)
    parser.add_argument("--scope", "-s")
    # Swallow any other flags the harness might pass through.
    args, _unknown = parser.parse_known_args()

    sink = os.environ.get("AEGIS_FINDINGS_SINK")
    if not sink:
        print("no sink configured")
        return 0

    host = args.target.split("://")[-1].split("/")[0]
    findings = [
        _finding(
            type="subdomain", source="subfinder", target=host, host=host,
            title=f"Subdomain: {host}", severity="info", confidence="high",
        ),
        _finding(
            type="vulnerability", source="aegis-vanguard-poc", target=host, host=host,
            url=f"{args.target}/rest/user/login",
            title="SQL Injection in login", severity="critical", confidence="confirmed",
            tags=["confirmed", "poc", "sqli"],
            raw_data={"poc": {"endpoint": f"{args.target}/rest/user/login"}},
        ),
        _finding(
            type="vulnerability", source="test_dom_xss", target=host, host=host,
            url=f"{args.target}/search?q=test",
            title="Reflected XSS in search", severity="high", confidence="high",
            tags=["xss"],
        ),
        _finding(
            type="vulnerability", source="nuclei", target=host, host=host,
            url=f"{args.target}/server-status",
            title="Information disclosure: server-status exposed",
            severity="low", confidence="high", tags=["info-disclosure"],
        ),
    ]

    # Flag-capture (CTF/XBEN) mode: embed the captured flag in a PoC finding so
    # the flag judge can find it.
    flag = os.environ.get("AEGIS_STUB_FLAG")
    if flag:
        findings.append(_finding(
            type="vulnerability", source="aegis-vanguard-poc", target=host, host=host,
            url=f"{args.target}/flag",
            title="IDOR leading to flag disclosure", severity="high",
            confidence="confirmed", tags=["confirmed", "poc", "idor"],
            description=f"Extracted flag via IDOR: {flag}",
            raw_data={"poc": {"endpoint": f"{args.target}/flag",
                              "response_snippet": f"200 OK\n\n{flag}\n"}},
        ))

    os.makedirs(os.path.dirname(os.path.abspath(sink)), exist_ok=True)
    with open(sink, "a", encoding="utf-8") as fh:
        for f in findings:
            fh.write(json.dumps(f) + "\n")

    traces_dir = os.environ.get("AEGIS_TRACES_DIR")
    if traces_dir:
        os.makedirs(traces_dir, exist_ok=True)
        with open(os.path.join(traces_dir, "trace_stub.json"), "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "summary": {
                        "session_id": "stub",
                        "model": "claude-sonnet-4-6",
                        "tokens": {"input": 100000, "output": 5000, "total": 105000},
                        "estimated_cost_usd": 0.375,
                    },
                    "spans": [],
                },
                fh,
            )

    print(f"stub scan complete for {args.target}: {len(findings)} findings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
