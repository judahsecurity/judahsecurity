"""Diagnose the assessment-Caido readback used for agent traffic review.

Run it after wiring the Caido history source to get a clear pass/fail instead of
a silent empty result:

    python -m app.services.agent.caido_doctor
    python -m app.services.agent.caido_doctor --url http://localhost:8083/graphql --token "$TOKEN"

It checks, in order: configuration, endpoint reachability + that
``requestsByOffset`` exists (unauthenticated introspection), token presence and
expiry (the local session token lasts ~7 days), and one authenticated data call.
It never mutates anything — only a schema introspection and a bounded read.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time

INTROSPECT = ('{"query":"query{__schema{queryType{fields{name}}}}"}')
DATA_QUERY = (
    '{"query":"query{requestsByOffset(limit:1,offset:0)'
    '{edges{node{host port path query method isTls}}}}"}'
)


def token_expiry(token: str) -> dict:
    """Decode a JWT's exp claim without verifying it. Best-effort only."""
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload_b64))
        exp = claims.get("exp")
        if not isinstance(exp, (int, float)):
            return {"known": False}
        remaining = int(exp - time.time())
        return {"known": True, "expired": remaining <= 0,
                "seconds_left": remaining, "days_left": round(remaining / 86400, 1)}
    except Exception:
        return {"known": False}


def _post(url: str, body: str, token: str):
    import httpx

    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    with httpx.Client(timeout=15.0, trust_env=False) as client:
        response = client.post(url, content=body, headers=headers)
    return response.status_code, response.json()


def diagnose(url: str, token: str, *, post=_post) -> dict:
    """Return a structured report; `post` is injected for testing."""
    from app.services.agent.caido_history import assessment_caido_binding, graphql_error_reason

    report: dict = {"endpoint": url, "binding": assessment_caido_binding(), "checks": []}

    def check(name, ok, detail=""):
        report["checks"].append({"name": name, "ok": bool(ok), "detail": detail})
        return ok

    if not url:
        check("configured", False, "AEGIS_ASSESSMENT_CAIDO_GRAPHQL_URL is unset")
        report["ok"] = False
        return report
    check("configured", True, url)

    try:
        status, payload = post(url, INTROSPECT, "")
    except Exception as exc:
        check("reachable", False, f"{type(exc).__name__}: {str(exc)[:120]}")
        report["ok"] = False
        return report
    fields = (((payload or {}).get("data") or {}).get("__schema") or {}).get("queryType") or {}
    names = {f.get("name") for f in (fields.get("fields") or []) if isinstance(f, dict)}
    check("reachable", status == 200, f"HTTP {status}")
    check("requestsByOffset_present", "requestsByOffset" in names,
          "schema exposes requestsByOffset" if "requestsByOffset" in names
          else "field missing — Caido schema may have changed this release")

    if not token:
        check("token_present", False, "AEGIS_ASSESSMENT_CAIDO_TOKEN is unset")
        report["ok"] = False
        return report
    exp = token_expiry(token)
    if exp.get("known"):
        check("token_unexpired", not exp["expired"],
              f"{exp['days_left']} day(s) left" if not exp["expired"] else "token expired")
    else:
        check("token_unexpired", True, "expiry unknown (could not decode JWT)")

    try:
        status, payload = post(url, DATA_QUERY, token)
    except Exception as exc:
        check("data_call", False, f"{type(exc).__name__}: {str(exc)[:120]}")
        report["ok"] = False
        return report
    reason = graphql_error_reason(payload)
    if reason == "caido_auth_invalid_or_expired":
        check("data_call", False, "INVALID_TOKEN — wrong token type (use the LOCAL "
              "session token from the UI's localStorage, not a Caido Cloud PAT) or expired")
    elif reason:
        check("data_call", False, reason)
    else:
        edges = ((((payload or {}).get("data") or {}).get("requestsByOffset") or {}).get("edges"))
        n = len(edges) if isinstance(edges, list) else 0
        check("data_call", True, f"authorized; {n} record(s) in this sample "
              "(0 is fine if the project has no in-scope traffic yet)")

    report["ok"] = all(c["ok"] for c in report["checks"])
    return report


def format_report(report: dict) -> str:
    lines = [f"assessment-Caido readback: {'PASS' if report.get('ok') else 'FAIL'}",
             f"  endpoint: {report.get('endpoint') or '(unset)'}",
             f"  binding:  {report.get('binding', {}).get('isolation', 'unknown')}"
             f" (project={report.get('binding', {}).get('project') or '-'})"]
    for c in report["checks"]:
        lines.append(f"  [{'OK ' if c['ok'] else 'XX '}] {c['name']}: {c['detail']}")
    if not report.get("ok"):
        lines.append("  -> see docs/PROWL_CAIDO_CAPTURE.md (IDOR leads / Caido history)")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Diagnose the assessment-Caido readback")
    parser.add_argument("--url", default=os.environ.get("AEGIS_ASSESSMENT_CAIDO_GRAPHQL_URL", "").strip())
    parser.add_argument("--token", default=os.environ.get("AEGIS_ASSESSMENT_CAIDO_TOKEN", "").strip())
    args = parser.parse_args(argv)
    report = diagnose(args.url.rstrip("/"), args.token)
    print(format_report(report))
    return 0 if report.get("ok") else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
