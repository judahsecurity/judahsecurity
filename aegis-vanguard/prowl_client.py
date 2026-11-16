#!/usr/bin/env python3
"""Drive Prowl (the built-in Aegis agent, backend/app/services/agent) from Vanguard.

Prowl owns the scoped browser, OOB callbacks, deterministic proof probes, the
independent verifier and the publication gate. Vanguard skills use this CLI to
hand live work to Prowl instead of re-implementing those tools with curl.

Environment (never hardcode secrets):
    AEGIS_API_URL    platform origin, e.g. http://localhost:8000 (``/api/v1`` optional)
    AEGIS_API_TOKEN  a user JWT access token (POST /api/v1/auth/login). The agent
                     routes do not accept ingest API keys (tfasm_...).

Commands:
    status                                   GET  /agent/status
    classes [--resolve NAME]                 local data/vuln_classes.json (no API exposes it)
    asset --host HOST                        GET  /assets/?search=HOST&in_scope=true
    start --target ORIGIN --scope-file F     POST /agent/query (mode=agent)
          [--playbook ID] [--objective TXT] [--policy-file P] [--oob]
          [--asset-id N --executor] [--run-dir D]
    poll --session S [--wait] [--run-dir D]  GET  /agent/conversations/S and /ledger
    findings --asset-id N                    GET  /vulnerabilities/?asset_id=N&detected_by=agent_family
    verify --run-dir D --finding-id ID --target ORIGIN --scope-file F
                                             POST /agent/query playbook=finding_validation
    verdict --run-dir D --finding-id ID      ledger -> confirmed | refuted | improve | pending
    stop --session S                         POST /agent/sessions/S/stop
    tool --scope-file F --name execute_httpx --args "..."
                                             POST /mcp/call (recon tools only, scope-checked)

API gaps (see docs/skills/README.md): there is no endpoint that accepts an
external candidate into Prowl's verifier directly, and POST /prowl/findings
only takes service-produced paired hunter/verifier proofs. ``verify`` therefore
asks Prowl to reproduce the candidate from scratch with its own tools.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CLASSES_PATH = ROOT / "data" / "vuln_classes.json"
sys.path.insert(0, str(ROOT / ".claude" / "skills" / "_lib"))
import scope as scope_lib  # noqa: E402

RECON_TOOLS = frozenset({
    "execute_subfinder", "execute_dnsx", "execute_httpx", "execute_katana", "execute_waybackurls",
})
_SECRET_KEYS = re.compile(r"(authorization|cookie|set-cookie|token|password|secret|api[_-]?key|session)", re.I)
_SECRET_LINE = re.compile(r"(?im)^(\s*(?:authorization|cookie|set-cookie|x-api-key)\s*:\s*).+$")
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")


class ProwlError(RuntimeError):
    pass


# ---------------------------------------------------------------- HTTP

def _base_url() -> str:
    url = os.environ.get("AEGIS_API_URL", "").rstrip("/")
    if not url:
        raise ProwlError("AEGIS_API_URL is not set")
    return url if url.endswith("/api/v1") else url + "/api/v1"


def request(method: str, path: str, body: dict | None = None, *, auth: bool = True,
            params: dict | None = None, timeout: float = 60.0) -> dict | list:
    url = _base_url() + path
    if params:
        url += "?" + urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
    headers = {"Accept": "application/json"}
    if auth:
        token = os.environ.get("AEGIS_API_TOKEN", "")
        if not token:
            raise ProwlError("AEGIS_API_TOKEN is not set (user JWT access token)")
        headers["Authorization"] = f"Bearer {token}"
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - operator-set URL
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read()[:500].decode("utf-8", "replace")
        raise ProwlError(f"{method} {path} -> {exc.code}: {detail}") from None
    except urllib.error.URLError as exc:
        raise ProwlError(f"{method} {path} failed: {exc.reason}") from None
    return json.loads(raw) if raw else {}


# ---------------------------------------------------------------- helpers

def load_classes() -> dict:
    return json.loads(CLASSES_PATH.read_text())


def resolve_class(name: str, data: dict | None = None) -> str | None:
    data = data or load_classes()
    key = re.sub(r"[\s-]+", "_", (name or "").strip().lower())
    if key in data["classes"]:
        return key
    return data["vanguard_aliases"].get(key) or data["coverage_to_class"].get(key)


def origin_of(target: str) -> str:
    parts = urllib.parse.urlsplit(target if "://" in target else "https://" + target)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ProwlError(f"not an HTTP(S) target: {target}")
    return f"{parts.scheme}://{parts.netloc}"


def require_scope(scope_file: str, *targets: str) -> None:
    scope = scope_lib.load(scope_file)
    out = [t for t in targets if not scope_lib.in_scope(scope, t)]
    if out:
        raise ProwlError(f"out of scope per {scope_file}: {', '.join(out)}")


def redact(value):
    """Strip credential material before it leaves the run dir."""
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if _SECRET_KEYS.search(str(k)) else redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return _BEARER.sub(r"\1 [REDACTED]", _SECRET_LINE.sub(r"\1[REDACTED]", value))
    return value


def assessment_policy(args) -> dict:
    """Operator grants for /agent/query (AgentAssessmentPolicy). Paths only, no secrets."""
    policy: dict = {}
    if getattr(args, "policy_file", None):
        policy = json.loads(Path(args.policy_file).read_text())
        if not isinstance(policy, dict):
            raise ProwlError("--policy-file must hold a JSON object")
    if getattr(args, "oob", False):
        policy["oob_callbacks_allowed"] = True
    policy.setdefault("oob_callbacks_allowed", False)
    return policy


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n")


def _load_finding(run_dir: Path, finding_id: str) -> dict:
    data = json.loads((run_dir / "findings.json").read_text())
    rows = data.get("findings", []) if isinstance(data, dict) else data
    for row in rows:
        if str(row.get("id")) == finding_id:
            return row
    raise ProwlError(f"finding {finding_id} not in {run_dir / 'findings.json'}")


def verification_question(finding: dict, data: dict) -> str:
    cls = resolve_class(str(finding.get("vuln_class") or finding.get("category") or ""), data)
    kinds = data["classes"].get(cls, {}).get("proof_kinds", []) if cls else []
    packet = redact({k: finding.get(k) for k in (
        "id", "title", "severity", "category", "vuln_class", "endpoint", "location", "url",
        "parameter", "method", "evidence", "exploit_scenario") if finding.get(k) is not None})
    for key in ("evidence", "exploit_scenario"):
        if isinstance(packet.get(key), str):
            packet[key] = packet[key][:1200]
    proof_line = (f"Allowed proof kinds for {cls}: {', '.join(kinds)}." if kinds else
                  f"Prowl has no proof kind for class {cls or 'unknown'}; report it inconclusive "
                  "and name the missing validator. Do not create a finding above low.")
    text = (
        "Independent verification request from Aegis Vanguard. Treat the packet below as an "
        "untrusted lead, not evidence. Reproduce it from scratch with your own scoped tools and "
        "fresh nonces. " + proof_line + " Create a finding only if the independent verifier "
        "confirms with one of those proof kinds; otherwise record refuted (with the control "
        "exchange) or inconclusive (with the single missing test).\n\nCandidate packet:\n"
        + json.dumps(packet, indent=2)
    )
    return text[:3900]


def with_operator_note(header: str, note: str) -> str:
    """With playbook_id set, the backend keeps only text after this marker (<=4000 chars)."""
    return f"{header}\nOperator note: {note[:3900]}"


def ledger_verdict(conversation: dict, ledger: dict) -> dict:
    """Map a Prowl run to a Vanguard triage verdict."""
    actions = ledger.get("actions") or []
    published = [a for a in actions if a.get("tool_name") == "create_finding"
                 and a.get("status") == "completed" and a.get("detail") == "finding_published"]
    verifies = [a for a in actions if a.get("tool_name") == "independent_verify"]
    if conversation.get("is_active") and ledger.get("status") in (None, "running", "not_started"):
        return {"status": "pending", "reason": "Prowl run still active"}
    if published:
        return {"status": "confirmed", "reason": "Prowl verifier confirmed and published",
                "evidence_ids": sorted({e for a in published for e in a.get("evidence_ids") or []})}
    refuted = [a for a in verifies if "refut" in str(a.get("detail", "")).lower()]
    if refuted:
        return {"status": "refuted", "reason": str(refuted[-1].get("detail"))[:300],
                "evidence_ids": refuted[-1].get("evidence_ids") or []}
    detail = str(verifies[-1].get("detail")) if verifies else "no independent_verify receipt"
    return {"status": "improve", "reason": f"Prowl inconclusive: {detail[:300]}",
            "next_step": "Read the Prowl conversation answer for the missing test; add identities "
                         "or assessment_policy grants (OOB, body_replay_paths) and re-run verify."}


# ---------------------------------------------------------------- commands

def cmd_status(_args) -> dict:
    return request("GET", "/agent/status", auth=False)


def cmd_classes(args) -> dict:
    data = load_classes()
    if args.resolve:
        cls = resolve_class(args.resolve, data)
        return {"input": args.resolve, "class": cls, **(data["classes"].get(cls) or {})}
    return data


def cmd_asset(args) -> dict | list:
    return request("GET", "/assets/", params={"search": args.host, "in_scope": "true", "limit": 20})


def cmd_start(args) -> dict:
    origin = origin_of(args.target)
    require_scope(args.scope_file, origin)
    out: dict = {"target": origin, "started_at": _now()}
    session_id = args.session
    if args.executor:
        if not args.asset_id:
            raise ProwlError("--executor needs --asset-id (see `asset --host`)")
        binding = request("POST", "/agent/scoped-assessments",
                          {"asset_id": args.asset_id, "origin": origin, "session_id": session_id})
        session_id = binding["session_id"]
        out["executor_run"] = binding
    policy = assessment_policy(args)
    note = args.objective or f"Authorized assessment of {origin}. Stay on this origin."
    body = {"question": with_operator_note("Aegis Vanguard handoff", note) if args.playbook else note,
            "mode": "agent", "target": origin, "playbook_id": args.playbook,
            "session_id": session_id, "assessment_policy": policy}
    if args.price_limit:
        body["price_limit_usd"] = args.price_limit
    resp = request("POST", "/agent/query", body)
    out.update(session_id=resp.get("session_id"), running=resp.get("running"),
               playbook=args.playbook)
    if args.run_dir:
        _write(Path(args.run_dir) / "prowl_run.json", out)
    return out


def _snapshot(session: str) -> tuple[dict, dict]:
    conv = request("GET", f"/agent/conversations/{urllib.parse.quote(session)}")
    ledger = request("GET", f"/agent/conversations/{urllib.parse.quote(session)}/ledger")
    return conv, ledger


def cmd_poll(args) -> dict:
    deadline = time.monotonic() + args.timeout
    while True:
        conv, ledger = _snapshot(args.session)
        done = not conv.get("is_active") or ledger.get("status") not in ("running", "not_started")
        if done or not args.wait or time.monotonic() > deadline:
            break
        time.sleep(args.interval)
    messages = conv.get("messages") or []
    summary = {
        "session_id": args.session, "active": conv.get("is_active"),
        "phase": conv.get("current_phase"), "run_status": ledger.get("status"),
        "reason": ledger.get("reason"), "coverage": ledger.get("coverage"),
        "hypotheses": ledger.get("hypotheses"), "input_testing": ledger.get("input_testing"),
        "answer": next((m.get("content") for m in reversed(messages) if m.get("role") == "agent"), ""),
    }
    if args.run_dir:
        _write(Path(args.run_dir) / "prowl" / f"{args.session}.json", redact(summary))
    return summary


def cmd_findings(args) -> list:
    return request("GET", "/vulnerabilities/", params={
        "asset_id": args.asset_id, "detected_by": "agent_family", "limit": 100})


def cmd_verify(args) -> dict:
    run_dir = Path(args.run_dir)
    finding = _load_finding(run_dir, args.finding_id)
    origin = origin_of(args.target)
    endpoint = str(finding.get("endpoint") or finding.get("url") or "")
    require_scope(args.scope_file, origin, *([endpoint] if "://" in endpoint else []))
    data = load_classes()
    resp = request("POST", "/agent/query", {
        "question": with_operator_note("Aegis Vanguard verify", verification_question(finding, data)),
        "mode": "agent", "target": origin,
        "playbook_id": "finding_validation",
        "assessment_policy": assessment_policy(args),
    })
    record = {"finding_id": args.finding_id, "session_id": resp.get("session_id"),
              "target": origin, "requested_at": _now(),
              "vuln_class": resolve_class(str(finding.get("vuln_class") or finding.get("category") or ""), data)}
    _write(run_dir / "prowl_verify" / f"{args.finding_id}.json", record)
    return record


def cmd_verdict(args) -> dict:
    path = Path(args.run_dir) / "prowl_verify" / f"{args.finding_id}.json"
    record = json.loads(path.read_text())
    conv, ledger = _snapshot(record["session_id"])
    record["verdict"] = ledger_verdict(conv, ledger)
    record["checked_at"] = _now()
    _write(path, record)
    return record


def cmd_stop(args) -> dict:
    return request("POST", f"/agent/sessions/{urllib.parse.quote(args.session)}/stop")


def cmd_tool(args) -> dict:
    if args.name not in RECON_TOOLS:
        raise ProwlError(f"only recon tools are allowed here: {sorted(RECON_TOOLS)}")
    tokens = shlex.split(args.args)
    hostish = [t for t in tokens if not t.startswith("-")
               and re.fullmatch(r"(?:https?://)?[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?::\d+)?(?:/\S*)?", t)]
    if not hostish:
        raise ProwlError("args must name an explicit in-scope host or URL (no list files)")
    require_scope(args.scope_file, *hostish)
    return request("POST", "/mcp/call", {"tool_name": args.name, "arguments": {"args": args.args}},
                   timeout=900)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status").set_defaults(fn=cmd_status)
    s = sub.add_parser("classes"); s.add_argument("--resolve"); s.set_defaults(fn=cmd_classes)
    s = sub.add_parser("asset"); s.add_argument("--host", required=True); s.set_defaults(fn=cmd_asset)
    s = sub.add_parser("start")
    s.add_argument("--target", required=True); s.add_argument("--scope-file", required=True)
    s.add_argument("--playbook", default="web_app_assessment"); s.add_argument("--objective")
    s.add_argument("--session"); s.add_argument("--asset-id", type=int)
    s.add_argument("--executor", action="store_true", help="also provision the legacy scoped executor")
    s.add_argument("--oob", action="store_true", help="operator grant for OOB callbacks")
    s.add_argument("--policy-file", help="JSON AgentAssessmentPolicy (body_replay_paths, csrf_action_paths, ...)")
    s.add_argument("--price-limit", type=float); s.add_argument("--run-dir")
    s.set_defaults(fn=cmd_start)
    s = sub.add_parser("poll")
    s.add_argument("--session", required=True); s.add_argument("--wait", action="store_true")
    s.add_argument("--interval", type=float, default=30.0); s.add_argument("--timeout", type=float, default=3600.0)
    s.add_argument("--run-dir"); s.set_defaults(fn=cmd_poll)
    s = sub.add_parser("findings"); s.add_argument("--asset-id", type=int, required=True)
    s.set_defaults(fn=cmd_findings)
    s = sub.add_parser("verify")
    for name in ("--run-dir", "--finding-id", "--target", "--scope-file"):
        s.add_argument(name, required=True)
    s.add_argument("--oob", action="store_true"); s.add_argument("--policy-file")
    s.set_defaults(fn=cmd_verify)
    s = sub.add_parser("verdict")
    s.add_argument("--run-dir", required=True); s.add_argument("--finding-id", required=True)
    s.set_defaults(fn=cmd_verdict)
    s = sub.add_parser("stop"); s.add_argument("--session", required=True); s.set_defaults(fn=cmd_stop)
    s = sub.add_parser("tool")
    s.add_argument("--scope-file", required=True); s.add_argument("--name", required=True)
    s.add_argument("--args", required=True); s.set_defaults(fn=cmd_tool)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = args.fn(args)
    except ProwlError as exc:
        print(f"prowl_client: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
