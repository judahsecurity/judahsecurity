"""Console entrypoint for the Aegis offensive agent.

Run an engagement headlessly, without the HTTP layer, reusing the exact same
``AgentOrchestrator.invoke()`` path that the REST and WebSocket routes use.

Usage (from ``backend/`` with the app on PYTHONPATH, or inside the container)::

    python -m app.cli run --target https://app.example.com
    python -m app.cli run --target https://app.example.com --playbook tester_process
    python -m app.cli run --question "Find IDORs in the /api/orders endpoints" --target https://app.example.com
    python -m app.cli playbooks
    python -m app.cli status

An engagement can be aimed three ways, in priority order:

  1. ``--playbook ID``  -> structured objective + seeded todos (build_initial_objective)
  2. ``--question TEXT`` -> free-form objective (agent decides everything)
  3. ``--target URL`` alone -> a general owner-authorized "find bugs" objective,
     for onboarding a new customer where you just want the surface hunted.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import time
import uuid
from typing import Any, Dict, List, Optional


def _runtime_available() -> bool:
    """True when any cloud LLM key is set or local Ollama can serve requests."""
    from app.core.config import settings
    from app.services.agent.model_router import ollama_fallback_available

    return bool(
        settings.OPENAI_API_KEY
        or settings.ANTHROPIC_API_KEY
        or getattr(settings, "DEEPSEEK_API_KEY", None)
        or getattr(settings, "MOONSHOT_API_KEY", None)
        or getattr(settings, "GROQ_API_KEY", None)
        or ollama_fallback_available()
    )


def _default_objective(target: str) -> str:
    """Flexible 'just find bugs' objective when no playbook or question is given."""
    return (
        "Perform an authorized, in-scope security assessment of "
        f"{target}. This is an owner-authorized engagement under the platform's "
        "Rules of Engagement. Enumerate the attack surface, fingerprint "
        "technologies, map the inventory, and hunt for vulnerabilities using the "
        "tools actually available on this worker. Prefer non-destructive checks, "
        "submit finding candidates for independent verification, and account for "
        "every surface (proven, tested-clean, or deliberately skipped) before "
        "completing. Summarize concrete findings with reproducible evidence."
    )


def _resolve_objective(args: argparse.Namespace) -> tuple[str, Optional[List[Dict[str, Any]]]]:
    """Return (question, initial_todos) from the flexible aiming rules."""
    from app.services.agent.playbooks import build_initial_objective, get_playbook

    if args.playbook:
        if not get_playbook(args.playbook):
            raise SystemExit(
                f"Unknown playbook '{args.playbook}'. Run `python -m app.cli playbooks` to list them."
            )
        objective, todos = build_initial_objective(args.playbook, args.target)
        return objective, todos

    if args.question:
        question = args.question.strip()
        if args.target and args.target.strip():
            question = f"{question}\n\nTarget: {args.target.strip()}"
        return question, None

    if args.target and args.target.strip():
        objective = _default_objective(args.target.strip())
        if getattr(args, "scope", None):
            objective = f"{objective}\n\nScope: {args.scope.strip()}"
        return objective, None

    raise SystemExit("Provide at least one of --playbook, --question, or --target.")


def _make_status_callback(quiet: bool):
    async def _cb(msg: Any) -> None:
        if quiet:
            return
        if not isinstance(msg, dict):
            print(f"[{time.strftime('%H:%M:%S')}] EVENT {msg}", flush=True)
            return
        etype = msg.get("type") or msg.get("event") or "?"
        tool = msg.get("tool") or msg.get("tool_name") or ""
        phase = msg.get("phase") or ""
        extra = ""
        if etype in ("tool_start", "tool_complete", "tool_end"):
            extra = f" tool={tool}"
            if msg.get("success") is not None:
                extra += f" success={msg.get('success')}"
        elif msg.get("message"):
            extra = " " + str(msg.get("message"))[:200]
        phase_str = f" phase={phase}" if phase else ""
        print(f"[{time.strftime('%H:%M:%S')}] {etype}{phase_str}{extra}", flush=True)

    return _cb


async def _run(args: argparse.Namespace) -> int:
    if not _runtime_available():
        print(
            "AI agent not available - configure a cloud LLM API key (OPENAI_API_KEY, "
            "ANTHROPIC_API_KEY, ...) or enable local Ollama.",
            file=sys.stderr,
            flush=True,
        )
        return 3

    from app.services.agent.orchestrator import get_agent_orchestrator

    question, initial_todos = _resolve_objective(args)
    session_id = args.session or f"cli-{uuid.uuid4().hex[:12]}"

    orchestrator = await get_agent_orchestrator()

    t0 = time.time()
    result = await orchestrator.invoke(
        question=question,
        user_id=args.user,
        organization_id=args.org,
        session_id=session_id,
        initial_todos=initial_todos,
        mode=args.mode,
        status_callback=_make_status_callback(args.quiet),
        max_iterations=args.max_iterations,
    )
    elapsed = round(time.time() - t0, 1)

    payload = {
        "session_id": session_id,
        "elapsed_s": elapsed,
        "task_complete": bool(getattr(result, "task_complete", False)),
        "awaiting_approval": bool(getattr(result, "awaiting_approval", False)),
        "awaiting_question": bool(getattr(result, "awaiting_question", False)),
        "current_phase": getattr(result, "current_phase", None),
        "iteration_count": getattr(result, "iteration_count", None),
        "error": getattr(result, "error", None),
        "warning": getattr(result, "warning", None),
        "answer": getattr(result, "answer", "") or "",
    }

    if args.json:
        print(json.dumps(payload, default=str, indent=2), flush=True)
    else:
        print("\n=== ENGAGEMENT RESULT ===", flush=True)
        print(f"session_id:   {payload['session_id']}", flush=True)
        print(f"elapsed_s:    {payload['elapsed_s']}", flush=True)
        print(f"phase:        {payload['current_phase']}", flush=True)
        print(f"complete:     {payload['task_complete']}", flush=True)
        if payload["awaiting_approval"]:
            print("awaiting:     phase-transition approval", flush=True)
        if payload["awaiting_question"]:
            print("awaiting:     answer to agent question", flush=True)
        if payload["warning"]:
            print(f"warning:      {payload['warning']}", flush=True)
        if payload["error"]:
            print(f"error:        {payload['error']}", flush=True)
        print("--- ANSWER ---", flush=True)
        print(payload["answer"], flush=True)

    if payload["error"]:
        return 2
    if payload["awaiting_approval"] or payload["awaiting_question"]:
        return 4
    return 0


async def _playbooks(args: argparse.Namespace) -> int:
    from app.services.agent.playbooks import list_playbooks

    plays = list_playbooks()
    if args.json:
        print(json.dumps(plays, indent=2), flush=True)
        return 0
    width = max((len(p["id"]) for p in plays), default=2)
    for p in plays:
        print(f"{p['id']:<{width}}  {p['description']}", flush=True)
    return 0


async def _status(args: argparse.Namespace) -> int:
    available = _runtime_available()
    info = {"agent_runtime_available": available}
    if args.json:
        print(json.dumps(info, indent=2), flush=True)
    else:
        print("agent runtime available:" , available, flush=True)
    return 0 if available else 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis-agent",
        description="Run the Aegis offensive agent from the console.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Start an engagement and stream progress.")
    run.add_argument("--target", help="Target URL / host / repo in scope.")
    run.add_argument(
        "--scope",
        help="Root-domain scope (accepted for harness compatibility; folded into the objective).",
    )
    run.add_argument("--playbook", help="Playbook id (see `playbooks`). Optional.")
    run.add_argument("--question", help="Free-form objective. Overridden by --playbook.")
    run.add_argument(
        "--mode",
        choices=["assist", "agent"],
        default="agent",
        help="assist = step-by-step with approvals; agent = autonomous (default).",
    )
    run.add_argument("--org", type=int, default=1, help="Organization id (default 1).")
    run.add_argument("--user", default="1", help="User id (default '1').")
    run.add_argument("--session", help="Session id (default: random cli-<hex>).")
    run.add_argument(
        "--max-iterations",
        type=int,
        default=None,
        dest="max_iterations",
        help="Cap agent iterations for this run (default: orchestrator default).",
    )
    run.add_argument("--json", action="store_true", help="Emit the result as JSON.")
    run.add_argument("--quiet", action="store_true", help="Suppress streamed events.")
    run.set_defaults(func=_run)

    pb = sub.add_parser("playbooks", help="List available playbooks.")
    pb.add_argument("--json", action="store_true", help="Emit as JSON.")
    pb.set_defaults(func=_playbooks)

    st = sub.add_parser("status", help="Check whether an LLM runtime is configured.")
    st.add_argument("--json", action="store_true", help="Emit as JSON.")
    st.set_defaults(func=_status)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    logging.getLogger().setLevel(logging.WARNING)
    parser = build_parser()
    args = parser.parse_args(argv)
    return asyncio.run(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
