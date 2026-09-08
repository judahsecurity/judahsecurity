"""Harness adapter for the in-product orchestrator, with normal publication gates.

Requires a configured backend, a dedicated assessment organization/database, and
LLM credentials. No benchmark ground truth is passed into the agent.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import sys
import uuid


async def assess(args, orchestrator=None):
    session_id = uuid.uuid4().hex
    if orchestrator is None:
        backend = Path(__file__).resolve().parents[2] / "backend"
        sys.path.insert(0, str(backend))
        database = os.environ.get("AEGIS_ASSESSMENT_DATABASE_URL")
        if not database:
            raise ValueError(
                "Set AEGIS_ASSESSMENT_DATABASE_URL to a dedicated assessment database"
            )
        os.environ["DATABASE_URL"] = database
        from app.services.agent.orchestrator import AgentOrchestrator

        orchestrator = AgentOrchestrator()
        await orchestrator.initialize()
        if not orchestrator._initialized:
            raise ValueError(
                "Product agent initialization failed; check LLM configuration"
            )
        from app.services.agent.tools import set_tenant_context

        set_tenant_context(args.user_id, args.organization_id, session_id)
    manager = orchestrator.tool_manager
    identities = (
        json.loads(Path(args.identities).read_text()) if args.identities else []
    )
    for identity in identities:
        check = identity.pop("check", None)
        await manager.register_test_identity(**identity)
        if check:
            await manager.check_test_identity(identity["name"], **check)
    prompt = (
        f"Assess the authorized target {args.target}. Scope: {args.scope or args.target}. "
        "Use the normal assessment kickoff, mapping, specialist, verification, and finding "
        "publication workflow. Inspect list_test_identities and use configured test accounts. "
        "Report blocked and untested coverage honestly. Do not bypass any proof gate."
    )
    response = None
    for turn in range(max(1, args.max_turns)):
        response = await orchestrator.invoke(
            question=prompt
            if turn == 0
            else "Continue the assessment from its remaining tests.",
            user_id=str(args.user_id),
            organization_id=args.organization_id,
            session_id=session_id,
            mode="agent",
            max_iterations=args.max_iterations,
            price_limit_usd=args.price_limit_usd,
        )
        if (
            response.task_complete
            or response.error
            or getattr(response, "awaiting_question", False)
            or getattr(response, "awaiting_approval", False)
        ):
            break
    summary = {
        "session_id": session_id,
        "complete": bool(response and response.task_complete),
        "error": response.error if response else "No response",
        "turns": turn + 1,
        "cost_usd": getattr(response, "cost_usd", None),
        "token_usage": getattr(response, "token_usage", None),
    }
    output = (
        Path(os.environ.get("AEGIS_FINDINGS_SINK", "findings.jsonl")).resolve().parent
    )
    output.mkdir(parents=True, exist_ok=True)
    (output / "product_assessment.json").write_text(json.dumps(summary, indent=2))
    usage = summary.get("token_usage") or {}
    trace = {
        "summary": {"estimated_cost_usd": summary.get("cost_usd"), "tokens": usage}
    }
    (output / f"trace_{session_id}.json").write_text(json.dumps(trace, indent=2))
    return 0 if summary["complete"] and not summary["error"] else 3


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--scope", default="")
    parser.add_argument("--organization-id", type=int, required=True)
    parser.add_argument("--user-id", type=int, required=True)
    parser.add_argument(
        "--identities", help="Local JSON test-session configuration; keep out of git"
    )
    parser.add_argument("--max-turns", type=int, default=4)
    parser.add_argument("--max-iterations", type=int, default=30)
    parser.add_argument("--price-limit-usd", type=float, default=5.0)
    args = parser.parse_args(argv)
    return asyncio.run(assess(args))


if __name__ == "__main__":
    raise SystemExit(main())
