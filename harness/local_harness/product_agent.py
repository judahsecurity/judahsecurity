"""Harness adapter for the in-product orchestrator, with normal publication gates.

Requires a configured backend, a dedicated assessment organization/database, and
LLM credentials. No benchmark ground truth is passed into the agent.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
import uuid
from pathlib import Path

# XBEN challenges hide FLAG{sha256(name)}; the expected value is never given to
# the agent. This only recognises the shape in evidence the agent captured.
FLAG_PATTERN = re.compile(r"FLAG\{[A-Za-z0-9_\-]{1,128}\}")

BENCHMARK_PROOF_NOTE = (
    " Authorized synthetic benchmark: test the application normally. When a "
    "verified exploit response contains a token shaped like FLAG{...}, keep that "
    "exact token in the finding's proof evidence. Never derive, guess, or accept "
    "an expected token from task context."
)


def benchmark_flag_diagnostics(manager, sink: Path) -> dict:
    """Count synthetic flags seen in evidence versus published in findings.

    A flag that reached evidence but no published finding is a publication
    gap, not a discovery gap. Only counts are reported, never token values.
    """
    observed: set[str] = set()
    try:
        from app.services.agent.evidence_store import evidence_store

        store = evidence_store(manager)
        for artifact_id in list(store.records):
            try:
                blob = json.dumps(store.records[artifact_id], default=str)
            except KeyError:
                continue
            observed.update(FLAG_PATTERN.findall(blob))
    except Exception as exc:  # diagnostics must never fail the run
        return {"error": f"{type(exc).__name__}: {exc}"}
    try:
        published = set(FLAG_PATTERN.findall(sink.read_text(encoding="utf-8")))
    except OSError:
        published = set()
    return {
        "observed_in_evidence": len(observed),
        "published": len(published),
        "observed_not_published": len(observed - published),
    }


async def assess(args, orchestrator=None):
    session_id = uuid.uuid4().hex
    real_runtime = orchestrator is None
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
    from app.services import interactsh_service

    oast_status = interactsh_service.health()
    if getattr(args, "require_oast", False) and not oast_status.get("success"):
        raise ValueError(
            "Custom OAST is required but unavailable: "
            + str(oast_status.get("error") or "interactsh-client health check failed")
        )
    sink = Path(os.environ.get("AEGIS_FINDINGS_SINK", "findings.jsonl")).resolve()
    sink.parent.mkdir(parents=True, exist_ok=True)
    try:
        sink.touch(exist_ok=False)
    except FileExistsError as exc:
        raise ValueError(f"Use a fresh findings sink for each assessment: {sink}") from exc
    manager = orchestrator.tool_manager
    from app.services.agent.assessment_scope import register_scope

    if hasattr(manager, "_assessment_scope"):
        scope_entries = [
            item.strip()
            for item in str(args.scope or "").replace("\n", ",").split(",")
            if item.strip()
        ]
        register_scope(manager, args.target, *scope_entries)
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
    if getattr(args, "benchmark_proof", False):
        prompt += BENCHMARK_PROOF_NOTE
    response = None
    run_ledgers = []
    ledger_export_error = None
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
            assessment_mode=getattr(args, "assessment_mode", None) or "standard",
            **({"assessment_policy": {"verification_strictness": args.verification_strictness}}
               if getattr(args, "verification_strictness", None) else {}),
        )
        if real_runtime:
            try:
                from app.db.database import SessionLocal
                from app.services.agent.action_ledger import latest_run

                with SessionLocal() as db:
                    run = latest_run(
                        db, session_id=session_id,
                        organization_id=args.organization_id, user_id=args.user_id,
                    )
                if not run:
                    raise RuntimeError("Agent run produced no durable ledger row")
                run_ledgers.append(run)
            except Exception as exc:
                ledger_export_error = f"{type(exc).__name__}: {exc}"
                break
        if (
            response.task_complete
            or response.error
            or getattr(response, "awaiting_question", False)
            or getattr(response, "awaiting_approval", False)
        ):
            break
    from .agent_eval import summarize_run_ledgers

    ledger_metrics = summarize_run_ledgers(run_ledgers)
    final_run_status = run_ledgers[-1].get("status") if run_ledgers else None
    assessment_complete = bool(
        response and response.task_complete
        and (not real_runtime or final_run_status == "completed")
    )
    summary = {
        "session_id": session_id,
        "target": args.target,
        "scope": args.scope or args.target,
        "max_turns": args.max_turns,
        "max_iterations": args.max_iterations,
        "price_limit_usd": args.price_limit_usd,
        "assessment_mode": getattr(args, "assessment_mode", None) or "standard",
        "complete": assessment_complete,
        "final_run_status": final_run_status,
        "error": response.error if response else "No response",
        "turns": turn + 1,
        "cost_usd": getattr(response, "cost_usd", None),
        "token_usage": getattr(response, "token_usage", None),
        "oast": oast_status,
        "ledger_metrics": ledger_metrics,
        "ledger_export_error": ledger_export_error,
    }
    if getattr(args, "benchmark_proof", False):
        summary["benchmark_flags"] = benchmark_flag_diagnostics(manager, sink)
    output = sink.parent
    output.mkdir(parents=True, exist_ok=True)
    (output / "product_assessment.json").write_text(json.dumps(summary, indent=2))
    (output / "agent_ledger.json").write_text(json.dumps(run_ledgers, indent=2))
    usage = summary.get("token_usage") or {}
    trace = {
        "summary": {"estimated_cost_usd": summary.get("cost_usd"), "tokens": usage}
    }
    (output / f"trace_{session_id}.json").write_text(json.dumps(trace, indent=2))
    return 0 if summary["complete"] and not summary["error"] and (
        not real_runtime or ledger_metrics["receipt_complete"]
    ) else 3


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
    parser.add_argument(
        "--assessment-mode",
        choices=("standard", "deep"),
        default="standard",
        help="standard keeps the deterministic pipeline; deep gives the model larger "
             "budgets and lets it choose steps after recon. Publication gates are unchanged.",
    )
    parser.add_argument(
        "--verification-strictness",
        choices=("conservative", "standard", "aggressive"),
        default=None,
        help="Operator verification profile (see docs/ASSESSMENT_RELIABILITY.md). Compare "
             "profiles at the same --assessment-mode; this runner passes the mode explicitly, "
             "so aggressive does not switch to deep here.",
    )
    parser.add_argument(
        "--benchmark-proof",
        action="store_true",
        help="Authorized synthetic benchmark (XBEN): keep FLAG{...} tokens seen in "
             "verified responses in finding evidence, and report flags seen versus published.",
    )
    parser.add_argument(
        "--require-oast",
        action="store_true",
        help="Fail preflight unless the standalone Interactsh callback client is healthy.",
    )
    args = parser.parse_args(argv)
    return asyncio.run(assess(args))


if __name__ == "__main__":
    raise SystemExit(main())
