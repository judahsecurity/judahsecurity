"""Harness adapter for the in-product orchestrator, with normal publication gates.

Requires a configured backend, a dedicated assessment organization/database, and
LLM credentials. No benchmark ground truth is passed into the agent.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import uuid
from pathlib import Path


class _Autonomy:
    """Scheduled-run limits, request governor and signal pool for one assessment."""

    def __init__(self, args):
        from urllib.parse import urlsplit

        from app.services.agent.autonomy_limits import (
            SignalBonusPool, current_autonomy_limits, current_signal_bonus_pool,
            limits_from_config,
        )
        from app.services.agent.egress_governor import (
            RequestGovernor, current_request_governor, install_httpx_governor,
        )

        hosts = sorted({
            (urlsplit(item if "://" in item else f"https://{item}").hostname or "").lower()
            for item in [args.target, *str(args.scope or "").replace("\n", ",").split(",")]
            if item.strip()
        } - {""})
        delegate = bool(getattr(args, "delegate_replay_approval", False))
        self.limits = limits_from_config({
            "allowed_hosts": hosts,
            "allowed_actions": ["read", "probe", *(["state_change"] if delegate else [])],
            "delegate_replay_approval": delegate,
        }, target=args.target)
        install_httpx_governor()
        self.governor = RequestGovernor(
            self.limits.allowed_hosts,
            rate_per_second=self.limits.request_rate_per_second,
            max_requests=self.limits.max_run_requests,
        )
        self.pool = SignalBonusPool(self.limits.signal_bonus_pool, self.limits.signal_bonus_step)
        self._resets = [
            (current_autonomy_limits, current_autonomy_limits.set(self.limits)),
            (current_request_governor, current_request_governor.set(self.governor)),
            (current_signal_bonus_pool, current_signal_bonus_pool.set(self.pool)),
        ]

    def close(self, manager) -> dict:
        for var, token in reversed(self._resets):
            var.reset(token)
        brain = getattr(manager, "_engagement_brain", None) or {}
        decisions = brain.get("replay_approvals") if isinstance(brain, dict) else None
        decisions = [row for row in decisions or [] if isinstance(row, dict)]
        return {
            "enabled": True,
            "traffic": self.governor.summary(),
            "signal_bonus": {
                "granted": dict(self.pool.granted),
                "remaining": self.pool.remaining,
            },
            "replay_approvals": {
                "approved": sum(row.get("decision") == "approved" for row in decisions),
                "denied": sum(row.get("decision") == "denied" for row in decisions),
            },
        }


def _autonomy_context(args):
    return _Autonomy(args) if getattr(args, "autonomy", False) else None


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
    response = None
    run_ledgers = []
    ledger_export_error = None
    autonomy = _autonomy_context(args)
    invoke_extra = (
        {"assessment_policy": {"delegated_replay_approval": {"enabled": True}}}
        if getattr(args, "delegate_replay_approval", False) else {}
    )
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
            **invoke_extra,
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
    autonomy_summary = autonomy.close(manager) if autonomy else {"enabled": False}
    autonomy_summary["delegated_replay_approval"] = bool(invoke_extra)
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
        "complete": assessment_complete,
        "final_run_status": final_run_status,
        "error": response.error if response else "No response",
        "turns": turn + 1,
        "cost_usd": getattr(response, "cost_usd", None),
        "token_usage": getattr(response, "token_usage", None),
        "oast": oast_status,
        "ledger_metrics": ledger_metrics,
        "ledger_export_error": ledger_export_error,
        "autonomy": autonomy_summary,
    }
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
        "--require-oast",
        action="store_true",
        help="Fail preflight unless the standalone Interactsh callback client is healthy.",
    )
    parser.add_argument(
        "--autonomy",
        action="store_true",
        help="Apply scheduled-run limits: request governor, signal-earned budget and specialist contracts.",
    )
    parser.add_argument(
        "--delegate-replay-approval",
        action="store_true",
        help="Let the agent unlock write paths it observed (implies state_change in --autonomy).",
    )
    args = parser.parse_args(argv)
    return asyncio.run(assess(args))


if __name__ == "__main__":
    raise SystemExit(main())
