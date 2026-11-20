"""Background execution for long-running agent tools.

A slow scanner (nuclei, nmap, ffuf, sqlmap ...) used to hold the agent's turn
until it finished or hit the hard cap, then get killed. With background
execution the orchestrator waits a bounded time (``AGENT_TOOL_WAIT_SECONDS``)
once the tool is actually running. If it is still running, the agent gets an
``execution_id`` and keeps working; the tool continues under the same hard
cap. The agent reads the result later with ``wait_tool_execution`` or stops it
with ``cancel_tool_execution``.

Executions belong to one agent run. They are cancelled when that run ends, so
nothing keeps sending traffic after the operator's run is over. The tool's own
recording (action ledger, evidence store, demonstrated-chain buffer) happens
inside the tool manager, so a background result is recorded exactly like a
foreground one.

The bounded wait starts only after the confirmation gate has passed
(``mark_running``), so a call waiting for operator approval still blocks the
turn as before.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# Scanners that commonly run for minutes. Tools whose results feed the
# capability map or proof flow (browser, deep crawl, interceptor, scoped
# probes) stay synchronous.
BACKGROUND_TOOLS = frozenset({
    "execute_nuclei",
    "execute_naabu",
    "execute_nmap",
    "execute_masscan",
    "execute_ffuf",
    "execute_amass",
    "execute_katana",
    "execute_subfinder",
    "execute_gau",
    "execute_waybackurls",
    "execute_kiterunner",
    "execute_schemathesis",
    "execute_sqlmap",
    "execute_nikto",
    "execute_testssl",
    "execute_sslyze",
    "execute_wpscan",
})

MAX_PER_RUN = 4
MAX_RESULT_CHARS_DEFAULT = 20000

_current_execution: ContextVar[Optional["ToolExecution"]] = ContextVar(
    "current_tool_execution", default=None,
)


@dataclass
class ToolExecution:
    id: str
    run_id: str
    session_id: str
    tool_name: str
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None
    status: str = "queued"  # queued|running|completed|failed|cancelled|hard_timeout
    result: Optional[Dict[str, Any]] = None
    task: Optional["asyncio.Task"] = None
    running: asyncio.Event = field(default_factory=asyncio.Event)
    backgrounded: bool = False
    announced: bool = False

    @property
    def done(self) -> bool:
        return self.status in {"completed", "failed", "cancelled", "hard_timeout"}

    def summary(self) -> Dict[str, Any]:
        end = self.finished_at or time.time()
        return {
            "execution_id": self.id,
            "tool": self.tool_name,
            "status": self.status,
            "elapsed_seconds": round(end - self.started_at, 1),
        }


_executions: Dict[str, ToolExecution] = {}


def mark_running() -> None:
    """Called by the tool manager once a call has cleared approval gates."""
    execution = _current_execution.get()
    if execution is not None and not execution.running.is_set():
        execution.status = "running" if not execution.done else execution.status
        execution.running.set()


def background_enabled(tool_name: str) -> bool:
    from app.core.config import settings
    from app.services.agent.evidence_store import verification_run
    from app.services.agent.pilot_policy import current_pilot

    if tool_name not in BACKGROUND_TOOLS:
        return False
    if float(getattr(settings, "AGENT_TOOL_WAIT_SECONDS", 0) or 0) <= 0:
        return False
    # Bounded pilots and independent verification need the result in-turn.
    return current_pilot() is None and verification_run.get() is None


def wait_seconds() -> float:
    from app.core.config import settings

    return max(1.0, float(getattr(settings, "AGENT_TOOL_WAIT_SECONDS", 120) or 120))


def run_executions(run_id: str) -> List[ToolExecution]:
    return [e for e in _executions.values() if e.run_id == run_id]


def active_count(run_id: str) -> int:
    return sum(1 for e in run_executions(run_id) if not e.done)


def start(
    *,
    run_id: str,
    session_id: str,
    tool_name: str,
    factory: Callable[[], Awaitable[Dict[str, Any]]],
    hard_timeout: float,
) -> ToolExecution:
    execution = ToolExecution(
        id="exec_" + os.urandom(8).hex(), run_id=run_id or "",
        session_id=session_id or "", tool_name=tool_name,
    )

    async def runner() -> None:
        token = _current_execution.set(execution)
        try:
            result = await asyncio.wait_for(factory(), timeout=hard_timeout)
            execution.result = result if isinstance(result, dict) else {
                "success": True, "output": result}
            execution.status = "completed" if execution.result.get("success") else "failed"
        except asyncio.TimeoutError:
            execution.status = "hard_timeout"
            execution.result = {
                "success": False, "output": "",
                "error": (f"Tool '{tool_name}' exceeded its {int(hard_timeout)}s time "
                          "budget and was aborted. The backend stopped waiting."),
            }
        except asyncio.CancelledError:
            execution.status = "cancelled"
            execution.result = {"success": False, "output": "",
                                "error": f"Tool '{tool_name}' execution was cancelled."}
            raise
        except Exception as exc:  # the foreground path converts raises the same way
            execution.status = "failed"
            execution.result = {"success": False, "output": "",
                                "error": f"Tool '{tool_name}' raised: {exc}"}
        finally:
            execution.finished_at = time.time()
            execution.running.set()
            _current_execution.reset(token)

    _executions[execution.id] = execution
    execution.task = asyncio.create_task(runner(), name=f"tool:{tool_name}:{execution.id}")
    return execution


async def wait_until_settled(execution: ToolExecution, *, budget: float, wait: float) -> bool:
    """Wait for approval, then up to ``wait`` seconds of running. True if done.

    ``budget`` bounds the whole wait (the turn's remaining time) so a call
    that is never approved cannot hold the turn past it.
    """
    deadline = time.monotonic() + max(0.0, budget)
    task = execution.task
    assert task is not None
    running_wait = asyncio.ensure_future(execution.running.wait())
    try:
        await asyncio.wait({task, running_wait}, timeout=max(0.0, deadline - time.monotonic()),
                           return_when=asyncio.FIRST_COMPLETED)
    finally:
        running_wait.cancel()
    if task.done():
        return True
    remaining = min(wait, max(0.0, deadline - time.monotonic()))
    if remaining > 0:
        await asyncio.wait({task}, timeout=remaining)
    return task.done()


def get(execution_id: str, *, run_id: str = "", session_id: str = "") -> Optional[ToolExecution]:
    execution = _executions.get(str(execution_id or "").strip())
    if execution is None:
        return None
    # Executions are visible only to the run (or session) that started them.
    if run_id and execution.run_id != run_id:
        if not (session_id and execution.session_id == session_id):
            return None
    return execution


async def wait(execution: ToolExecution, timeout: float) -> bool:
    if execution.task is not None and not execution.task.done():
        await asyncio.wait({execution.task}, timeout=max(0.0, timeout))
    return execution.done


def cancel(execution: ToolExecution) -> bool:
    if execution.task is None or execution.task.done():
        return False
    return execution.task.cancel()


async def cancel_run(run_id: str) -> int:
    """Cancel every unfinished execution of a run and forget the run's records."""
    if not run_id:
        return 0
    executions = run_executions(run_id)
    pending = [e.task for e in executions if e.task is not None and not e.task.done()]
    for task in pending:
        task.cancel()
    if pending:
        await asyncio.wait(pending, timeout=5)
    for execution in executions:
        _executions.pop(execution.id, None)
    if pending:
        logger.info("Cancelled %d background tool execution(s) at end of run %s",
                    len(pending), run_id)
    return len(pending)


def take_unannounced(run_id: str) -> List[ToolExecution]:
    """Backgrounded executions that finished since the agent last heard."""
    finished = [e for e in run_executions(run_id)
                if e.backgrounded and e.done and not e.announced]
    for execution in finished:
        execution.announced = True
    return finished


def format_result(execution: ToolExecution, max_chars: int = MAX_RESULT_CHARS_DEFAULT) -> str:
    result = execution.result or {}
    output = result.get("output")
    if output is not None and not isinstance(output, str):
        import json

        try:
            output = json.dumps(output, default=str)
        except (TypeError, ValueError):
            output = str(output)
    body = output or result.get("error") or ""
    header = (f"Execution {execution.id} ({execution.tool_name}) {execution.status} "
              f"after {execution.summary()['elapsed_seconds']}s.")
    if result.get("error") and output:
        header += f" Error: {result['error']}"
    text = f"{header}\n{body}" if body else header
    if len(text) > max_chars:
        text = text[:max_chars] + f"\n...[truncated {len(text) - max_chars} chars]"
    return text


def background_notice(execution: ToolExecution, waited: float) -> Dict[str, Any]:
    return {
        "success": True,
        "background": True,
        "execution_id": execution.id,
        "status": execution.status,
        "output": (
            f"{execution.tool_name} is still running after {int(waited)}s and continues in "
            f"the background as execution_id={execution.id}. Do other useful work, then call "
            f"wait_tool_execution(execution_id=\"{execution.id}\") to read the result, or "
            f"cancel_tool_execution(execution_id=\"{execution.id}\") if it is no longer needed. "
            "Do not start the same scan again. Unfinished executions are cancelled when "
            "this run ends."
        ),
    }
