"""Scanner/MCP tool execution, background executions and external MCP servers.

Mixin for ASMToolsManager; methods moved verbatim from tools.py.
"""

from app.services.agent.tools_common import (
    Any,
    Dict,
    List,
    Optional,
    SessionLocal,
    _tool_output_max_chars,
    asyncio,
    current_seed_target,
    current_session_id,
    get_tenant_context,
    json,
    logger,
    settings,
)


class ToolExecutionMixin:
    """Scanner/MCP tool execution, background executions and external MCP servers."""

    async def auto_select_tools(
        self,
        target: str = "",
        **kwargs: Any,
    ) -> str:
        """Analyze the current assessment state and return prioritized tool
        recommendations based on discovered technologies, ports, parameters,
        and WAF presence.

        This tool reads the agent's accumulated target_info and execution_trace
        from the orchestrator state (passed via kwargs by the orchestrator) and
        returns a ranked list of tools to run next with rationale.

        Args:
            target: The primary target hostname/URL to generate recommendations for.
        """
        from app.services.agent.tool_selector import get_tool_recommendations_json

        target_info = kwargs.get("_target_info") or {}
        execution_trace = kwargs.get("_execution_trace") or []
        current_phase = kwargs.get("_current_phase") or "informational"
        parameters = kwargs.get("_parameters") or {}
        waf_detected = kwargs.get("_waf_detected")

        if not target:
            target = target_info.get("primary_target") or ""

        if not target:
            return json.dumps({
                "error": "No target specified. Provide a target URL or hostname.",
                "hint": "Use auto_select_tools(target='example.com') or run execute_httpx first to populate target_info.",
            }, indent=2)

        recs = get_tool_recommendations_json(
            target=target,
            target_info=target_info,
            execution_trace=execution_trace,
            current_phase=current_phase,
            parameters=parameters,
            waf_detected=waf_detected,
        )

        return json.dumps({
            "target": target,
            "current_phase": current_phase,
            "tools_already_run": list({
                s.get("tool_name") for s in execution_trace if s.get("tool_name")
            }),
            "recommendation_count": len(recs),
            "recommendations": recs,
        }, indent=2)

    async def execute_mcp_tool(self, tool_name: str = None, args: str = "", **kwargs) -> str:
        """
        Execute an MCP security tool.
        
        This method delegates to the MCP server for tool execution.
        
        Args:
            tool_name: Name of the MCP tool to execute
            args: CLI arguments for the tool
        
        Returns:
            Tool output as string
        """
        mcp = self._get_mcp_server()
        
        # Get the actual tool name from kwargs if provided
        actual_tool = tool_name or kwargs.get("_tool_name", "")
        
        if not actual_tool:
            return "Error: No tool name specified"
        
        # Build arguments
        arguments = {"args": args} if args else kwargs
        
        # Call MCP tool
        result = await mcp.call_tool(actual_tool, arguments)
        
        max_chars = _tool_output_max_chars()
        if result.get("success"):
            output = result.get("output", "")
            if len(output) > max_chars:
                output = output[:max_chars] + f"\n\n... (truncated, {len(result['output'])} total chars)"
            return output or "Command completed with no output."
        else:
            err = result.get("error", "Unknown error")
            out = result.get("output", "")
            err_max = min(8000, max_chars)
            if out and out.strip():
                return f"Error: {err}\nStdout:\n{out[:err_max]}" + ("\n... (truncated)" if len(out) > err_max else "")
            return f"Error: {err}"

    async def execute_uncover(
        self,
        query: str,
        engines: Optional[List[str]] = None,
        limit: int = 100,
        timeout: int = 120,
        persist: bool = False,
    ) -> str:
        """ProjectDiscovery Uncover - search Shodan/Censys/FOFA/Hunter/Quake in one go.

        Args:
            query: Engine-specific search DSL (e.g. ``"apache" country:"US"``).
            engines: List of engines to hit. Defaults to ["shodan","censys","fofa"].
            limit: Max results per engine.
            timeout: Command timeout in seconds.
            persist: If True, materialize discovered hosts as Assets in the DB.
        """
        from app.services.uncover_service import run_uncover, persist_uncover_assets
        if not query or not query.strip():
            return "Error: query is required."

        result = await run_uncover(
            query=query,
            engines=engines,
            limit=limit,
            timeout=timeout,
        )

        persisted = 0
        if persist:
            _, org_id = get_tenant_context()
            if org_id:
                db = SessionLocal()
                try:
                    persisted = persist_uncover_assets(db, org_id, result)
                finally:
                    db.close()

        payload = {
            "query": result.query,
            "engines": result.engines,
            "used_binary": result.used_binary,
            "duration_seconds": result.duration_seconds,
            "hit_count": len(result.hits),
            "errors": result.errors,
            "persisted_assets": persisted,
            "hits": [
                {
                    "host": h.host,
                    "port": h.port,
                    "engine": h.engine,
                }
                for h in result.hits[:200]
            ],
        }
        return json.dumps(payload, indent=2)[:_tool_output_max_chars()]

    def _active_testing_denied(self, tool_name: str) -> Optional[Dict[str, Any]]:
        from app.services.agent.confirmation_service import READONLY_TOOLS, SAFE_RECON_TOOLS

        if tool_name in READONLY_TOOLS or tool_name in SAFE_RECON_TOOLS or tool_name.endswith("_help"):
            return None
        user_id, _ = get_tenant_context()
        if not user_id:
            return None
        try:
            from app.core.permissions import user_id_restricted_from

            if not user_id_restricted_from(int(user_id), "agent.active_testing"):
                return None
        except Exception:
            logger.exception("Permission check failed for %s", tool_name)
            return {"success": False, "error": "permission_check_failed",
                    "output": "Tool blocked: the permission check could not be completed."}
        return {"success": False, "error": "permission_denied",
                "output": (f"Tool '{tool_name}' needs the 'agent.active_testing' permission, "
                           "which your role does not include. Use read-only queries and light "
                           "recon, or ask an admin.")}

    def _start_ai_review(self, token: str, tool_name: str, tool_args: Dict[str, Any],
                         org_id: Optional[int]):
        """Ask the AI reviewer to approve a routine call; humans can still decide."""
        from app.services.agent.approval_reviewer import review_and_decide
        from app.services.agent.confirmation_service import preview_tool_args
        from app.services.agent.model_router import LLMTask, get_llm_for_task

        def llm_factory():
            db = SessionLocal()
            try:
                return get_llm_for_task(db, org_id, LLMTask.RECON, temperature=0,
                                        max_tokens=300, timeout=45, max_retries=1)
            finally:
                db.close()

        return asyncio.create_task(review_and_decide(
            token, llm_factory=llm_factory, tool_name=tool_name,
            tool_args=preview_tool_args(tool_args or {}),
            scope=sorted(getattr(self, "_assessment_scope", set()) or []),
            objective=current_seed_target.get() or getattr(self, "_fallback_target", "") or "",
            organization_id=org_id,
        ))

    def _lookup_execution(self, execution_id: str):
        from app.services.agent import tool_executions
        from app.services.agent.action_ledger import active_run_id

        return tool_executions.get(
            execution_id, run_id=active_run_id.get() or "",
            session_id=str(current_session_id.get() or ""),
        )

    @staticmethod
    def _execution_progress(execution, include_partial_output: bool,
                            partial_output_max_bytes: int) -> str:
        summary = execution.summary()
        text = (f"Execution {summary['execution_id']} ({summary['tool']}) is still "
                f"{summary['status']} after {summary['elapsed_seconds']}s "
                f"({execution.output_bytes} output bytes so far).")
        if include_partial_output and execution.output_bytes:
            tail = execution.output_tail(partial_output_max_bytes)
            text += ("\nLive output tail (partial, not the final result):\n" + tail)
        return text

    async def get_tool_execution(self, execution_id: str, include_partial_output: bool = True,
                                 partial_output_max_bytes: int = 4096) -> str:
        """Status of a background tool execution; the result if it has finished.

        While running, includes a bounded live tail of output (default 4096
        bytes, max 65536). The tail is a preview, not the final result."""
        from app.services.agent import tool_executions

        execution = self._lookup_execution(execution_id)
        if execution is None:
            return f"No background execution '{execution_id}' in this run."
        if execution.done:
            execution.announced = True
            return tool_executions.format_result(execution, _tool_output_max_chars())
        return (self._execution_progress(execution, include_partial_output,
                                         partial_output_max_bytes)
                + "\nCall wait_tool_execution to wait for it.")

    async def wait_tool_execution(self, execution_id: str, timeout_seconds: float = 120,
                                  include_partial_output: bool = True,
                                  partial_output_max_bytes: int = 4096) -> str:
        """Wait up to timeout_seconds (max 600) for a background execution and return its result.

        Reaching the timeout is not a failure: the execution keeps running and
        can be waited on again or cancelled.
        """
        from app.services.agent import tool_executions

        execution = self._lookup_execution(execution_id)
        if execution is None:
            return f"No background execution '{execution_id}' in this run."
        try:
            timeout = float(timeout_seconds)
        except (TypeError, ValueError):
            timeout = 120.0
        await tool_executions.wait(execution, min(max(timeout, 0.0), 600.0))
        if execution.done:
            execution.announced = True
            return tool_executions.format_result(execution, _tool_output_max_chars())
        return (self._execution_progress(execution, include_partial_output,
                                         partial_output_max_bytes)
                + "\nDo other work and wait again later, or cancel_tool_execution "
                "if it is no longer needed.")

    async def cancel_tool_execution(self, execution_id: str) -> str:
        """Cancel a background tool execution started in this run."""
        from app.services.agent import tool_executions

        execution = self._lookup_execution(execution_id)
        if execution is None:
            return f"No background execution '{execution_id}' in this run."
        if not tool_executions.cancel(execution):
            return f"Execution {execution.id} already {execution.status}; nothing to cancel."
        await tool_executions.wait(execution, 5)
        return f"Execution {execution.id} ({execution.tool_name}) {execution.status}."

    async def list_tool_executions(self) -> str:
        """List background tool executions of this run and their status."""
        from app.services.agent import tool_executions
        from app.services.agent.action_ledger import active_run_id

        rows = tool_executions.run_executions(active_run_id.get() or "")
        if not rows:
            return "No background tool executions in this run."
        return "\n".join(
            "- {execution_id} {tool}: {status} ({elapsed_seconds}s)".format(**e.summary())
            for e in rows
        )

    async def mcp_connect(self, url: str, name: str = "burp") -> str:
        """Attach an external MCP server (Burp, Caido, custom) as agent tools.

        CAI analog: `/mcp load http://localhost:9876/sse burp`. Supports
        streamable HTTP and SSE. Tools become callable via mcp_call.
        """
        import asyncio
        from app.services.agent import mcp_client

        _, org_id = get_tenant_context()
        if not org_id:
            return "Error: organization context required"
        user_id, _ = get_tenant_context()
        from app.services.platform_audit import record as audit

        try:
            result = await asyncio.to_thread(mcp_client.connect, org_id, url, name)
        except Exception as exc:
            audit("mcp.connect", organization_id=org_id, actor=f"user:{user_id}", target=name,
                  outcome="failed", detail={"url": url, "error": str(exc)[:300]})
            return f"MCP connect failed: {exc}"
        audit("mcp.connect", organization_id=org_id, actor=f"user:{user_id}", target=name,
              detail={"url": url, "tools": len(result.get("tools") or [])})
        tools = result.get("tools") or []
        names = ", ".join(t.get("name") or "?" for t in tools[:40]) or "(none listed)"
        return (
            f"Connected MCP server '{result.get('name')}' via {result.get('transport')} "
            f"({len(tools)} tools): {names}. Call mcp_call(server='{result.get('name')}', "
            f"tool='...', arguments={{...}})."
        )

    async def mcp_list(self) -> str:
        """List attached external MCP servers and their tools."""
        from app.services.agent import mcp_client

        _, org_id = get_tenant_context()
        if not org_id:
            return "Error: organization context required"
        sessions = mcp_client.list_sessions(org_id)
        if not sessions:
            return "No external MCP servers attached. Use mcp_connect(url, name)."
        health = {row["name"]: row for row in mcp_client.server_health(org_id)}
        lines = []
        for s in sessions:
            tools = ", ".join(s.get("tools") or []) or "(no tools)"
            state = health.get(s.get("name"), {}).get("state", "closed")
            breaker = "" if state == "closed" else f" (circuit {state})"
            lines.append(f"- {s.get('name')} [{s.get('transport')}] {s.get('url')}{breaker}: {tools}")
        return "\n".join(lines)

    async def mcp_call(
        self,
        server: str,
        tool: str,
        arguments: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Call a tool on an attached MCP server (Burp Repeater, Caido, …)."""
        import asyncio
        from app.services.agent import mcp_client

        _, org_id = get_tenant_context()
        if not org_id:
            return "Error: organization context required"
        try:
            result = await asyncio.to_thread(
                mcp_client.call_tool, org_id, server, tool, arguments or {},
            )
        except Exception as exc:
            return f"mcp_call failed: {exc}"
        text = json.dumps(result, default=str) if not isinstance(result, str) else result
        return text[: int(getattr(settings, "AGENT_TOOL_OUTPUT_MAX_CHARS", 20000) or 20000)]

    async def mcp_disconnect(self, name: str) -> str:
        """Detach an external MCP server."""
        from app.services.agent import mcp_client

        _, org_id = get_tenant_context()
        if not org_id:
            return "Error: organization context required"
        ok = mcp_client.disconnect(org_id, name)
        if ok:
            from app.services.platform_audit import record as audit

            user_id, _ = get_tenant_context()
            audit("mcp.disconnect", organization_id=org_id, actor=f"user:{user_id}", target=name)
        return f"Disconnected '{name}'." if ok else f"No MCP session named '{name}'."
