"""Session notes, memory, knowledge base, prior sessions and context compaction.

Mixin for ASMToolsManager; methods moved verbatim from tools.py.
"""

from app.services.agent.tools_common import (
    AgentNote,
    Any,
    Optional,
    SessionLocal,
    _tool_output_max_chars,
    current_session_id,
    get_tenant_context,
    json,
    logger,
)


class MemoryToolsMixin:
    """Session notes, memory, knowledge base, prior sessions and context compaction."""

    async def save_note(
        self,
        category: str,
        content: str,
        target: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        """Save a session note (credential, vulnerability, finding, artifact). Uses current org/session from context."""
        user_id, org_id = get_tenant_context()
        session_id = current_session_id.get()
        if not org_id:
            return "Error: No organization context. save_note requires an active session."
        db = SessionLocal()
        try:
            note = AgentNote(
                organization_id=org_id,
                user_id=user_id,
                session_id=session_id,
                category=category.strip().lower() if category else "finding",
                content=content[:10000] if content else "",
                target=target[:512] if target else None,
            )
            db.add(note)
            db.commit()
            return f"Saved note: category={note.category}, target={note.target or 'N/A'}"
        except Exception as e:
            db.rollback()
            logger.exception("save_note failed")
            return f"Error saving note: {e}"
        finally:
            db.close()

    def get_session_notes(
        self,
        session_id: Optional[str] = None,
        category: Optional[str] = None,
    ) -> str:
        """Return formatted session notes for prompt injection. Used by orchestrator or get_notes tool."""
        _, org_id = get_tenant_context()
        if not org_id:
            return "No session notes (no organization context)."
        db = SessionLocal()
        try:
            q = db.query(AgentNote).filter(AgentNote.organization_id == org_id)
            if session_id:
                q = q.filter(AgentNote.session_id == session_id)
            if category:
                q = q.filter(AgentNote.category == category.strip().lower())
            notes = q.order_by(AgentNote.created_at.desc()).limit(50).all()
            if not notes:
                return "No session notes yet."
            lines = []
            for n in notes:
                target_str = f" target={n.target}" if n.target else ""
                lines.append(f"- [{n.category}]{target_str}: {(n.content or '')[:500]}{'...' if len(n.content or '') > 500 else ''}")
            return "\n".join(lines)
        finally:
            db.close()

    async def get_notes(
        self,
        session_id: Optional[str] = None,
        category: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        """Get session notes (optionally filtered by category). Uses current session from context if session_id not provided."""
        sid = session_id or current_session_id.get()
        return self.get_session_notes(session_id=sid, category=category)

    async def search_memory(
        self,
        query: str,
        room: Optional[str] = None,
        limit: int = 5,
        target: Optional[str] = None,
    ) -> str:
        """Semantic search over org-scoped verbatim palace memory.

        Covers RoE/scope docs, prior tool output, specialist diaries, and
        mined knowledge. Pass target to restrict recall to its exact host
        before repeating recon, crawl, WAF, or Nuclei.
        """
        from app.services.agent.palace_memory import search_memory as palace_search

        _, org_id = get_tenant_context()
        if not org_id:
            return json.dumps({"error": "no tenant context"}, indent=2)
        if not query or not str(query).strip():
            return json.dumps({"error": "query is required"}, indent=2)
        rows = palace_search(
            org_id,
            query,
            room=(room or None),
            target=(target or None),
            limit=max(1, min(int(limit or 5), 10)),
        )
        return json.dumps(
            {"query": query, "target": target, "count": len(rows), "results": rows},
            indent=2,
        )[:_tool_output_max_chars()]

    async def store_memory(
        self,
        content: str,
        room: str = "general",
        title: str = "",
        target: Optional[str] = None,
    ) -> str:
        """Store a verbatim (redacted) drawer in this org's palace.

        Use for durable notes that should survive this session: WAF vendor,
        in-scope hosts, killed techniques, confirmed findings.
        """
        from app.services.agent.palace_memory import HALL_FACTS, store_drawer, wing_for_org

        _, org_id = get_tenant_context()
        if not org_id:
            return json.dumps({"error": "no tenant context"}, indent=2)
        if not content or not str(content).strip():
            return json.dumps({"error": "content is required"}, indent=2)
        ids = store_drawer(
            org_id,
            content,
            wing=wing_for_org(org_id),
            room=(room or "general")[:128],
            hall=HALL_FACTS,
            title=title or "",
            source="manual",
            session_id=current_session_id.get() or None,
            target=target,
        )
        return json.dumps({"stored": len(ids), "ids": ids, "room": room or "general"})

    async def search_knowledge_base(
        self,
        query: str,
        limit: int = 5,
    ) -> str:
        """Alias of search_memory — palace search including mined knowledge docs."""
        return await self.search_memory(query=query, limit=limit)

    async def query_prior_sessions(
        self,
        max_chains: int = 5,
        max_findings: int = 15,
        max_failures: int = 10,
    ) -> str:
        """Return a markdown digest of prior sessions, findings and lessons learned
        for the current organization, pulled from the EvoGraph cross-session memory
        (Neo4j). Returns an empty string if Neo4j is unavailable or empty.
        """
        from app.services.agent import evograph
        _user_id, org_id = get_tenant_context()
        session_id = current_session_id.get() or ""
        if not org_id:
            return ""
        return evograph.get_prior_chain_context(
            organization_id=org_id,
            current_session_id=session_id,
            max_chains=max_chains,
            max_findings=max_findings,
            max_failures=max_failures,
        ) or ""

    async def compact_context(self) -> str:
        """Request CAI-style /compact: collapse older execution-trace steps next think."""
        from app.services.agent.run_control import request_compact

        session_id = current_session_id.get() or ""
        if not session_id:
            return "No session to compact."
        request_compact(session_id)
        return "Compact queued. The next reasoning turn will summarize older steps and keep the recent window."

    async def load_prior_hunt(self, source_session_id: str) -> str:
        """Load a prior conversation's compact brief into this hunt (CAI /load)."""
        from app.db.database import SessionLocal
        from app.services.agent.run_control import queue_load_brief
        from app.services.agent.session_ops import load_prior_conversation_brief

        _, org_id = get_tenant_context()
        session_id = current_session_id.get() or ""
        if not org_id or not session_id:
            return "Error: organization/session context required"
        db = SessionLocal()
        try:
            brief = load_prior_conversation_brief(db, org_id, source_session_id)
        finally:
            db.close()
        if not brief:
            return f"No prior hunt found for session {source_session_id}."
        queue_load_brief(session_id, brief)
        return brief[:4000]
