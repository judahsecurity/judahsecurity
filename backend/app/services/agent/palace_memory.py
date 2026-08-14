"""MemPalace-style verbatim memory for the ASM agent.

Stores original (redacted) text in org-scoped wings / rooms / drawers and
retrieves with hybrid keyword + embedding search. This is the retrieval
layer — it does not replace the engagement brain, finding gate, or EvoGraph.

Two agent tools sit on top of this module: ``search_memory`` and ``store_memory``.
The MemPalace MCP server (44 tools) is intentionally not wired in.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from typing import Any, Optional

from sqlalchemy import or_

from app.db.database import SessionLocal
from app.models.agent_palace import AgentPalaceDrawer

logger = logging.getLogger(__name__)

WAKE_UP_MAX_CHARS = 3600
DRAWER_MAX_CHARS = 4000
TOOL_MAX_CHUNKS = 3
CONVO_MAX_CHUNKS = 2
SEARCH_SHORTLIST = 40

HALL_FACTS = "facts"
HALL_EVENTS = "events"
HALL_DISCOVERIES = "discoveries"

_HASH_DIM = 256


def chunk_text(text: str, max_chars: int = 1200, overlap: int = 150) -> list[str]:
    try:
        from app.services.agent.knowledge_embeddings import chunk_text as _chunk
        return _chunk(text, max_chars=max_chars, overlap=overlap)
    except Exception:
        pass
    text = (text or "").strip()
    if not text:
        return []
    if len(text) <= max_chars:
        return [text]
    chunks = []
    i = 0
    while i < len(text):
        chunks.append(text[i : i + max_chars])
        i += max(1, max_chars - overlap)
    return chunks


def cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = sum(x * x for x in a) ** 0.5
    nb = sum(y * y for y in b) ** 0.5
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def embed(text: str) -> tuple[list[float], str]:
    try:
        from app.services.agent.knowledge_embeddings import embed as _embed
        return _embed(text)
    except Exception:
        pass
    text = (text or "").strip()
    vec = [0.0] * _HASH_DIM
    tokens = re.findall(r"[a-zA-Z0-9_\-]{2,}", text.lower())
    if not tokens:
        return vec, f"hash-bow-{_HASH_DIM}"
    for tok in tokens:
        h = int(hashlib.md5(tok.encode("utf-8")).hexdigest(), 16)
        idx = h % _HASH_DIM
        sign = 1.0 if (h >> 8) & 1 else -1.0
        vec[idx] += sign
    norm = sum(v * v for v in vec) ** 0.5 or 1.0
    return [v / norm for v in vec], f"hash-bow-{_HASH_DIM}"


_STOP_WORDS = {
    "the", "and", "for", "are", "but", "not", "you", "all",
    "can", "had", "her", "was", "one", "our", "out", "has",
    "with", "this", "that", "from", "they", "been", "have",
    "what", "when", "will", "how", "than", "its", "also",
}

# Tools whose outputs are already in Postgres or are memory meta-ops.
_SKIP_REMEMBER = {
    "search_memory",
    "store_memory",
    "search_knowledge_base",
    "query_prior_sessions",
    "get_notes",
    "get_engagement_brain",
    "get_methodology_progress",
    "sanitize_evidence",
    "auto_select_tools",
    "query_assets",
    "query_vulnerabilities",
    "query_ports",
    "query_technologies",
    "query_graph",
    "get_asset_details",
    "analyze_attack_surface",
    "rank_attack_surface",
    "search_cve",
    "search_vulnx",
    "vulnx_query",
    "web_search",
}

_TOOL_ROOMS = {
    "execute_wafw00f": "waf",
    "execute_nuclei": "nuclei",
    "execute_deep_crawl": "crawl",
    "execute_interceptor": "crawl",
    "execute_katana": "crawl",
    "execute_gau": "crawl",
    "execute_waybackurls": "crawl",
    "ingest_urls_into_map": "crawl",
    "execute_subfinder": "recon",
    "execute_subfaster": "recon",
    "execute_amass": "recon",
    "execute_crtsh": "recon",
    "execute_crt_name": "recon",
    "execute_dnsx": "recon",
    "execute_httpx": "recon",
    "execute_whatweb": "recon",
    "execute_wappalyzer": "recon",
    "execute_knockpy": "recon",
    "create_finding": "findings",
    "validate_finding": "findings",
    "compare_requests": "authz",
    "execute_jwt": "authz",
    "bypass_403": "authz",
    "test_credential_spray": "authz",
    "fireteam_dispatch": "fireteam",
    "sync_engagement_brain": "methodology",
}

_WAKE_ROOMS = ("scope_roe", "methodology", "findings", "waf", "diary", "crawl")

_L0_IDENTITY = (
    "Joshua — Judah Security ASM agent. Palace memory is verbatim and org-scoped. "
    "Call search_memory before repeating recon, crawl, WAF, or Nuclei on a target "
    "you may have already assessed."
)

_SECRET_FIELD_RE = re.compile(
    r'(?i)("?(?:password|passwd|pwd|secret|token|access_token|refresh_token|'
    r'authorization|cookie|cookies|storage_state|local_storage|api_key|apikey|'
    r'x-api-key|username|basic_auth|session|sessionid|client_secret)"?\s*[:=]\s*)'
    r'("?)([^",\s&}]{4,})\2'
)
_AWS_KEY_RE = re.compile(r"\bA[KS]IA[0-9A-Z]{16}\b")
_GITHUB_TOKEN_RE = re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)

def _keywords(query: str, limit: int = 6) -> list[str]:
    return [
        w for w in (query or "").lower().split()
        if len(w) >= 3 and w not in _STOP_WORDS
    ][:limit]


def _content_hash(organization_id: Optional[int], wing: str, room: str, content: str) -> str:
    raw = f"{organization_id}|{wing}|{room}|{content}".encode("utf-8", errors="replace")
    return hashlib.sha256(raw).hexdigest()


def redact_for_palace(text: str) -> str:
    """Strip credentials / tokens before a drawer is written."""
    if not text:
        return ""
    sanitized = _PRIVATE_KEY_RE.sub("***REDACTED_PRIVATE_KEY***", text)
    sanitized = _AWS_KEY_RE.sub("***REDACTED_AWS_KEY***", sanitized)
    sanitized = _GITHUB_TOKEN_RE.sub("***REDACTED_GITHUB_TOKEN***", sanitized)
    sanitized = _JWT_RE.sub("***REDACTED_JWT***", sanitized)
    sanitized = _SECRET_FIELD_RE.sub(
        lambda m: m.group(1) + m.group(2) + "***REDACTED***" + m.group(2),
        sanitized,
    )
    return sanitized


def wing_for_org(organization_id: Optional[int]) -> str:
    if organization_id is None:
        return "global"
    return f"org:{organization_id}"


def room_for_tool(tool_name: str) -> str:
    if tool_name in _TOOL_ROOMS:
        return _TOOL_ROOMS[tool_name]
    if tool_name.endswith("_help"):
        return "help"
    if tool_name.startswith("execute_"):
        return "tools"
    return "general"


def room_for_knowledge_tags(tags: Optional[list]) -> str:
    lowered = {str(t).lower() for t in (tags or [])}
    if lowered & {"scope", "roe", "rules", "in-scope", "out-of-scope"}:
        return "scope_roe"
    if lowered & {"methodology", "playbook", "cwe", "capec"}:
        return "methodology"
    if lowered & {"recon", "crawl", "katana", "interceptor"}:
        return "crawl"
    return "knowledge"


def store_drawer(
    organization_id: Optional[int],
    content: str,
    *,
    wing: Optional[str] = None,
    room: str = "general",
    hall: str = HALL_FACTS,
    title: str = "",
    source: str = "manual",
    source_id: Optional[str] = None,
    tool_name: Optional[str] = None,
    session_id: Optional[str] = None,
    target: Optional[str] = None,
) -> list[int]:
    """Persist one or more verbatim drawers. Dedupes by content hash. Returns ids."""
    text = redact_for_palace((content or "").strip())
    if not text:
        return []

    wing = wing or wing_for_org(organization_id)
    title = (title or text[:80].split("\n", 1)[0])[:512]
    target = (target or "")[:512] or None
    chunks = chunk_text(text, max_chars=DRAWER_MAX_CHARS, overlap=120)
    if source == "tool":
        chunks = chunks[:TOOL_MAX_CHUNKS]
    elif source == "conversation":
        chunks = chunks[:CONVO_MAX_CHUNKS]

    ids: list[int] = []
    db = SessionLocal()
    try:
        for i, chunk in enumerate(chunks):
            digest = _content_hash(organization_id, wing, room, chunk)
            existing = (
                db.query(AgentPalaceDrawer)
                .filter(
                    AgentPalaceDrawer.organization_id == organization_id,
                    AgentPalaceDrawer.content_hash == digest,
                )
                .first()
            )
            if existing:
                ids.append(existing.id)
                continue
            chunk_title = title if i == 0 else f"{title} ({i + 1})"
            vec, model = embed(f"{chunk_title}\n{chunk[:2000]}")
            drawer = AgentPalaceDrawer(
                organization_id=organization_id,
                wing=wing,
                room=room,
                hall=hall,
                title=chunk_title[:512],
                content=chunk,
                content_hash=digest,
                source=source,
                source_id=source_id,
                tool_name=tool_name,
                session_id=session_id,
                target=target,
                embedding=vec or None,
                embedding_model=model,
            )
            db.add(drawer)
            db.flush()
            ids.append(drawer.id)
        db.commit()
        return ids
    except Exception:
        db.rollback()
        logger.exception("store_drawer failed")
        return []
    finally:
        db.close()


def search_memory(
    organization_id: int,
    query: str,
    *,
    wing: Optional[str] = None,
    room: Optional[str] = None,
    limit: int = 5,
    max_chars: int = 2400,
) -> list[dict]:
    """Hybrid keyword + embedding search. Org filter is mandatory."""
    if not query or not str(query).strip():
        return []
    if not organization_id:
        return []

    ensure_knowledge_mined(organization_id)
    ensure_conversations_mined(organization_id)

    keywords = _keywords(query)
    db = SessionLocal()
    try:
        tenant = or_(
            AgentPalaceDrawer.organization_id == organization_id,
            AgentPalaceDrawer.organization_id.is_(None),
        )
        q = db.query(AgentPalaceDrawer).filter(tenant)
        if wing:
            q = q.filter(AgentPalaceDrawer.wing == wing)
        if room:
            q = q.filter(AgentPalaceDrawer.room == room)

        shortlist: list[AgentPalaceDrawer] = []
        if keywords:
            kw_filters = []
            for kw in keywords:
                kw_filters.append(AgentPalaceDrawer.title.ilike(f"%{kw}%"))
                kw_filters.append(AgentPalaceDrawer.content.ilike(f"%{kw}%"))
                kw_filters.append(AgentPalaceDrawer.target.ilike(f"%{kw}%"))
            shortlist = (
                q.filter(or_(*kw_filters))
                .order_by(AgentPalaceDrawer.created_at.desc())
                .limit(max(limit * 6, SEARCH_SHORTLIST))
                .all()
            )
        if not shortlist:
            shortlist = (
                q.order_by(AgentPalaceDrawer.created_at.desc())
                .limit(max(limit * 6, SEARCH_SHORTLIST))
                .all()
            )

        q_vec: Optional[list[float]] = None
        if len(query.strip()) >= 8:
            q_vec, _ = embed(query)

        ranked: list[tuple[float, AgentPalaceDrawer]] = []
        for drawer in shortlist:
            # Defense in depth: never return another tenant's row.
            if (
                drawer.organization_id is not None
                and drawer.organization_id != organization_id
            ):
                continue
            score = 0.0
            if q_vec and drawer.embedding:
                score = cosine(q_vec, drawer.embedding)
            blob = f"{drawer.title} {drawer.target or ''} {drawer.content[:2000]}".lower()
            score += 0.06 * sum(1 for kw in keywords if kw in blob)
            if room and drawer.room == room:
                score += 0.05
            ranked.append((score, drawer))

        ranked.sort(key=lambda x: x[0], reverse=True)
        out: list[dict] = []
        total = 0
        for score, drawer in ranked[:limit]:
            snippet = drawer.content[:900]
            if len(drawer.content) > 900:
                snippet += "..."
            row = {
                "id": drawer.id,
                "title": drawer.title,
                "wing": drawer.wing,
                "room": drawer.room,
                "hall": drawer.hall,
                "snippet": snippet,
                "score": round(float(score), 4),
                "source": drawer.source,
                "tool_name": drawer.tool_name,
                "target": drawer.target,
                "created_at": drawer.created_at.isoformat() if drawer.created_at else "",
            }
            out.append(row)
            total += len(snippet) + len(drawer.title)
            if total >= max_chars:
                break
        return out
    except Exception:
        logger.exception("search_memory failed")
        return []
    finally:
        db.close()


def format_search_results(query: str, rows: list[dict]) -> str:
    if not rows:
        return f"No palace memories for {query!r}."
    parts = [f"Palace hits for {query!r} ({len(rows)}):"]
    for r in rows:
        loc = f"{r.get('wing')}/{r.get('room')}"
        tgt = f" target={r['target']}" if r.get("target") else ""
        parts.append(
            f"- [{r.get('title')}] ({loc}{tgt} score={r.get('score')})\n{r.get('snippet')}"
        )
    return "\n\n".join(parts)


def wake_up(
    organization_id: int,
    *,
    target: Optional[str] = None,
    specialist: Optional[str] = None,
    max_chars: int = WAKE_UP_MAX_CHARS,
) -> str:
    """L0 identity + L1 critical facts. Call once per session / specialist."""
    if not organization_id:
        return _L0_IDENTITY

    ensure_knowledge_mined(organization_id)
    ensure_conversations_mined(organization_id)

    parts = [_L0_IDENTITY]
    used = len(_L0_IDENTITY)
    db = SessionLocal()
    try:
        tenant = or_(
            AgentPalaceDrawer.organization_id == organization_id,
            AgentPalaceDrawer.organization_id.is_(None),
        )
        q = db.query(AgentPalaceDrawer).filter(tenant)
        if specialist:
            q = q.filter(
                or_(
                    AgentPalaceDrawer.wing == f"specialist:{specialist}",
                    AgentPalaceDrawer.room.in_(_WAKE_ROOMS),
                )
            )
        else:
            q = q.filter(AgentPalaceDrawer.room.in_(_WAKE_ROOMS))

        drawers = q.order_by(AgentPalaceDrawer.created_at.desc()).limit(30).all()
        if target:
            t = target.lower()
            drawers.sort(
                key=lambda d: (
                    0 if (d.target or "").lower().find(t) >= 0 else 1,
                    0 if t in (d.content or "").lower()[:500] else 1,
                )
            )

        rooms_seen: set[str] = set()
        facts: list[str] = []
        for drawer in drawers:
            if (
                drawer.organization_id is not None
                and drawer.organization_id != organization_id
            ):
                continue
            snippet = drawer.content[:420].strip()
            if not snippet:
                continue
            line = f"- [{drawer.room}] {drawer.title}: {snippet}"
            if used + len(line) > max_chars:
                break
            facts.append(line)
            rooms_seen.add(drawer.room)
            used += len(line)
            if len(facts) >= 8:
                break

        count = (
            db.query(AgentPalaceDrawer)
            .filter(AgentPalaceDrawer.organization_id == organization_id)
            .count()
        )
        if facts:
            parts.append("Critical memories:")
            parts.extend(facts)
        if count:
            rooms = ", ".join(sorted(rooms_seen)) or "general"
            parts.append(
                f"Palace has {count} org drawers (sampled rooms: {rooms}). "
                "Use search_memory for the rest."
            )
        return "\n".join(parts)
    except Exception:
        logger.exception("wake_up failed")
        return _L0_IDENTITY
    finally:
        db.close()


def ensure_knowledge_mined(organization_id: int) -> None:
    """Idempotent backfill of AgentKnowledge into drawers for this org."""
    rows: list[dict] = []
    db = SessionLocal()
    try:
        already = (
            db.query(AgentPalaceDrawer.id)
            .filter(
                AgentPalaceDrawer.organization_id == organization_id,
                AgentPalaceDrawer.source == "knowledge",
            )
            .first()
        )
        global_mined = (
            db.query(AgentPalaceDrawer.id)
            .filter(
                AgentPalaceDrawer.organization_id.is_(None),
                AgentPalaceDrawer.source == "knowledge",
            )
            .first()
        )
        if already and global_mined:
            return
        from app.models.agent_knowledge import AgentKnowledge

        docs = (
            db.query(AgentKnowledge)
            .filter(
                or_(
                    AgentKnowledge.organization_id == organization_id,
                    AgentKnowledge.organization_id.is_(None),
                )
            )
            .all()
        )
        rows = [
            {
                "organization_id": d.organization_id,
                "title": d.title,
                "content": d.content,
                "tags": d.tags or [],
                "id": d.id,
            }
            for d in docs
        ]
    except Exception:
        logger.debug("ensure_knowledge_mined query failed", exc_info=True)
        return
    finally:
        try:
            db.close()
        except Exception:
            pass

    for row in rows:
        org = row["organization_id"]
        if org is not None and org != organization_id:
            continue
        mine_knowledge_doc(
            organization_id=org,
            title=row["title"],
            content=row["content"],
            tags=row["tags"],
            doc_id=row["id"],
        )


def ensure_conversations_mined(organization_id: int) -> None:
    """Idempotent backfill of recent AgentConversation turns into drawers."""
    if not organization_id:
        return
    payloads: list[tuple] = []
    db = SessionLocal()
    try:
        already = (
            db.query(AgentPalaceDrawer.id)
            .filter(
                AgentPalaceDrawer.organization_id == organization_id,
                AgentPalaceDrawer.source == "conversation",
            )
            .first()
        )
        if already:
            return
        from app.models.agent_conversation import AgentConversation

        convs = (
            db.query(AgentConversation)
            .filter(AgentConversation.organization_id == organization_id)
            .order_by(AgentConversation.id.desc())
            .limit(20)
            .all()
        )
        for conv in convs:
            for i, msg in enumerate((conv.messages or [])[-30:]):
                if not isinstance(msg, dict):
                    continue
                payloads.append(
                    (
                        organization_id,
                        msg.get("role") or "",
                        msg.get("content") or "",
                        conv.session_id,
                        f"{conv.session_id}:{i}",
                    )
                )
    except Exception:
        logger.debug("ensure_conversations_mined query failed", exc_info=True)
        return
    finally:
        try:
            db.close()
        except Exception:
            pass

    for org, role, content, session_id, source_id in payloads:
        mine_conversation_turn(
            org,
            role,
            content,
            session_id=session_id,
            source_id=source_id,
        )


def mine_knowledge_doc(
    organization_id: Optional[int],
    title: str,
    content: str,
    tags: Optional[list] = None,
    doc_id: Optional[int] = None,
) -> list[int]:
    return store_drawer(
        organization_id,
        f"{title}\n\n{content}",
        wing=wing_for_org(organization_id),
        room=room_for_knowledge_tags(tags),
        hall=HALL_FACTS,
        title=title or "knowledge",
        source="knowledge",
        source_id=str(doc_id) if doc_id is not None else None,
    )


def _current_tenant() -> tuple[Optional[int], Optional[str]]:
    try:
        from app.services.agent.tools import current_session_id, get_tenant_context

        _uid, org_id = get_tenant_context()
        return org_id, current_session_id.get()
    except Exception:
        return None, None


def remember_tool_result(
    tool_name: str,
    tool_args: Optional[dict],
    result: Optional[dict],
) -> None:
    """Fire-and-forget: persist redacted tool output as drawers."""
    try:
        if not tool_name or tool_name in _SKIP_REMEMBER or tool_name.endswith("_help"):
            return
        org_id, session_id = _current_tenant()
        if not org_id:
            return
        result = result or {}
        output = result.get("output")
        if output is None:
            output = result.get("error") or ""
        if not isinstance(output, str):
            output = str(output)
        output = output.strip()
        if len(output) < 40:
            return
        err = str(result.get("error") or "")
        if any(
            s in output or s in err
            for s in ("Missing required parameter", "policy_denied", "confirmation_denied")
        ):
            return

        success = bool(result.get("success"))
        hall = HALL_DISCOVERIES if success else HALL_EVENTS
        target = _target_from_args(tool_args)
        args_preview = ""
        if isinstance(tool_args, dict):
            raw = tool_args.get("args") or tool_args.get("target") or ""
            if isinstance(raw, str):
                args_preview = raw[:200]
        body = output
        if args_preview:
            body = f"args: {args_preview}\n\n{output}"
        store_drawer(
            org_id,
            body,
            wing=wing_for_org(org_id),
            room=room_for_tool(tool_name),
            hall=hall,
            title=f"{tool_name} {'ok' if success else 'fail'}",
            source="tool",
            tool_name=tool_name,
            session_id=session_id,
            target=target,
        )
    except Exception:
        logger.debug("remember_tool_result skipped", exc_info=True)


def store_specialist_diary(
    organization_id: int,
    specialist: str,
    summary: str,
    key_findings: Optional[list] = None,
    session_id: Optional[str] = None,
    target: Optional[str] = None,
) -> None:
    findings = key_findings or []
    bullets = "\n".join(f"- {x}" for x in findings[:20])
    content = f"{specialist} diary\n\n{summary or ''}\n\n{bullets}".strip()
    if len(content) < 40:
        return
    store_drawer(
        organization_id,
        content,
        wing=f"specialist:{specialist}",
        room="diary",
        hall=HALL_FACTS,
        title=f"{specialist} diary",
        source="specialist_diary",
        session_id=session_id,
        target=target,
    )


def mine_conversation_turn(
    organization_id: Optional[int],
    role: str,
    content: str,
    *,
    session_id: Optional[str] = None,
    source_id: Optional[str] = None,
) -> list[int]:
    """Persist a redacted chat turn. Conversation drawers are search-only, not wake-up."""
    if not organization_id:
        return []
    label = (role or "").strip().lower()
    if label == "assistant":
        label = "agent"
    if label == "human":
        label = "user"
    if label not in ("user", "agent"):
        return []
    text = (content or "").strip()
    if len(text) < 40:
        return []
    return store_drawer(
        organization_id,
        text,
        wing=wing_for_org(organization_id),
        room="conversation",
        hall=HALL_EVENTS,
        title=f"{label} turn",
        source="conversation",
        source_id=source_id,
        session_id=session_id,
    )


def persist_engagement_brain(
    organization_id: Optional[int],
    brain: Optional[dict[str, Any]],
    *,
    session_id: Optional[str] = None,
    target: Optional[str] = None,
) -> list[int]:
    """Store a compact, credential-free brain snapshot in the methodology room."""
    if not organization_id or not isinstance(brain, dict):
        return []

    hyps: list[dict[str, Any]] = []
    for h in (brain.get("hypotheses") or [])[:20]:
        if not isinstance(h, dict):
            continue
        hyps.append(
            {
                "id": h.get("id"),
                "title": h.get("title"),
                "status": h.get("status"),
                "specialist": h.get("specialist"),
                "target": h.get("target"),
                "priority": h.get("priority"),
            }
        )

    approaches: list[dict[str, Any]] = []
    for a in (brain.get("approaches") or [])[:15]:
        if not isinstance(a, dict):
            continue
        approaches.append(
            {
                "technique": a.get("technique"),
                "target": a.get("target"),
                "result": a.get("result"),
            }
        )

    next_steps = brain.get("next_steps") or []
    if isinstance(next_steps, list):
        next_steps = [str(s)[:400] for s in next_steps[:12]]
    else:
        next_steps = []

    findings_raw = brain.get("confirmed_findings") or []
    findings: list[str] = []
    if isinstance(findings_raw, list):
        for item in findings_raw[:12]:
            if isinstance(item, str):
                findings.append(item[:400])
            elif isinstance(item, dict):
                findings.append(str(item.get("title") or item.get("id") or item)[:400])

    notes_raw = brain.get("notes") or []
    notes: list[str] = []
    if isinstance(notes_raw, list):
        notes = [str(n)[:300] for n in notes_raw[:8]]

    if not hyps and not approaches and not next_steps and not findings:
        return []

    creds = brain.get("credentials") or []
    snapshot = {
        "phase": brain.get("phase"),
        "target": brain.get("target") or target,
        "identities": brain.get("identities") or [],
        "credential_count": len(creds) if isinstance(creds, list) else 0,
        "hypotheses": hyps,
        "approaches": approaches,
        "next_steps": next_steps,
        "confirmed_findings": findings,
        "notes": notes,
    }
    tgt = snapshot.get("target")
    tgt_str = tgt[:512] if isinstance(tgt, str) and tgt.strip() else None
    return store_drawer(
        organization_id,
        json.dumps(snapshot, indent=2, default=str),
        wing=wing_for_org(organization_id),
        room="methodology",
        hall=HALL_FACTS,
        title="engagement brain snapshot",
        source="engagement_brain",
        source_id=session_id,
        session_id=session_id,
        target=tgt_str,
    )


_URL_RE = re.compile(r"https?://[^\s\"']+", re.I)
_HOST_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)


def _target_from_args(tool_args: Optional[dict]) -> Optional[str]:
    if not isinstance(tool_args, dict):
        return None
    for key in ("target", "url", "host", "domain"):
        val = tool_args.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()[:512]
    args = tool_args.get("args")
    if isinstance(args, str):
        m = _URL_RE.search(args)
        if m:
            return m.group(0).rstrip(").,;]")[:512]
        m = _HOST_RE.search(args)
        if m:
            return m.group(0)[:512]
    return None
