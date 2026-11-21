"""Retrieval for org-scoped agent knowledge (hybrid keyword + embedding RAG)."""

from __future__ import annotations

import logging
import re
from typing import Optional

from sqlalchemy import or_

from app.db.database import SessionLocal
from app.models.agent_knowledge import AgentKnowledge
from app.services.agent.knowledge_embeddings import (
    cosine,
    embed,
    reindex_doc,
)

logger = logging.getLogger(__name__)


_STOP_WORDS = {
    "the", "and", "for", "are", "but", "not", "you", "all",
    "can", "had", "her", "was", "one", "our", "out", "has",
    "with", "this", "that", "from", "they", "been", "have",
    "what", "when", "will", "how", "than", "its", "also",
}


def _keywords(query: str, limit: int = 5) -> list[str]:
    return [
        w for w in (query or "").lower().split()
        if len(w) >= 3 and w not in _STOP_WORDS
    ][:limit]


# Security vocabulary: abbreviations and their spelled-out / sibling terms.
# Used to rewrite a query into a few variants (multi-query retrieval) without
# an extra model call.
_SYNONYM_GROUPS = (
    ("sqli", "sql injection", "sql"),
    ("xss", "cross-site scripting", "cross site scripting"),
    ("idor", "bola", "insecure direct object reference", "broken object level authorization"),
    ("ssrf", "server-side request forgery", "server side request forgery"),
    ("rce", "remote code execution", "command injection"),
    ("lfi", "path traversal", "directory traversal", "local file inclusion"),
    ("ssti", "server-side template injection", "template injection"),
    ("csrf", "cross-site request forgery", "xsrf"),
    ("jwt", "json web token"),
    ("xxe", "xml external entity"),
    ("ato", "account takeover"),
    ("mfa", "2fa", "multi-factor authentication"),
    ("cve", "vulnerability", "advisory"),
    ("waf", "web application firewall"),
    ("cors", "cross-origin resource sharing"),
    ("nosqli", "nosql injection"),
)
MAX_QUERY_VARIANTS = 3


def query_variants(query: str) -> list[str]:
    """The query plus up to two rewrites that swap security terms for synonyms."""
    text = " ".join((query or "").lower().split())
    variants = [text]
    for group in _SYNONYM_GROUPS:
        for term in group:
            pattern = r"(?<![a-z0-9])" + re.escape(term) + r"(?![a-z0-9])"
            if re.search(pattern, text):
                for alt in group:
                    if alt != term:
                        candidate = re.sub(pattern, alt, text, count=1)
                        if candidate not in variants:
                            variants.append(candidate)
                break
        if len(variants) >= MAX_QUERY_VARIANTS:
            break
    return variants[:MAX_QUERY_VARIANTS]


def intent_terms(query: str) -> list[str]:
    """Every synonym of the security terms the query mentions."""
    text = " ".join((query or "").lower().split())
    terms: list[str] = []
    for group in _SYNONYM_GROUPS:
        if any(re.search(r"(?<![a-z0-9])" + re.escape(t) + r"(?![a-z0-9])", text) for t in group):
            terms.extend(group)
    return terms


# A document naming the query's security concept (in any spelling) outranks
# one that only shares incidental words with it.
INTENT_BONUS = 0.25


def search_knowledge(
    organization_id: int,
    query: str,
    limit: int = 5,
    max_chars: int = 1800,
) -> list[dict]:
    """Hybrid retrieval: keyword shortlist then embedding rerank.

    Returns a list of structured rows ``{id,title,snippet,score,source}``.
    """
    if not query or not query.strip():
        return []

    db = SessionLocal()
    try:
        base_filter = or_(
            AgentKnowledge.organization_id == organization_id,
            AgentKnowledge.organization_id.is_(None),
        )

        # Phase 1 - keyword shortlist (wide net), widened by query rewrites
        variants = query_variants(query)
        intents = intent_terms(query)
        keywords = list(dict.fromkeys(
            kw for variant in variants for kw in _keywords(variant)))[:10]
        shortlist: list[AgentKnowledge] = []
        if keywords:
            kw_filters = []
            for kw in keywords:
                kw_filters.append(AgentKnowledge.title.ilike(f"%{kw}%"))
                kw_filters.append(AgentKnowledge.content.ilike(f"%{kw}%"))
            shortlist = (
                db.query(AgentKnowledge)
                .filter(base_filter, or_(*kw_filters))
                .order_by(AgentKnowledge.updated_at.desc())
                .limit(max(limit * 5, 20))
                .all()
            )

        if not shortlist:
            shortlist = (
                db.query(AgentKnowledge)
                .filter(base_filter)
                .order_by(AgentKnowledge.updated_at.desc())
                .limit(max(limit * 5, 20))
                .all()
            )

        # Phase 2 - embedding rerank (only when the query is long enough for
        # semantic signal to be meaningful)
        q_vecs: list[list[float]] = []
        if len(query.strip()) >= 8:
            for variant in variants:
                vec, _ = embed(variant)
                if vec:
                    q_vecs.append(vec)
                if not q_vecs:
                    break  # embeddings unavailable; don't retry per variant

        ranked: list[tuple[float, AgentKnowledge, str]] = []
        for doc in shortlist:
            score = 0.0
            reason = "keyword"
            if q_vecs:
                doc_vec = doc.embedding
                if not doc_vec:
                    doc_vec = reindex_doc(doc)
                    try:
                        db.commit()
                    except Exception:
                        db.rollback()
                if doc_vec:
                    # Best match across the original query and its rewrites.
                    score = max(cosine(vec, doc_vec) for vec in q_vecs)
                    reason = "semantic"

            # Keyword score floor so title-hits always surface
            text_lower = f"{doc.title} {doc.content[:2000]}".lower()
            keyword_hits = sum(1 for kw in keywords if kw in text_lower)
            score += 0.05 * keyword_hits
            if intents and any(
                    re.search(r"(?<![a-z0-9])" + re.escape(t) + r"(?![a-z0-9])", text_lower)
                    for t in intents):
                score += INTENT_BONUS
            ranked.append((score, doc, reason))

        ranked.sort(key=lambda x: x[0], reverse=True)

        out: list[dict] = []
        total = 0
        for score, doc, reason in ranked[:limit]:
            if total >= max_chars:
                break
            snippet = _best_snippet(doc.content, keywords, max_len=800)
            out.append({
                "id": doc.id,
                "title": doc.title,
                "snippet": snippet,
                "score": round(float(score), 4),
                "source": reason,
                "tags": doc.tags or [],
            })
            total += len(snippet) + len(doc.title)
        return out
    except Exception as exc:
        logger.exception("search_knowledge failed: %s", exc)
        return []
    finally:
        db.close()


def _best_snippet(content: str, keywords: list[str], max_len: int = 800) -> str:
    if not content:
        return ""
    content = content.strip()
    if not keywords or len(content) <= max_len:
        return content[:max_len] + ("..." if len(content) > max_len else "")

    lower = content.lower()
    idx = -1
    for kw in keywords:
        pos = lower.find(kw)
        if pos != -1:
            idx = pos
            break
    if idx == -1:
        return content[:max_len] + "..."

    start = max(0, idx - max_len // 3)
    end = min(len(content), start + max_len)
    prefix = "..." if start > 0 else ""
    suffix = "..." if end < len(content) else ""
    return f"{prefix}{content[start:end]}{suffix}"


def retrieve_knowledge(
    organization_id: int,
    query: str,
    limit: int = 5,
    max_chars: int = 1500,
) -> str:
    """Legacy string-format retrieval for system-prompt injection. Uses the
    same hybrid ranker under the hood and concatenates the top snippets.
    """
    rows = search_knowledge(organization_id, query, limit=limit, max_chars=max_chars)
    if not rows:
        return ""
    parts = []
    for r in rows:
        parts.append(f"[{r['title']}] (score={r['score']}, src={r['source']})\n{r['snippet']}")
    return "\n\n".join(parts)
