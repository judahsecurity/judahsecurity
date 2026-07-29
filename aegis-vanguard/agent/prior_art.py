"""
Prior Art Search — keyword-search over a curated technique knowledge base.

Hunters call search_prior_art(query, category) before testing a surface to get
proven payloads, target patterns, and bypass notes from the knowledge base.

The knowledge base is data/techniques.json relative to the aegis-vanguard root.
"""
from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("agent.prior_art")

_KB_PATH = (
    Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    / "data"
    / "techniques.json"
)

_kb: Optional[List[dict]] = None


def _load_kb() -> List[dict]:
    global _kb
    if _kb is not None:
        return _kb
    try:
        _kb = json.loads(_KB_PATH.read_text())
        logger.debug("prior_art: loaded %d techniques from %s", len(_kb), _KB_PATH)
    except Exception as exc:
        logger.warning("prior_art: could not load %s — %s", _KB_PATH, exc)
        _kb = []
    return _kb


def search(query: str, category: str = "", top_k: int = 8) -> List[Dict[str, Any]]:
    """Search the technique knowledge base.

    Scoring:
      +3 per query token that matches ``category`` field
      +2 per query token that matches ``name`` or ``subcategory``
      +1 per query token that matches any other field (description, patterns, payloads)

    Returns up to ``top_k`` results sorted by descending relevance score.
    """
    kb = _load_kb()
    if not kb:
        return []

    # Tokenise query into lower-case words (no stop words — security terms matter)
    tokens = [t.lower() for t in re.split(r"[\s,_/-]+", query) if len(t) >= 2]
    if not tokens:
        return []

    # Optional hard filter on category
    cat_filter = category.lower().strip() if category else ""

    scored: List[tuple[int, dict]] = []
    for entry in kb:
        if cat_filter and entry.get("category", "").lower() != cat_filter:
            continue

        score = 0
        entry_category = entry.get("category", "").lower()
        entry_name = entry.get("name", "").lower()
        entry_sub = entry.get("subcategory", "").lower()
        entry_text = json.dumps(entry).lower()

        for tok in tokens:
            if tok in entry_category:
                score += 3
            if tok in entry_name or tok in entry_sub:
                score += 2
            elif tok in entry_text:
                score += 1

        if score > 0:
            scored.append((score, entry))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [e for _, e in scored[:top_k]]


def format_results(results: List[Dict[str, Any]]) -> str:
    """Format search results as a compact markdown string for agent consumption."""
    if not results:
        return "No matching techniques found in the knowledge base."
    lines: List[str] = [f"Found {len(results)} technique(s) from the prior-art knowledge base:\n"]
    for r in results:
        lines.append(f"### [{r.get('id', '?')}] {r.get('name', 'Unnamed')} ({r.get('category', '')})")
        if r.get("description"):
            lines.append(f"**Description**: {r['description']}")
        if r.get("target_params"):
            lines.append(f"**Target params**: {', '.join(r['target_params'][:8])}")
        if r.get("target_patterns"):
            lines.append(f"**Look for**: {'; '.join(r['target_patterns'][:4])}")
        payloads = r.get("payloads", [])
        if payloads:
            lines.append(f"**Payloads** ({len(payloads)} total):")
            for p in payloads[:5]:
                lines.append(f"  - `{p}`")
        if r.get("indicators"):
            lines.append(f"**Success indicators**: {'; '.join(r['indicators'][:3])}")
        if r.get("bypass_notes"):
            lines.append(f"**Bypass notes**: {r['bypass_notes']}")
        lines.append(f"**Impact**: {r.get('impact', 'unknown')}")
        lines.append("")
    return "\n".join(lines)
