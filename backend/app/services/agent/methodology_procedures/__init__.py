"""
Methodology procedure packs — short "how to test" cards.

Layered with methodology_catalog (WHAT) and palace (deep HOW):
  - Catalog seeds hypothesis cards from observations
  - These packs inject compact Burp-style procedures when a card is open
  - search_memory(room="methodologies") remains available for longer notes

Packs live as JSON under methodology_procedures/packs/{id}.json
"""

from __future__ import annotations

import json
import logging
import os
from functools import lru_cache
from typing import Any, Dict, List, Optional, Sequence

logger = logging.getLogger(__name__)

_PACKS_DIR = os.path.join(os.path.dirname(__file__), "packs")

# Soft cap so specialists don't drown in procedure text
_MAX_PACKS_IN_PROMPT = 3
_MAX_STEPS = 8


def packs_dir() -> str:
    return _PACKS_DIR


@lru_cache(maxsize=1)
def list_procedure_ids() -> tuple:
    """Return sorted methodology ids that have a procedure pack on disk."""
    if not os.path.isdir(_PACKS_DIR):
        return tuple()
    ids = []
    for name in os.listdir(_PACKS_DIR):
        if name.endswith(".json") and not name.startswith("_"):
            ids.append(name[:-5])
    return tuple(sorted(ids))


def clear_procedure_cache() -> None:
    list_procedure_ids.cache_clear()
    load_procedure.cache_clear()


@lru_cache(maxsize=128)
def load_procedure(methodology_id: str) -> Optional[Dict[str, Any]]:
    """Load one procedure pack by methodology id. Returns None if missing."""
    mid = (methodology_id or "").strip()
    if not mid or "/" in mid or ".." in mid:
        return None
    path = os.path.join(_PACKS_DIR, f"{mid}.json")
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return None
        data.setdefault("id", mid)
        return data
    except Exception as e:
        logger.warning("failed to load procedure pack %s: %s", mid, e)
        return None


def procedures_for_ids(
    methodology_ids: Sequence[str],
    *,
    limit: int = _MAX_PACKS_IN_PROMPT,
) -> List[Dict[str, Any]]:
    """Load packs for the given ids (deduped, first-wins order)."""
    out: List[Dict[str, Any]] = []
    seen = set()
    for mid in methodology_ids or []:
        if not mid or mid in seen:
            continue
        seen.add(mid)
        pack = load_procedure(mid)
        if pack:
            out.append(pack)
        if len(out) >= limit:
            break
    return out


def format_procedure_block(pack: Dict[str, Any]) -> str:
    """Format a single pack for specialist / agent prompts."""
    mid = pack.get("id") or "?"
    title = pack.get("title") or mid
    summary = (pack.get("summary") or "").strip()
    steps = list(pack.get("steps") or [])[:_MAX_STEPS]
    tools = list(pack.get("tools") or [])[:12]
    pass_s = list(pack.get("pass_signals") or [])[:4]
    kill_s = list(pack.get("kill_signals") or [])[:4]
    refs = list(pack.get("references") or [])[:4]

    lines = [f"PROCEDURE PACK — {title} (`{mid}`)"]
    if summary:
        lines.append(f"Summary: {summary}")
    if steps:
        lines.append("Steps:")
        for i, s in enumerate(steps, 1):
            lines.append(f"  {i}. {s}")
    if tools:
        lines.append(f"Preferred tools: {', '.join(tools)}")
    if pass_s:
        lines.append("PASS signals: " + "; ".join(pass_s))
    if kill_s:
        lines.append("KILL signals: " + "; ".join(kill_s))
    if refs:
        lines.append("Refs: " + "; ".join(str(r) for r in refs))
    lines.append(
        "Stay bounded: one variable at a time; status 200 alone is never a finding."
    )
    return "\n".join(lines)


def format_procedures_for_prompt(
    methodology_ids: Sequence[str],
    *,
    limit: int = _MAX_PACKS_IN_PROMPT,
) -> str:
    """Concatenate procedure blocks for open methodology cards."""
    packs = procedures_for_ids(methodology_ids, limit=limit)
    if not packs:
        return ""
    return "\n\n".join(format_procedure_block(p) for p in packs)


def procedures_summary_for_brain(
    methodology_ids: Sequence[str],
    *,
    limit: int = 6,
) -> List[Dict[str, Any]]:
    """Compact list for sync_engagement_brain / get_methodology_progress JSON."""
    packs = procedures_for_ids(methodology_ids, limit=limit)
    return [
        {
            "id": p.get("id"),
            "title": p.get("title"),
            "summary": p.get("summary"),
            "steps": (p.get("steps") or [])[:5],
            "tools": (p.get("tools") or [])[:8],
            "has_pack": True,
        }
        for p in packs
    ]
