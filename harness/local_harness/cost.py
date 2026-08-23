"""Load Vanguard trace summaries next to harness artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional


def load_trace_summary(out_dir: Path) -> Optional[Dict[str, Any]]:
    """Return the latest trace_*.json summary written into ``out_dir``."""
    traces = sorted(Path(out_dir).glob("trace_*.json"))
    if not traces:
        return None
    try:
        data = json.loads(traces[-1].read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    summary = data.get("summary") if isinstance(data, dict) else None
    return summary if isinstance(summary, dict) else None


def cost_metrics(
    summary: Optional[Dict[str, Any]],
    *,
    finding_count: int,
    true_positives: int = 0,
) -> Dict[str, Any]:
    cost = float((summary or {}).get("estimated_cost_usd") or 0)
    tokens = (summary or {}).get("tokens") or {}
    return {
        "cost_usd": round(cost, 6),
        "input_tokens": int(tokens.get("input") or tokens.get("input_tokens") or 0),
        "output_tokens": int(tokens.get("output") or tokens.get("output_tokens") or 0),
        "cost_per_finding": round(cost / finding_count, 6) if finding_count else None,
        "cost_per_true_positive": round(cost / true_positives, 6) if true_positives else None,
    }
