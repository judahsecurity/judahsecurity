"""CAI-style compact and prior-hunt reload helpers for the CLI harness."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List


def compact_message_tool_results(
    messages: List[dict],
    *,
    keep_recent: int = 6,
    max_chars: int = 2000,
) -> List[dict]:
    """Shrink old tool_result payloads without breaking tool_use pairing."""
    tool_idxs = [
        i
        for i, msg in enumerate(messages)
        if msg.get("role") == "user" and isinstance(msg.get("content"), list)
    ]
    shrink = set(tool_idxs[:-keep_recent] if len(tool_idxs) > keep_recent else [])
    if not shrink:
        return messages
    out: List[dict] = []
    for i, msg in enumerate(messages):
        if i not in shrink:
            out.append(msg)
            continue
        content = []
        for block in msg["content"]:
            if isinstance(block, dict) and block.get("type") == "tool_result":
                text = str(block.get("content") or "")
                if len(text) > max_chars:
                    block = {**block, "content": text[:max_chars] + "\n...[compacted]"}
            content.append(block)
        out.append({**msg, "content": content})
    return out


def load_prior_brief(path: str, max_chars: int = 8000) -> str:
    """Load a CAI-style JSONL conversation or Vanguard trace JSON as a brief."""
    p = Path(path)
    text = p.read_text(encoding="utf-8", errors="replace")
    if p.suffix == ".jsonl":
        lines: List[str] = []
        for raw in text.splitlines():
            raw = raw.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError:
                lines.append(raw[:400])
                continue
            role = obj.get("role") or obj.get("type") or "event"
            content = obj.get("content") or obj.get("message") or obj.get("text") or ""
            if isinstance(content, (list, dict)):
                content = json.dumps(content, default=str)[:400]
            lines.append(f"- {role}: {str(content)[:500]}")
        return "\n".join(lines[-40:])[:max_chars]
    if p.suffix == ".json":
        data = json.loads(text)
        if isinstance(data, dict) and "summary" in data:
            return json.dumps(data.get("summary"), indent=2, default=str)[:max_chars]
        return json.dumps(data, indent=2, default=str)[:max_chars]
    return text[:max_chars]


def over_budget(cost_usd: float, limit_usd: float) -> bool:
    if limit_usd <= 0:
        return False
    return float(cost_usd) >= float(limit_usd)
