"""PortSwigger Web Security Academy topic cards for Vanguard hunters."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path


_CATALOG = Path(__file__).with_name("web_security_topics.json")


@lru_cache(maxsize=1)
def topic_playbooks() -> tuple[dict, ...]:
    return tuple(json.loads(_CATALOG.read_text(encoding="utf-8")))


def relevant_playbooks(hunter: str, observations: str) -> tuple[dict, ...]:
    """Select cards whose owner and observed feature cues match this hunter."""
    category = hunter.removesuffix("_hunter")
    observed = observations.lower()
    return tuple(
        row for row in topic_playbooks()
        if row["hunter"] in {category, "all"}
        and (not row["signals"] or any(cue in observed for cue in row["signals"]))
    )


def format_hunter_playbooks(hunter: str, observations: str) -> str:
    rows = relevant_playbooks(hunter, observations)
    if not rows:
        return ""
    lines = ["Web Security Academy topic playbooks selected from observed features:"]
    for row in rows:
        lines.append(f"\n{row['title']} ({row['id']}):")
        lines.append("Mechanism: " + row["summary"])
        for step in row["steps"]:
            lines.append(f"- {step}")
        lines.append("Proof: " + row["pass_signals"][0])
        lines.append("Stop or mark inconclusive: " + row["kill_signals"][0])
        lines.append("Source: " + row["references"][0])
    return "\n".join(lines)
