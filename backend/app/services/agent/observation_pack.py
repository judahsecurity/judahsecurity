"""Bound large model observations while retaining a stored evidence handle."""

from __future__ import annotations

import re


_ARTIFACT_ID = re.compile(r"[0-9a-f]{32}\Z")


def project_observation(output: str, *, artifact_id: str = "", max_chars: int = 6000) -> str:
    """Show the beginning and end of a long result; keep stored text recallable."""
    text = str(output or "")
    if max_chars <= 0:
        return ""
    if len(text) <= max_chars:
        return text
    if not _ARTIFACT_ID.fullmatch(artifact_id or "") or max_chars < 400:
        return text[:max_chars]
    marker = (
        f"\n...[{len(text)} chars; middle omitted. "
        f"read_evidence(evidence_id='{artifact_id}', offset=...) for stored redacted text]...\n"
    )
    available = max_chars - len(marker)
    if available < 100:
        return text[:max_chars]
    head = (available * 2) // 3
    tail = available - head
    return text[:head] + marker + text[-tail:]
