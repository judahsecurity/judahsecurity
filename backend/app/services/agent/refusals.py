"""Recognise a model refusal, so refusal rates can be measured per role."""

from __future__ import annotations

from typing import Any

_MARKERS = (
    "i can't help", "i cannot help", "i can't assist", "i cannot assist",
    "i'm unable to", "i am unable to", "i'm not able to", "i am not able to",
    "i won't", "i will not", "cannot comply", "can't comply",
    "against my guidelines", "i must decline", "i have to decline",
    "not able to provide", "unable to provide assistance",
    "i can't provide", "i cannot provide",
)


def text_looks_like_refusal(text: str) -> bool:
    low = (text or "").lower()
    return bool(low) and any(marker in low for marker in _MARKERS)


def response_text(response: Any) -> str:
    content = getattr(response, "content", response)
    if isinstance(content, list):
        return "".join(
            str(part.get("text", "")) if isinstance(part, dict) else str(part) for part in content
        )
    return str(content or "")


def is_refusal(response: Any) -> bool:
    """A provider refusal stop reason, or a reply with no JSON that reads as one."""
    metadata = getattr(response, "response_metadata", None) or {}
    if isinstance(metadata, dict):
        reason = str(metadata.get("stop_reason") or metadata.get("finish_reason") or "").lower()
        if reason in {"refusal", "content_filter"}:
            return True
    text = response_text(response)
    return "{" not in text[:2000] and text_looks_like_refusal(text[:2000])
