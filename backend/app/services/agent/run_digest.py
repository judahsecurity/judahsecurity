"""Shared, summarised run digest so parallel specialists stop repeating recon.

Prowl isolates specialists on purpose: each gets a fresh context and returns
only a summary contract. That keeps contexts clean but means a specialist
cannot see that a sibling already fetched ``/api/orders`` or killed an
injection idea a minute ago.

This digest is the middle ground. The *program* (never the model) appends one
short, redacted line per specialist action and per specialist outcome. Other
specialists in the same run can search it with the read-only
``search_run_digest`` tool. Entries are leads, not evidence: they carry
evidence IDs for orientation but can never satisfy a proof or verifier gate,
and a specialist never sees its own entries echoed back.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from contextvars import ContextVar
from typing import Any, Iterable, Optional
from urllib.parse import urlsplit

MAX_ENTRIES = 400
MAX_SUMMARY = 200

current_specialist: ContextVar[str] = ContextVar("current_specialist", default="")

_URL_KEYS = ("url", "target", "endpoint", "base_url", "host", "origin")


def _redact(text: Any, limit: int = MAX_SUMMARY) -> str:
    from app.services.agent.observability import redact_string

    return redact_string(" ".join(str(text or "").split()))[:limit]


def target_from_args(args: Optional[dict]) -> str:
    """Origin + path of the first URL-like argument; query strings are dropped."""
    for key in _URL_KEYS:
        value = (args or {}).get(key)
        if not isinstance(value, str) or not value.strip():
            continue
        raw = value.strip()
        try:
            parts = urlsplit(raw if "://" in raw else f"https://{raw}")
        except ValueError:
            continue
        if parts.hostname:
            return f"{parts.scheme}://{parts.netloc}{parts.path or '/'}"[:300]
    return ""


class RunDigest:
    def __init__(self, max_entries: int = MAX_ENTRIES):
        self._entries: deque[dict] = deque(maxlen=max_entries)
        self._lock = threading.Lock()
        self._seq = 0

    def add(self, *, kind: str, specialist: str, summary: str, target: str = "",
            tool: str = "", verdict: str = "", hypothesis_ids: Iterable[str] = (),
            evidence_ids: Iterable[str] = ()) -> None:
        with self._lock:
            self._seq += 1
            self._entries.append({
                "seq": self._seq,
                "at": round(time.time(), 3),
                "kind": kind,
                "specialist": str(specialist or "orchestrator")[:64],
                "tool": str(tool or "")[:64],
                "target": _redact(target, 300),
                "summary": _redact(summary),
                "verdict": str(verdict or "")[:32],
                "hypothesis_ids": [str(h)[:64] for h in hypothesis_ids][:8],
                "evidence_ids": [str(e)[:32] for e in evidence_ids][:8],
            })

    def search(self, *, query: str = "", kind: str = "", exclude_specialist: str = "",
               limit: int = 20) -> list[dict]:
        needle = (query or "").strip().lower()
        with self._lock:
            entries = list(self._entries)
        out = []
        for entry in reversed(entries):
            if exclude_specialist and entry["specialist"] == exclude_specialist:
                continue
            if kind and entry["kind"] != kind:
                continue
            if needle and needle not in " ".join(
                (entry["target"], entry["summary"], entry["tool"], entry["specialist"], entry["verdict"])
            ).lower():
                continue
            out.append(dict(entry))
            if len(out) >= limit:
                break
        return out

    def __len__(self) -> int:
        return len(self._entries)


def run_digest(manager: Any) -> RunDigest:
    digest = getattr(manager, "_run_digest", None)
    if digest is None:
        digest = RunDigest()
        manager._run_digest = digest
    return digest


def record_tool_attempt(manager: Any, tool_name: str, args: Optional[dict], *, success: bool,
                        evidence_ids: Iterable[str] = (), error: str = "") -> None:
    """One line per specialist tool call. HTTP exchanges show method, path and status."""
    try:
        specialist = current_specialist.get()
        if not specialist or tool_name in _READ_ONLY_TOOLS:
            return
        evidence_ids = list(evidence_ids)
        summary = ""
        target = target_from_args(args)
        if evidence_ids:
            from app.services.agent.evidence_store import evidence_store

            parts = []
            store = evidence_store(manager)
            for artifact_id in evidence_ids[:4]:
                record = store.records.get(artifact_id) if artifact_id in store.records else None
                payload = (record or {}).get("payload") or {}
                request = payload.get("request") or {}
                response = payload.get("response") or {}
                if request:
                    url = target_from_args({"url": request.get("url")}) or target
                    target = target or url
                    parts.append(
                        f"{request.get('method', 'GET')} {url} -> {response.get('status', '?')}"
                        f" ({response.get('length', '?')} B, {request.get('identity') or 'anonymous'})"
                    )
            summary = "; ".join(parts)
        if not summary:
            summary = f"{tool_name} {'ok' if success else 'failed'}" + (f": {error}" if error and not success else "")
        hypothesis = str((args or {}).get("hypothesis_id") or "")
        run_digest(manager).add(
            kind="tried", specialist=specialist, tool=tool_name, target=target, summary=summary,
            verdict="ok" if success else "failed", hypothesis_ids=[hypothesis] if hypothesis else [],
            evidence_ids=evidence_ids,
        )
    except Exception:
        pass


def record_specialist_outcome(manager: Any, report: Any, targets: Iterable[str] = ()) -> None:
    """One line per finished specialist: verdict plus up to three short key findings."""
    try:
        findings = [str(f)[:120] for f in (getattr(report, "key_findings", None) or [])[:3]]
        summary = "; ".join(findings) or str(getattr(report, "evidence", "") or "")[:200] or "no key findings"
        evidence = [e for inv in (getattr(report, "tool_calls", None) or []) for e in (inv.evidence_ids or [])]
        run_digest(manager).add(
            kind="outcome", specialist=getattr(report, "specialist", ""),
            target=next(iter(targets), ""), summary=summary,
            verdict=getattr(report, "verdict", "") or ("error" if getattr(report, "error", None) else ""),
            hypothesis_ids=getattr(report, "hypothesis_ids", None) or [],
            evidence_ids=evidence[-8:],
        )
    except Exception:
        pass


_READ_ONLY_TOOLS = frozenset({
    "search_run_digest", "read_evidence", "search_memory", "list_test_identities",
    "get_assessment_coverage", "list_proof_captures", "list_authorization_leads", "search_traffic",
})
