"""Deterministic, bounded Intruder-style mutation planning.

The planner converts captured API traffic into one-field differential tests.
It does not send traffic; execution remains behind the agent confirmation and
assessment-scope gates in ``ToolsManager``.
"""

from __future__ import annotations

import json
import re
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlparse

from app.services.agent.request_mutate import normalize_sample


READ_ONLY_METHODS = {"GET", "HEAD", "OPTIONS"}
ID_FIELDS = re.compile(
    r"(^id$|_id$|Id$|uuid|guid|user|account|owner|tenant|organi[sz]ation|"
    r"customer|invoice|order|project|document|file|site)",
    re.I,
)
URL_FIELDS = re.compile(r"(url|uri|redirect|return|next|callback|webhook|proxy|preview)", re.I)
SEARCH_FIELDS = re.compile(r"(q|query|search|filter|sort|where|name|title|message)", re.I)
PAGE_FIELDS = re.compile(r"(page|offset|limit|size|count|cursor)", re.I)
BOOL_FIELDS = re.compile(r"(enabled|active|admin|debug|include|is[A-Z_])", re.I)


def _candidate_value(field: str, current: Any) -> tuple[str, str, str] | None:
    name = str(field or "")
    value = "" if current is None else str(current)
    if URL_FIELDS.search(name):
        return "ssrf_redirect", "https://example.invalid/aegis-intruder", "URL-fetch/redirect canary"
    if PAGE_FIELDS.search(name):
        return "boundary", "1000", "pagination boundary"
    if BOOL_FIELDS.search(name) or value.lower() in {"true", "false"}:
        return "authorization", "false" if value.lower() == "true" else "true", "boolean trust flag"
    if ID_FIELDS.search(name):
        replacement = str(int(value) + 1) if value.isdigit() else "aegis-adjacent-object"
        return "authorization", replacement, "adjacent-object authorization check"
    if SEARCH_FIELDS.search(name):
        return "injection", "aegis-canary'", "non-destructive parser canary"
    return None


def _body_fields(body: Any) -> Iterable[tuple[str, Any, str]]:
    if not body:
        return []
    text = body if isinstance(body, str) else json.dumps(body)
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return [(str(k), v, "body_json") for k, v in list(parsed.items())[:30]]
    except Exception:
        pass
    return [(str(k), v, "body_form") for k, v in parse_qsl(text, keep_blank_values=True)[:30]]


def plan_intruder_mutations(
    samples: list[dict[str, Any]],
    *,
    fallback_origin: str = "",
    max_mutations: int = 12,
    allow_state_change: bool = False,
    categories: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Build a deduplicated queue of one-field mutations from captured traffic."""
    limit = max(1, min(int(max_mutations or 12), 25))
    selected = {str(c).strip().lower() for c in (categories or []) if str(c).strip()}
    plans: list[dict[str, Any]] = []
    seen: set[tuple[int, str, str, str]] = set()
    skipped_state_changing = 0

    def add(sample_index: int, location: str, field: str, current: Any) -> None:
        candidate = _candidate_value(field, current)
        if not candidate:
            return
        category, value, rationale = candidate
        if selected and category not in selected:
            return
        key = (sample_index, location, field, value)
        if key in seen or len(plans) >= limit:
            return
        seen.add(key)
        plans.append({
            "sample_index": sample_index,
            "location": location,
            "field": field,
            "value": value,
            "category": category,
            "rationale": rationale,
            "compare": True,
        })

    for index, raw in enumerate(samples[:80]):
        if not isinstance(raw, dict):
            continue
        sample = normalize_sample(raw, fallback_origin=fallback_origin)
        method = sample["method"].upper()
        if method not in READ_ONLY_METHODS and not allow_state_change:
            skipped_state_changing += 1
            continue
        if len(plans) >= limit:
            continue

        parsed = urlparse(sample["url"])
        for field, value in parse_qsl(parsed.query, keep_blank_values=True):
            add(index, "query", field, value)

        for field, value, location in _body_fields(sample.get("body")):
            add(index, location, field, value)

        # Numeric/UUID-looking path segments are useful BOLA candidates.
        for segment in [s for s in parsed.path.split("/") if s]:
            if segment.isdigit() or re.fullmatch(r"[0-9a-f-]{16,}", segment, re.I):
                replacement = str(int(segment) + 1) if segment.isdigit() else "00000000-0000-4000-8000-000000000000"
                key = (index, "path", segment, replacement)
                if key not in seen and len(plans) < limit and (not selected or "authorization" in selected):
                    seen.add(key)
                    plans.append({
                        "sample_index": index,
                        "location": "path",
                        "field": segment,
                        "value": replacement,
                        "category": "authorization",
                        "rationale": "adjacent path-object authorization check",
                        "compare": True,
                    })

    return {
        "ok": True,
        "dry_run": True,
        "samples_considered": min(len(samples), 80),
        "mutation_count": len(plans),
        "skipped_state_changing": skipped_state_changing,
        "allow_state_change": bool(allow_state_change),
        "mutations": plans,
        "safety": (
            "Plans use one-field canaries. Execution is scope-checked, rate-bounded, "
            "and confirmation-gated. State-changing methods are excluded by default."
        ),
    }
