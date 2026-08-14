"""Build Praetorian-style scanner Detection payloads from Nuclei results.

Surfaces the raw request, cURL, response, matched URL, matcher DSL, and
template YAML that confirmed a finding — not an agent demonstrated-compromise
chain.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Optional

logger = logging.getLogger(__name__)

MAX_DUMP_CHARS = 256_000

_CURL_RE = re.compile(
    r"Reproduction:\s*```(?:[a-zA-Z0-9_-]+)?\n(.*?)```",
    re.DOTALL,
)
_MATCHED_AT_RE = re.compile(r"Matched at:\s*(\S+)")

_PROTOCOLS = (
    "http",
    "dns",
    "tcp",
    "network",
    "ssl",
    "websocket",
    "headless",
    "javascript",
    "code",
    "whois",
)

_MATCHER_VALUE_KEYS = (
    "dsl",
    "words",
    "regex",
    "status",
    "size",
    "binary",
    "xpath",
    "part",
)


def as_dump_text(value: Any, limit: int = MAX_DUMP_CHARS) -> str:
    """Normalize Nuclei request/response dumps to a truncated string."""
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray)):
        text = value.decode("utf-8", errors="replace")
    elif isinstance(value, str):
        text = value
    elif isinstance(value, dict):
        text = (
            value.get("raw")
            or value.get("dump")
            or value.get("body")
            or json.dumps(value, indent=2, default=str)
        )
        if not isinstance(text, str):
            text = str(text)
    elif isinstance(value, list):
        text = "\n".join(as_dump_text(item, limit=0) for item in value)
    else:
        text = str(value)
    text = text.replace("\r\n", "\n").strip("\n")
    if limit and len(text) > limit:
        return text[:limit] + "\n… [truncated]"
    return text


def collect_matchers(template: Any) -> list[dict[str, Any]]:
    """Walk a parsed Nuclei template for matcher blocks."""
    if not isinstance(template, dict):
        return []
    matchers: list[dict[str, Any]] = []
    for proto in _PROTOCOLS:
        blocks = template.get(proto)
        if not blocks:
            continue
        if isinstance(blocks, dict):
            blocks = [blocks]
        if not isinstance(blocks, list):
            continue
        for block in blocks:
            if not isinstance(block, dict):
                continue
            raw = block.get("matchers") or []
            if isinstance(raw, dict):
                raw = [raw]
            for matcher in raw:
                if isinstance(matcher, dict):
                    matchers.append(matcher)
    return matchers


def format_matcher(matcher: dict[str, Any]) -> str:
    """Render one matcher the way Praetorian shows Match Criteria."""
    mtype = str(matcher.get("type") or "matcher").strip() or "matcher"
    values: list[str] = []
    typed = matcher.get(mtype)
    if isinstance(typed, list):
        values = [str(v) for v in typed]
    elif typed is not None and not isinstance(typed, (dict, bool)):
        values = [str(typed)]
    if not values:
        for key in _MATCHER_VALUE_KEYS:
            raw = matcher.get(key)
            if isinstance(raw, list) and raw:
                values = [str(v) for v in raw]
                if key != mtype:
                    mtype = key
                break
            if raw is not None and not isinstance(raw, (dict, bool, list)):
                values = [str(raw)]
                if key != mtype:
                    mtype = key
                break
    if not values and matcher.get("name"):
        values = [str(matcher["name"])]
    body = "\n".join(values) if values else ""
    if body:
        return f"{mtype} :\n{body}"
    return f"{mtype} :"


def extract_match_criteria(
    template_yaml: Optional[str] = None,
    matcher_name: Optional[str] = None,
) -> str:
    """Build Match Criteria text from template YAML and/or matcher name."""
    matchers: list[dict[str, Any]] = []
    if template_yaml:
        try:
            import yaml

            parsed = yaml.safe_load(template_yaml)
            matchers = collect_matchers(parsed)
        except Exception as exc:
            logger.debug("Could not parse template YAML for match criteria: %s", exc)

    selected = matchers
    name = (matcher_name or "").strip()
    if name and matchers:
        named = [m for m in matchers if str(m.get("name") or "") == name]
        if named:
            selected = named
    if selected and not name:
        confirming = [m for m in selected if not m.get("internal")]
        if confirming:
            selected = confirming

    parts = [format_matcher(m) for m in selected]
    if parts:
        return "\n\n".join(parts)
    if name:
        return f"matcher :\n{name}"
    return ""


_yaml_cache: dict[str, str] = {}


def lookup_template_yaml_cached(
    template_id: Optional[str] = None,
    template_path: Optional[str] = None,
) -> str:
    """Read template YAML from disk, caching by template id for a scan batch."""
    tid = (template_id or "").strip()
    if tid and tid in _yaml_cache:
        return _yaml_cache[tid]
    text = read_template_yaml(template_path)
    if not text and tid:
        try:
            from app.services.nuclei_template_parser_service import find_matching_nuclei_template

            match = find_matching_nuclei_template(tid)
            if match and match.template_path:
                text = read_template_yaml(match.template_path)
        except Exception as exc:
            logger.debug("Could not look up Nuclei template %s: %s", tid, exc)
    if tid:
        _yaml_cache[tid] = text or ""
    return text or ""


def read_template_yaml(template_path: Optional[str] = None) -> str:
    """Read YAML from the Nuclei-reported template path when present."""
    if not template_path:
        return ""
    try:
        from pathlib import Path

        path = Path(template_path)
        if path.is_file():
            return path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        logger.debug("Could not read Nuclei template at %s: %s", template_path, exc)
    return ""


def compact_detection(payload: dict[str, Any]) -> dict[str, Any]:
    """Drop empty keys so list responses stay small."""
    return {k: v for k, v in payload.items() if v not in (None, "", [], {})}


def build_nuclei_detection(nuclei_result: Any) -> dict[str, Any]:
    """Build a Detection blob from a live NucleiResult."""
    template_path = getattr(nuclei_result, "template_path", None) or ""
    template_yaml = as_dump_text(
        getattr(nuclei_result, "template_yaml", None)
        or lookup_template_yaml_cached(
            getattr(nuclei_result, "template_id", None),
            template_path,
        ),
        limit=MAX_DUMP_CHARS,
    )
    matcher_name = getattr(nuclei_result, "matcher_name", None) or ""
    curl_command = as_dump_text(getattr(nuclei_result, "curl_command", None), limit=MAX_DUMP_CHARS)
    request = as_dump_text(getattr(nuclei_result, "request", None))
    response = as_dump_text(getattr(nuclei_result, "response", None))
    match = (getattr(nuclei_result, "matched_at", None) or "").strip()
    match_criteria = extract_match_criteria(template_yaml, matcher_name)

    return compact_detection(
        {
            "request": request,
            "curl_command": curl_command,
            "response": response,
            "match": match,
            "match_criteria": match_criteria,
            "template_id": getattr(nuclei_result, "template_id", None) or "",
            "template_yaml": template_yaml,
            "matcher_name": matcher_name,
        }
    )


def detection_from_evidence(
    *,
    evidence: Optional[str] = None,
    matcher_name: Optional[str] = None,
    template_id: Optional[str] = None,
    matched_at: Optional[str] = None,
    metadata: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Best-effort Detection for findings ingested before request dumps were stored."""
    meta = metadata if isinstance(metadata, dict) else {}
    stored = meta.get("detection")
    if isinstance(stored, dict) and stored:
        merged = dict(stored)
        if not merged.get("match"):
            merged["match"] = (
                matched_at
                or meta.get("nuclei_matched_at")
                or merged.get("match")
                or ""
            )
        if not merged.get("matcher_name") and matcher_name:
            merged["matcher_name"] = matcher_name
        if not merged.get("template_id") and template_id:
            merged["template_id"] = template_id
        if not merged.get("match_criteria"):
            merged["match_criteria"] = extract_match_criteria(
                merged.get("template_yaml"),
                merged.get("matcher_name") or matcher_name,
            )
        return compact_detection(merged)

    text = evidence or ""
    curl = ""
    curl_match = _CURL_RE.search(text)
    if curl_match:
        curl = curl_match.group(1).strip()

    match = (matched_at or meta.get("nuclei_matched_at") or "").strip()
    if not match:
        m = _MATCHED_AT_RE.search(text)
        if m:
            match = m.group(1).strip()

    template_yaml = ""
    if isinstance(meta.get("detection"), dict):
        template_yaml = meta["detection"].get("template_yaml") or ""

    return compact_detection(
        {
            "curl_command": curl,
            "match": match,
            "match_criteria": extract_match_criteria(template_yaml, matcher_name),
            "template_id": template_id or "",
            "template_yaml": template_yaml,
            "matcher_name": matcher_name or "",
        }
    )


def scanner_detection_for_vulnerability(
    vuln: Any,
    *,
    include_dumps: bool = True,
) -> Optional[dict[str, Any]]:
    """Surface Detection on scanner (Nuclei) findings; skip agent chains."""
    detected_by = (getattr(vuln, "detected_by", None) or "").lower()
    if detected_by in {"agent", "llm_red_team"}:
        return None

    meta = getattr(vuln, "metadata_", None)
    if not isinstance(meta, dict):
        meta = {}

    has_scanner_signal = bool(
        getattr(vuln, "template_id", None)
        or detected_by in {"nuclei", "scanner"}
        or meta.get("detection")
        or meta.get("nuclei_matched_at")
    )
    if not has_scanner_signal:
        return None

    payload = detection_from_evidence(
        evidence=getattr(vuln, "evidence", None),
        matcher_name=getattr(vuln, "matcher_name", None),
        template_id=getattr(vuln, "template_id", None),
        matched_at=None,
        metadata=meta,
    )
    if not payload:
        return None
    if not include_dumps:
        payload = compact_detection(
            {k: v for k, v in payload.items() if k not in ("request", "response", "template_yaml")}
        )
    return payload or None
