"""
JavaScript attack-surface analyzer — DOM XSS sinks/sources + secrets.

Recall is where real-world hunts fail: a taint flow you never see is a bug you
never report. This mines collected JS for two high-value, real-world classes:

  • DOM XSS candidates — an attacker-controllable *source* (location.hash/search,
    URLSearchParams, postMessage, window.name, cookie) reaching a dangerous
    *sink* (innerHTML, eval, document.write, location assign) in the same file.
    Each candidate is a LEAD that aims `test_dom_xss` — which produces the
    browser_exec proof token. Static analysis finds it; the browser proves it.
  • Secrets — hardcoded keys/tokens, via the secrets-patterns-db corpus
    (mazen160/secrets-patterns-db, ~1600 patterns; vendored at
    data/secrets_patterns.json). Sink/source regexes are ports of jxscout's AST
    analyzers (github.com/francisconeves97/jxscout).

Leads are never auto-confirmed — they are NEEDS_EVIDENCE until a prover
(test_dom_xss for a sink flow, a live check for a secret) earns a proof token.
This is the recall half; the proof gate is the precision half.
"""

import json
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("agent.js_recon")

_PATTERNS_PATH = Path(__file__).resolve().parent.parent / "data" / "secrets_patterns.json"
_MAX_MATCHES_PER_PATTERN = 5
_MAX_SECRET_SCAN_BYTES = 4_000_000

# DOM sink/source regexes (ports of jxscout's AST analyzers), each tagged as an
# attacker-controllable SOURCE, a dangerous SINK, or a NETWORK call.
_ROLE_SINK, _ROLE_SOURCE, _ROLE_NETWORK = "sink", "source", "network"
DOM_PATTERNS = {
    # sinks — where untrusted data becomes code/markup/navigation
    "eval": (r"\beval\s*\(|new\s+Function\s*\(", _ROLE_SINK),
    "innerHTML": (r"\.(?:inner|outer)HTML\s*=|insertAdjacentHTML\s*\(|document\.write(?:ln)?\s*\(", _ROLE_SINK),
    "dangerouslySetInnerHTML": (r"dangerouslySetInnerHTML", _ROLE_SINK),
    "location-sink": (r"location\s*\.\s*(?:href|assign|replace)\s*[=(]|(?:window|document)\.location\s*=", _ROLE_SINK),
    "window.open": (r"window\.open\s*\(", _ROLE_SINK),
    "document.domain": (r"document\.domain\s*=", _ROLE_SINK),
    "postMessage-send": (r"\.postMessage\s*\(", _ROLE_SINK),
    # sources — attacker-controllable inputs
    "message-listener": (r"addEventListener\s*\(\s*[\"']message[\"']|\.onmessage\s*=", _ROLE_SOURCE),
    "hashchange": (r"addEventListener\s*\(\s*[\"']hashchange[\"']|\.onhashchange\s*=", _ROLE_SOURCE),
    "location-read": (r"location\s*\.\s*(?:hash|search|href|pathname)\b|document\.URL\b|document\.referrer\b", _ROLE_SOURCE),
    "url-search-params": (r"new\s+URLSearchParams\b|\.searchParams\b", _ROLE_SOURCE),
    "window.name": (r"window\.name\b", _ROLE_SOURCE),
    "cookie": (r"document\.cookie\b", _ROLE_SOURCE),
    "storage": (r"\b(?:local|session)Storage\s*\.\s*getItem\s*\(", _ROLE_SOURCE),
    # network — surface, not a sink itself
    "fetch": (r"\bfetch\s*\(", _ROLE_NETWORK),
    "xhr": (r"new\s+XMLHttpRequest\b|\.open\s*\(\s*[\"'](?:GET|POST|PUT|DELETE|PATCH|OPTIONS)[\"']", _ROLE_NETWORK),
    "graphql": (r"gql\s*`|[\"'`]\s*(?:query|mutation|subscription)\s+\w+", _ROLE_NETWORK),
}
_DOM_COMPILED = {k: (re.compile(v, re.IGNORECASE), role) for k, (v, role) in DOM_PATTERNS.items()}


def _line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def scan_js_for_sinks(js_text: str, filename: str = "") -> List[dict]:
    """Return DOM sink/source/network hits: {type, role, line, snippet, file}."""
    hits: List[dict] = []
    for stype, (rx, role) in _DOM_COMPILED.items():
        count = 0
        for m in rx.finditer(js_text):
            ln = _line_of(js_text, m.start())
            snippet = js_text[max(0, m.start() - 20): m.start() + 60].replace("\n", " ").strip()
            hits.append({"type": stype, "role": role, "line": ln,
                         "snippet": snippet, "file": filename})
            count += 1
            if count >= _MAX_MATCHES_PER_PATTERN:
                break
    return hits


_secret_patterns_cache: Optional[List[tuple]] = None


def load_secret_patterns(path: Optional[str] = None) -> List[tuple]:
    global _secret_patterns_cache
    if path is None and _secret_patterns_cache is not None:
        return _secret_patterns_cache
    p = Path(path) if path else _PATTERNS_PATH
    if not p.exists():
        logger.warning("secrets DB not found at %s", p)
        return []
    out = []
    for e in json.loads(p.read_text(encoding="utf-8")):
        try:
            out.append((e["name"], re.compile(e["pattern"])))
        except (re.error, KeyError):
            continue
    if path is None:
        _secret_patterns_cache = out
    return out


def scan_js_for_secrets(js_text: str, patterns: Optional[List[tuple]] = None) -> List[dict]:
    """Return secret hits: {name, match, file}. Regex leads, not proof."""
    if patterns is None:
        patterns = load_secret_patterns()
    if len(js_text) > _MAX_SECRET_SCAN_BYTES:
        return []
    found: List[dict] = []
    seen = set()
    for name, rx in patterns:
        count = 0
        for m in rx.finditer(js_text):
            val = (m.group(0) or "").strip()
            if not val or len(val) > 200:
                continue
            key = (name, val)
            if key in seen:
                continue
            seen.add(key)
            found.append({"name": name, "match": val})
            count += 1
            if count >= _MAX_MATCHES_PER_PATTERN:
                break
    return found


def _xss_candidates(sinks: List[dict]) -> List[dict]:
    """A file with both a source and a dangerous sink is a DOM XSS candidate."""
    by_file: Dict[str, Dict[str, list]] = {}
    for h in sinks:
        slot = by_file.setdefault(h["file"], {"sink": [], "source": []})
        if h["role"] in ("sink", "source"):
            slot[h["role"]].append(h)
    leads = []
    for fname, slot in by_file.items():
        if slot["sink"] and slot["source"]:
            src = ", ".join(sorted({h["type"] for h in slot["source"]}))
            snk = ", ".join(sorted({h["type"] for h in slot["sink"]}))
            leads.append({
                "title": f"DOM XSS candidate in {fname or 'inline script'}",
                "vuln_type": "dom_xss_candidate",
                "severity": "medium",
                "confidence": "lead",
                "file": fname,
                "sources": src,
                "sinks": snk,
                "evidence": f"source(s) [{src}] and sink(s) [{snk}] co-located in {fname}",
                "aim": "run test_dom_xss on pages that load this bundle, injecting into "
                       "the source (URL hash/query/param) to earn a browser_exec proof",
            })
    return leads


def analyze_js(js_by_name: Dict[str, str], with_secrets: bool = True) -> dict:
    """Analyze a set of {name: js_content}: sinks, secrets, and XSS leads.

    Everything returned is a LEAD (NEEDS_EVIDENCE) that aims a prover — nothing
    here is auto-confirmed.
    """
    all_sinks: List[dict] = []
    all_secrets: List[dict] = []
    patterns = load_secret_patterns() if with_secrets else []
    for name, content in js_by_name.items():
        if not content:
            continue
        all_sinks.extend(scan_js_for_sinks(content, filename=name))
        if with_secrets:
            for s in scan_js_for_secrets(content, patterns):
                all_secrets.append({**s, "file": name})

    leads = _xss_candidates(all_sinks)
    by_role: Dict[str, int] = {}
    for h in all_sinks:
        by_role[h["role"]] = by_role.get(h["role"], 0) + 1
    return {
        "files_scanned": len(js_by_name),
        "sinks_by_role": by_role,
        "dom_xss_candidates": leads,
        "secrets": all_secrets,
        "sinks": all_sinks,
        "summary": (f"{len(leads)} DOM XSS candidate(s), {len(all_secrets)} secret "
                    f"lead(s) across {len(js_by_name)} file(s). Leads are "
                    f"NEEDS_EVIDENCE — prove with test_dom_xss / a live secret check."),
    }
