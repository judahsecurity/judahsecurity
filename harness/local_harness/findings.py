"""
Loading and normalization of scanner findings.

The Aegis Vanguard scanner emits findings as JSON lines when
``AEGIS_FINDINGS_SINK`` is set (see ``aegis-vanguard/asm_bridge.py``). This
module reads that artifact and normalizes it into a shape the batch collector
and the benchmark judge can reason about.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# Recon/inventory finding types that are NOT vulnerabilities. Excluded from
# benchmark precision/recall scoring (they're attack-surface data, not defects).
NON_VULN_TYPES = {
    "subdomain",
    "domain",
    "ip_address",
    "port",
    "url",
    "technology",
    "mail_infrastructure",
    "third_party_vendor",
    "tls_analysis",
    "security_header",
}

# Keyword → canonical vulnerability category. First match wins.
_CATEGORY_PATTERNS: List[tuple] = [
    ("sqli", r"\bsql[\s-]?injection\b|\bsqli\b"),
    ("xss", r"\bxss\b|cross[\s-]?site[\s-]?script"),
    ("ssrf", r"\bssrf\b|server[\s-]?side[\s-]?request"),
    ("rce", r"\brce\b|remote[\s-]?code[\s-]?exec|command[\s-]?injection"),
    ("idor", r"\bidor\b|insecure[\s-]?direct[\s-]?object|broken[\s-]?object[\s-]?level"),
    ("lfi", r"\blfi\b|local[\s-]?file[\s-]?inclusion|path[\s-]?traversal|directory[\s-]?traversal"),
    ("ssti", r"\bssti\b|template[\s-]?injection"),
    ("xxe", r"\bxxe\b|xml[\s-]?external[\s-]?entity"),
    ("csrf", r"\bcsrf\b|cross[\s-]?site[\s-]?request[\s-]?forgery"),
    ("open_redirect", r"open[\s-]?redirect"),
    ("auth", r"\bauth(entication)?[\s-]?bypass\b|broken[\s-]?auth|weak[\s-]?password|jwt"),
    ("authz", r"\bauthorization\b|privilege[\s-]?escalation|access[\s-]?control"),
    ("takeover", r"takeover"),
    ("deserialization", r"deserializ"),
    ("info_disclosure", r"information[\s-]?disclosure|sensitive[\s-]?data|secret|api[\s-]?key"),
]


def categorize(text: str) -> str:
    """Map free text (title/type/tags) to a canonical vulnerability category."""
    low = (text or "").lower()
    for category, pattern in _CATEGORY_PATTERNS:
        if re.search(pattern, low):
            return category
    return "other"


@dataclass
class NormalizedFinding:
    """A scanner finding reduced to the fields the judge/collector need."""

    title: str
    type: str
    severity: str
    category: str
    host: Optional[str] = None
    url: Optional[str] = None
    endpoint: Optional[str] = None
    confidence: str = "info"
    cve_id: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_vulnerability(self) -> bool:
        return self.type not in NON_VULN_TYPES

    @property
    def is_confirmed(self) -> bool:
        return self.confidence == "confirmed" or "confirmed" in self.tags


def _endpoint_from(raw: Dict[str, Any]) -> Optional[str]:
    poc = (raw.get("raw_data") or {}).get("poc") or {}
    return poc.get("endpoint") or raw.get("url")


def normalize(raw: Dict[str, Any]) -> NormalizedFinding:
    title = raw.get("title") or raw.get("template_id") or raw.get("type") or "unknown"
    ftype = raw.get("type") or "unknown"
    tags = raw.get("tags") or []
    category_source = " ".join(
        str(x) for x in [title, ftype, " ".join(tags), raw.get("template_id", "")]
    )
    return NormalizedFinding(
        title=title,
        type=ftype,
        severity=(raw.get("severity") or "info").lower(),
        category=categorize(category_source),
        host=raw.get("host"),
        url=raw.get("url"),
        endpoint=_endpoint_from(raw),
        confidence=(raw.get("confidence") or "info").lower(),
        cve_id=raw.get("cve_id"),
        tags=list(tags),
        raw=raw,
    )


def load_findings(path: Path) -> List[NormalizedFinding]:
    """Read a JSONL findings sink file into normalized findings."""
    path = Path(path)
    if not path.exists():
        return []
    out: List[NormalizedFinding] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(normalize(json.loads(line)))
            except json.JSONDecodeError:
                continue
    return out


def vulnerabilities(findings: List[NormalizedFinding]) -> List[NormalizedFinding]:
    """Filter to true vulnerability findings (excludes recon/inventory)."""
    return [f for f in findings if f.is_vulnerability]


def severity_counts(findings: List[NormalizedFinding]) -> Dict[str, int]:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts
