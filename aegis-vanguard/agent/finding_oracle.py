"""
Finding oracle — the proof gate.

The flag oracle proved one thing (a CTF flag) from real output. This
generalizes that discipline to *every* finding: a finding may only be reported
as CONFIRMED if it carries a machine-checkable **proof token** produced by a
tool during the run — otherwise it is downgraded to NEEDS_EVIDENCE, no matter
how confident the agent's prose is. This is the gate that makes "confirmed"
mean the same thing to the harness and to a human.

Proof-token kinds and their producers:

  flag          — a benchmark/CTF flag captured in a real tool response
                  (agent.flag_oracle; consulted directly here).
  response_diff — a replay under a changed/absent identity returned the same
                  private content (broken-access-control signature)
                  (replay_request → ProofLedger).
  browser_exec  — a payload actually executed JS in a real browser
                  (test_dom_xss → ProofLedger).
  oob           — an out-of-band callback fired with a unique nonce (blind
                  SSRF/RCE/XXE). Taxonomy reserved; producer lands with the OOB
                  oracle.

A token counts only when `verified=True`. Producers set that flag only when the
evidence actually meets the bar, so registering a token is itself an assertion
of proof, not a hint.
"""

import json
import logging
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlsplit

logger = logging.getLogger("agent.finding_oracle")

CONFIRMED = "CONFIRMED"
NEEDS_EVIDENCE = "NEEDS_EVIDENCE"
REFUTED = "REFUTED"


# ── Proof tokens & ledger ──────────────────────────────────────────────────
@dataclass
class ProofToken:
    token_id: str
    kind: str            # flag | response_diff | browser_exec | oob
    verified: bool
    subject: str = ""    # normalized target key for correlation
    detail: str = ""     # redacted evidence excerpt / the flag / diff summary
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)


def normalize_subject(url_or_endpoint: str) -> str:
    """host+path, lowercased, query dropped — the key findings correlate on."""
    if not url_or_endpoint:
        return ""
    s = str(url_or_endpoint).strip()
    if "://" in s:
        parts = urlsplit(s)
        return f"{parts.netloc}{parts.path}".rstrip("/").lower()
    return s.split("?")[0].rstrip("/").lower()


class ProofLedger:
    """Thread-safe sink for proof tokens registered by tools during a run."""

    def __init__(self):
        self._tokens: List[ProofToken] = []
        self._counter = 0
        self._lock = threading.Lock()

    def add(self, kind: str, verified: bool, subject: str = "", detail: str = "") -> ProofToken:
        with self._lock:
            self._counter += 1
            token = ProofToken(
                token_id=f"proof-{self._counter:04d}",
                kind=kind,
                verified=bool(verified),
                subject=normalize_subject(subject),
                detail=str(detail)[:500],
            )
            self._tokens.append(token)
        if verified:
            logger.info("PROOF: %s verified for %s (%s)", kind, token.subject, token.token_id)
        return token

    def all(self) -> List[ProofToken]:
        with self._lock:
            return list(self._tokens)

    def verified(self) -> List[ProofToken]:
        with self._lock:
            return [t for t in self._tokens if t.verified]


# ── Singletons ─────────────────────────────────────────────────────────────
_LEDGER: Optional[ProofLedger] = None
_LOCK = threading.Lock()


def get_proof_ledger() -> ProofLedger:
    global _LEDGER
    if _LEDGER is None:
        with _LOCK:
            if _LEDGER is None:
                _LEDGER = ProofLedger()
    return _LEDGER


def set_proof_ledger(ledger: ProofLedger) -> ProofLedger:
    global _LEDGER
    with _LOCK:
        _LEDGER = ledger
    return ledger


def reset_proof_ledger() -> None:
    global _LEDGER
    with _LOCK:
        _LEDGER = None


def register_proof(kind: str, verified: bool, subject: str = "", detail: str = "") -> ProofToken:
    """Convenience for producers: record a proof token in the shared ledger."""
    return get_proof_ledger().add(kind, verified, subject=subject, detail=detail)


# ── Grading ────────────────────────────────────────────────────────────────
@dataclass
class FindingVerdict:
    status: str                       # CONFIRMED | NEEDS_EVIDENCE | REFUTED
    proof_token_ids: List[str]
    reason: str

    @property
    def confirmed(self) -> bool:
        return self.status == CONFIRMED

    def to_dict(self) -> dict:
        d = asdict(self)
        d["confirmed"] = self.confirmed
        return d


def _finding_subjects(finding: dict) -> List[str]:
    subs = []
    for key in ("endpoint", "url", "location", "target", "path"):
        v = finding.get(key)
        if isinstance(v, str) and v.strip():
            subs.append(normalize_subject(v))
    return [s for s in subs if s]


def _finding_text(finding: dict) -> str:
    try:
        return json.dumps(finding, default=str)
    except Exception:
        return str(finding)


def _flag_proofs() -> List[ProofToken]:
    """Adapt flag-oracle captures into flag proof tokens (no coupling needed)."""
    try:
        from agent.flag_oracle import get_flag_oracle
        caps = get_flag_oracle().captures
    except Exception:
        return []
    return [
        ProofToken(token_id=f"flag-{i}", kind="flag", verified=True,
                   subject=normalize_subject(c.argument_summary.split("=", 1)[-1]),
                   detail=c.flag)
        for i, c in enumerate(caps)
    ]


def _subjects_correlate(a: str, b: str) -> bool:
    if not a or not b:
        return False
    return a == b or a.endswith(b) or b.endswith(a)


def grade_finding(finding: dict, proofs: Optional[List[ProofToken]] = None) -> FindingVerdict:
    """Confirm a finding only if a verified proof token backs it.

    A token backs a finding when: the finding cites its id (proof_token_id),
    OR the token's subject correlates with the finding's endpoint/url, OR a
    flag token's flag string appears in the finding.
    """
    if proofs is None:
        proofs = get_proof_ledger().verified() + _flag_proofs()

    cited = str(finding.get("proof_token_id") or "").strip()
    subjects = _finding_subjects(finding)
    text = _finding_text(finding)

    matched: List[str] = []
    for tok in proofs:
        if not tok.verified:
            continue
        if cited and cited == tok.token_id:
            matched.append(tok.token_id)
            continue
        if tok.subject and any(_subjects_correlate(tok.subject, s) for s in subjects):
            matched.append(tok.token_id)
            continue
        if tok.kind == "flag" and tok.detail and tok.detail in text:
            matched.append(tok.token_id)

    if matched:
        return FindingVerdict(CONFIRMED, sorted(set(matched)),
                              "backed by verified proof token(s)")
    return FindingVerdict(
        NEEDS_EVIDENCE, [],
        "no machine-checkable proof token — claim rests on prose; run the "
        "matching oracle (replay_request / test_dom_xss / flag capture / OOB) "
        "to earn CONFIRMED",
    )


def grade_findings(findings: List[dict],
                   proofs: Optional[List[ProofToken]] = None) -> dict:
    """Grade every finding; return counts + per-finding verdicts."""
    if proofs is None:
        proofs = get_proof_ledger().verified() + _flag_proofs()

    results = []
    confirmed = 0
    for f in findings or []:
        v = grade_finding(f, proofs)
        if v.confirmed:
            confirmed += 1
        results.append({
            "title": f.get("title") or f.get("name") or "(untitled)",
            "severity": f.get("severity", "unknown"),
            "claimed_confidence": f.get("confidence") or f.get("cross_validated"),
            "verdict": v.to_dict(),
        })
    return {
        "total": len(findings or []),
        "confirmed": confirmed,
        "needs_evidence": len(findings or []) - confirmed,
        "verified_proof_tokens": [t.to_dict() for t in proofs],
        "results": results,
    }


_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]


def build_findings_document(findings: List[dict],
                            target: Optional[str] = None,
                            proofs: Optional[List[ProofToken]] = None) -> dict:
    """Grade every finding and produce the documented-findings record.

    This is the content of the `findings.json` artifact: each finding carries
    its gate verdict (CONFIRMED + proof tokens, or NEEDS_EVIDENCE), so a
    documented finding cannot claim more certainty than a tool actually earned.
    """
    if proofs is None:
        proofs = get_proof_ledger().verified() + _flag_proofs()

    documented = []
    for f in findings or []:
        v = grade_finding(f, proofs)
        documented.append({
            "title": f.get("title") or f.get("name") or "(untitled)",
            "severity": str(f.get("severity", "unknown")).lower(),
            "vuln_type": f.get("vuln_type") or f.get("type"),
            "endpoint": f.get("endpoint") or f.get("url") or f.get("location") or "",
            "description": f.get("description") or f.get("evidence") or "",
            "claimed_confidence": f.get("confidence")
            or ("cross_validated" if f.get("cross_validated") else None),
            "verification": v.to_dict(),
        })
    confirmed = sum(1 for d in documented if d["verification"]["confirmed"])
    return {
        "target": target,
        "total": len(documented),
        "confirmed": confirmed,
        "needs_evidence": len(documented) - confirmed,
        "verified_proof_tokens": [t.to_dict() for t in proofs],
        "findings": documented,
    }


def findings_markdown(doc: dict) -> str:
    """Render the VULN-FINDINGS.md document, grouped by severity, gate-aware."""
    lines = [
        f"# Findings — {doc.get('target') or 'assessment'}",
        "",
        f"**{doc['confirmed']} of {doc['total']} findings carry a verified proof "
        f"token** ({doc['needs_evidence']} NEEDS_EVIDENCE, reported for triage).",
        "",
    ]
    by_sev = {s: [] for s in _SEVERITY_ORDER}
    for d in doc["findings"]:
        by_sev.setdefault(d["severity"], by_sev["unknown"]).append(d)
    for sev in _SEVERITY_ORDER:
        group = by_sev.get(sev) or []
        if not group:
            continue
        lines.append(f"## {sev.capitalize()} ({len(group)})")
        lines.append("")
        for d in group:
            v = d["verification"]
            badge = "✅ CONFIRMED" if v["confirmed"] else "⚠️ NEEDS_EVIDENCE"
            proof = ", ".join(v["proof_token_ids"]) or "none"
            lines.append(f"### {d['title']}  — {badge}")
            if d["endpoint"]:
                lines.append(f"- **Endpoint:** `{d['endpoint']}`")
            lines.append(f"- **Proof:** {proof}")
            if not v["confirmed"]:
                lines.append(f"- **Gate:** {v['reason']}")
            if d["description"]:
                lines.append(f"- {str(d['description'])[:500]}")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def proof_gate_markdown(report: dict) -> str:
    """Deterministic report section — generated, not LLM prose."""
    lines = [
        "## Proof Gate",
        "",
        f"**{report['confirmed']} of {report['total']} findings carry a verified "
        f"proof token.** The rest are NEEDS_EVIDENCE — reported for triage, not as "
        f"confirmed, until an oracle backs them.",
        "",
        "| Finding | Severity | Gate | Proof |",
        "|---|---|---|---|",
    ]
    for r in report["results"]:
        v = r["verdict"]
        badge = "✅ CONFIRMED" if v["confirmed"] else "⚠️ NEEDS_EVIDENCE"
        proof = ", ".join(v["proof_token_ids"]) or "—"
        title = str(r["title"]).replace("|", "\\|")[:80]
        lines.append(f"| {title} | {r['severity']} | {badge} | {proof} |")
    return "\n".join(lines)
