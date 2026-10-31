"""
Finding publication gate — Solomon / judge receipts.

Medium+ findings require a prior ``validate_finding`` verdict of SUBMIT.
This mirrors Praetorian's demonstrated-compromise bar (no scanner-only noise).
"""

from __future__ import annotations

from app.services.agent.proof_policy import PROOF_GUIDANCE

import hashlib
import time
from typing import Any, Dict, Optional, Tuple


_GATE_SEVERITIES = frozenset({"critical", "high", "medium"})

# Demonstrated-compromise writeup (injected into create_finding / specialist prompts).
# Login success or a Nuclei template hit is a foothold, not a finding.
FINDING_WRITEUP_GUIDANCE = PROOF_GUIDANCE + "\nReport the affected URL, prerequisites, observed impact, redacted execution evidence IDs, remediation, and retest criteria. Separate failed attempts and untested effects from demonstrated results."


FINDING_REVIEW_GUIDANCE = PROOF_GUIDANCE + "\nAssess severity from recorded impact. Explain what is proven, what remains unproven, remediation, and retest criteria. Do not live-retest an existing report unless requested."


def acr_anonymous_pull_signals(text: Optional[str]) -> Dict[str, bool]:
    """Keyword signals for ACR / Docker Registry anonymous-pull findings."""
    t = (text or "").lower()
    is_finding = (
        "azurecr" in t
        or "anonymous pull" in t
        or "anonymouspullenabled" in t
        or "anonymous pull enabled" in t
        or "/v2/_catalog" in t
        or "docker registry" in t
        or (
            "container registry" in t
            and any(s in t for s in ("anonymous", "unauth", "catalog", "oauth2"))
        )
    )
    has_anon_proof = any(
        s in t
        for s in (
            "access_token",
            "anonymous bearer",
            "anonymous token",
            "registry:catalog",
            "repositories",
            "/v2/_catalog",
            "catalog",
        )
    )
    has_secret_class = any(
        s in t
        for s in (
            "ghp_",
            "github pat",
            "personal access token",
            "package-lock",
            "ghs_",
            "artifactory",
            "akcp",
            "nats",
            "git+https",
        )
    )
    live_privileged = has_secret_class and any(
        s in t
        for s in (
            "ghp_",
            "classic personal",
            "write:packages",
            "permissions admin",
            "admin=true",
            "repo, workflow",
            "workflow",
        )
    )
    return {
        "is_finding": is_finding,
        "has_anon_proof": has_anon_proof,
        "has_secret_class": has_secret_class,
        "live_privileged_token": live_privileged,
    }


def normalize_target(target: Optional[str]) -> str:
    t = (target or "").strip().lower()
    if t.startswith(("http://", "https://")):
        try:
            from urllib.parse import urlparse

            p = urlparse(t)
            t = (p.netloc or p.path.split("/")[0] or t).lower()
        except Exception:
            pass
    return t.rstrip("/").split("/")[0].split(":")[0]


def receipt_key(title: str, target: Optional[str]) -> str:
    blob = f"{(title or '').strip().lower()}|{normalize_target(target)}"
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:20]


def severity_requires_gate(severity: Optional[str]) -> bool:
    return (severity or "info").strip().lower() in _GATE_SEVERITIES


_VERIFICATION_LEVELS = frozenset({"source_verified", "exploit_verified"})
_SOURCE_SCANNERS = ("semgrep", "gitleaks", "trivy", "retire.js", "retirejs", "sast")


def classify_verification_level(
    *,
    runtime_confirmed: bool,
    explicit: Optional[str] = None,
    detected_by: Optional[str] = None,
    specialist: Optional[str] = None,
    evidence: Optional[str] = None,
) -> Optional[str]:
    """Label how a finding was verified.

    ``exploit_verified`` means the independent verifier reproduced it against
    the running target. ``source_verified`` means a static / source-only
    finding (SAST) with a reachable-exploit argument but no runtime
    reproduction. A finding not reproduced at runtime can never claim
    ``exploit_verified``, whatever the caller passes. Returns ``None`` when the
    finding is neither runtime-confirmed nor recognizably source-derived.
    """
    if runtime_confirmed:
        return "exploit_verified"
    if (explicit or "").strip().lower() == "source_verified":
        return "source_verified"
    blob = " ".join(x for x in (detected_by, specialist, evidence) if x).lower()
    if (specialist or "").strip().lower() == "code_sast" or any(
        scanner in blob for scanner in _SOURCE_SCANNERS
    ):
        return "source_verified"
    return None


def cap_source_verified_severity(
    severity: Optional[str], verification_level: Optional[str]
) -> Tuple[str, bool]:
    """Bound an un-exploited source finding's agent-published severity.

    A ``source_verified`` finding has no runtime reproduction, so it is not
    filed as high/critical; it is capped at ``medium`` until an exploit proof
    upgrades it. Returns ``(effective_severity, was_capped)``.
    """
    normalized = (severity or "info").strip().lower()
    if verification_level == "source_verified" and normalized in {"critical", "high"}:
        return "medium", True
    return normalized, False


def record_submit_receipt(
    store: Dict[str, Dict[str, Any]],
    *,
    title: str,
    target: Optional[str],
    severity: str,
    score: str,
) -> str:
    key = receipt_key(title, target)
    store[key] = {
        "title": title,
        "target": normalize_target(target),
        "severity": (severity or "").lower(),
        "score": score,
        "verdict": "SUBMIT",
        "ts": time.time(),
    }
    return key


def consume_or_check_receipt(
    store: Dict[str, Dict[str, Any]],
    *,
    title: str,
    target: Optional[str],
    severity: str,
    require: bool = True,
) -> Tuple[bool, str]:
    """Return (ok, message). Does not delete receipts (re-submit allowed)."""
    if not require or not severity_requires_gate(severity):
        return True, "gate_skipped"
    key = receipt_key(title, target)
    receipt = store.get(key)
    if not receipt:
        return False, (
            "JUDGE GATE: medium+ findings require validate_finding → verdict SUBMIT "
            f"for this title/target first (receipt key={key}). "
            "Call validate_finding with the same title/target/evidence, then retry "
            "create_finding only if verdict is SUBMIT. Do not claim the finding exists. "
            "Do not fireteam_dispatch, WPScan, or crawl until this finding is filed."
        )
    if receipt.get("verdict") != "SUBMIT":
        return False, f"JUDGE GATE: receipt exists but verdict={receipt.get('verdict')}"
    return True, f"gate_ok:{key}"
