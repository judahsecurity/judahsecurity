"""
Finding publication gate — Solomon / judge receipts.

Medium+ findings require a prior ``validate_finding`` verdict of SUBMIT.
This mirrors Praetorian's demonstrated-compromise bar (no scanner-only noise).
"""

from __future__ import annotations

import hashlib
import time
from typing import Any, Dict, Optional, Tuple


_GATE_SEVERITIES = frozenset({"critical", "high", "medium"})


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
            "create_finding only if verdict is SUBMIT."
        )
    if receipt.get("verdict") != "SUBMIT":
        return False, f"JUDGE GATE: receipt exists but verdict={receipt.get('verdict')}"
    return True, f"gate_ok:{key}"
