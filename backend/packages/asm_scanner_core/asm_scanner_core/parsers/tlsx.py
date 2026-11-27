"""tlsx JSON-lines parser with Vanguard's A-F certificate grade.

Ported from Vanguard ``run_tlsx`` / ``_grade_cert``. Fix: tlsx reports
``tls_version`` as ``tls10`` / ``tls11`` (no dot), so Vanguard's
``"1.0" in tls`` checks never fired and legacy protocols were graded A. The
version is normalized first. Days to expiry use the ``now`` argument when
given, so results are reproducible.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from asm_scanner_core.parsers.base import Observation, ParsedResult, iter_json_lines, run_status, strip_ansi

TOOL = "tlsx"


def normalize_tls_version(value: Any) -> str:
    """``tls12`` / ``TLSv1.2`` / ``1.2`` -> ``tls1.2``; ``ssl30`` / ``SSLv3`` -> ``ssl3``."""
    raw = str(value or "").strip().lower().replace("v", "").replace("_", "").replace(" ", "")
    for family in ("tls", "ssl"):
        if raw.startswith(family):
            digits = raw[len(family):].replace(".", "")
            if family == "ssl":
                return f"ssl{digits[:1]}" if digits else "ssl"
            if len(digits) >= 2:
                return f"tls{digits[0]}.{digits[1]}"
            return f"tls{digits}" if digits else "tls"
    if raw[:1].isdigit():
        return f"tls{raw}" if "." in raw else raw
    return raw


def grade_cert(data: Dict[str, Any]) -> str:
    """Heuristic A-F grade from tlsx output fields (Vanguard ``_grade_cert``)."""
    score = 100
    if data.get("expired"):
        score -= 50
    if data.get("self_signed"):
        score -= 40
    if data.get("mismatched"):
        score -= 30
    tls = normalize_tls_version(data.get("tls_version") or data.get("version") or "")
    if tls in ("tls1.0",) or tls.startswith("ssl"):
        score -= 30
    elif tls == "tls1.1":
        score -= 15
    key_size = data.get("public_key_size") or 0
    try:
        key_size = int(key_size)
    except (TypeError, ValueError):
        key_size = 0
    if key_size and key_size < 2048:
        score -= 20
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 65:
        return "C"
    if score >= 50:
        return "D"
    return "F"


def days_to_expiry(not_after: Any, now: Optional[datetime] = None) -> Optional[int]:
    if not not_after:
        return None
    try:
        expiry = datetime.fromisoformat(str(not_after).replace("Z", "+00:00"))
    except ValueError:
        return None
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    return (expiry - (now or datetime.now(timezone.utc))).days


def parse_tlsx(output: str, exit_code: Optional[int] = None, *, timed_out: bool = False,
               now: Optional[datetime] = None, **_context: Any) -> ParsedResult:
    observations: List[Observation] = []
    grades: Dict[str, int] = {}
    for data in iter_json_lines(strip_ansi(output or "")):
        host = str(data.get("host") or "")
        if not host:
            continue
        grade = grade_cert(data)
        grades[grade] = grades.get(grade, 0) + 1
        days_left = days_to_expiry(data.get("not_after"), now)
        severity = "info"
        if grade in ("D", "F"):
            severity = "high"
        elif grade == "C":
            severity = "medium"
        elif data.get("expired") or data.get("self_signed") or data.get("mismatched"):
            severity = "high"
        elif days_left is not None and days_left < 14:
            severity = "low"
        port = str(data.get("port") or "")
        tls = normalize_tls_version(data.get("tls_version") or data.get("version") or "")
        problems = [name for name in ("expired", "self_signed", "mismatched") if data.get(name)]
        observations.append(Observation(
            kind="tls_certificate",
            title=f"TLS grade {grade} ({tls or 'unknown'})" + (f": {', '.join(problems)}" if problems else ""),
            severity=severity, target=f"{host}:{port}" if port else host,
            attributes={"grade": grade, "tls_version": tls, "cipher": data.get("cipher") or "",
                        "days_to_expiry": days_left, "expired": bool(data.get("expired")),
                        "self_signed": bool(data.get("self_signed")),
                        "mismatched": bool(data.get("mismatched")),
                        "issuer": data.get("issuer_cn") or data.get("issuer_org") or "",
                        "subject_cn": data.get("subject_cn") or "",
                        "key_size": data.get("public_key_size") or None},
        ))
    status, reason = run_status(exit_code=exit_code, timed_out=timed_out, have_data=bool(observations))
    counts = {"hosts": len(observations)}
    counts.update({f"grade_{g}": n for g, n in sorted(grades.items())})
    return ParsedResult(tool=TOOL, status=status, observations=observations, counts=counts, reason=reason)
