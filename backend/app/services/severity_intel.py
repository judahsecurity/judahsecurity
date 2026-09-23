"""
Live exploitation intelligence for the severity evaluation.

Oracle's exploitation evidence is captured when it enriches a finding and
refreshed on its TTL (days). New exploitation — a CVE added to a KEV list, a
public or weaponized exploit appearing, a Nuclei template being published —
should re-score findings as soon as the platform's intel feeds pick it up.

This module reads the same local caches the intel refresher maintains
(Delphi KEV feeds, the VulnCheck exploit index, the Nuclei CVE index), with no
network calls, and:

  • ``live_intel(cve)`` returns exploitation fields in Oracle's evidence
    shape, merged into the finding's evidence by the evaluator;
  • ``intel_signature(intel)`` is a short hash of those fields, stored on
    each finding (``sev_intel_sig``) when it is evaluated;
  • ``mark_intel_changes(db)`` — run by the intel refresher after every feed
    refresh — marks dirty every open finding whose CVE's signature changed,
    so the severity worker re-scores it on its next tick.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_index_cache: Dict[str, tuple] = {}  # source -> (mtime, entries)


def _index(source: str) -> Dict[str, Any]:
    """Entries of a cached external index, reloaded only when the file changes."""
    from app.services import external_vuln_indexes as idx

    path = idx._cache_path(source)
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return {}
    with _lock:
        cached = _index_cache.get(source)
        if cached and cached[0] == mtime:
            return cached[1]
    payload, _ = idx._read_cache(source)
    entries = payload.get("entries") if isinstance(payload.get("entries"), dict) else {}
    with _lock:
        _index_cache[source] = (mtime, entries)
    return entries


def _delphi(cve: str) -> Dict[str, Any]:
    try:
        from app.services.delphi_enrichment_service import get_delphi_service

        return get_delphi_service().lookup(cve)
    except Exception as exc:  # noqa: BLE001
        logger.debug("Delphi lookup failed for %s: %s", cve, exc)
        return {}


def live_intel(cve_id: Optional[str]) -> Dict[str, Any]:
    """Current exploitation intel for a CVE from local caches, in Oracle's
    ExploitationEvidence field names. Empty when nothing is known."""
    cve = (cve_id or "").strip().upper()
    if not cve.startswith("CVE-"):
        return {}
    out: Dict[str, Any] = {}
    kev: List[str] = []

    d = _delphi(cve)
    for src in d.get("kev_sources") or []:
        kev.append({"shadowserver": "shadowserver", "kevintel": "kevintel"}.get(src, src))
    if (d.get("kev") or {}).get("known_ransomware_use", "").lower() in ("known", "yes"):
        out["ransomware_associated"] = True

    x = _index("vulncheck_exploits").get(cve) or {}
    if x:
        if x.get("public_exploit_found") or x.get("artifacts"):
            out["vulncheck_public_exploit"] = True
            out["vulncheck_exploit_count"] = len(x.get("artifacts") or [])
        if x.get("weaponized_exploit_found"):
            out["vulncheck_weaponized"] = True
        if x.get("commercial_exploit_found"):
            out["vulncheck_commercial_exploit"] = True
        if x.get("reported_exploited"):
            out["vulncheck_reported_exploited"] = True
        if x.get("in_cisa_kev"):
            kev.append("cisa_kev")
        if x.get("in_vulncheck_kev"):
            kev.append("vulncheck_kev")

    templates = _index("nuclei").get(cve) or []
    if templates:
        out["nuclei_template_count"] = len(templates)

    if kev:
        out["in_kev_sources"] = sorted(set(kev))
    return out


def intel_signature(intel: Dict[str, Any]) -> str:
    """Stable short hash of the fields that change a score."""
    keys = (
        "in_kev_sources", "ransomware_associated", "vulncheck_public_exploit", "vulncheck_weaponized",
        "vulncheck_commercial_exploit", "vulncheck_reported_exploited", "nuclei_template_count",
    )
    material = json.dumps({k: intel.get(k) for k in keys if intel.get(k)}, sort_keys=True)
    return hashlib.sha1(material.encode()).hexdigest()[:16]


def merge_evidence(oracle_evidence: Dict[str, Any], intel: Dict[str, Any]) -> Dict[str, Any]:
    """Oracle's evidence with live intel layered on (lists unioned, flags OR'd)."""
    merged = dict(oracle_evidence or {})
    for key, value in intel.items():
        if key == "nuclei_template_count":
            continue
        if isinstance(value, list):
            merged[key] = sorted(set(merged.get(key) or []) | set(value))
        elif isinstance(value, bool):
            merged[key] = bool(merged.get(key)) or value
        elif isinstance(value, (int, float)):
            merged[key] = max(merged.get(key) or 0, value)
    return merged


def mark_intel_changes(session_factory, cve_ids: Optional[Iterable[str]] = None) -> Dict[str, int]:
    """Mark open findings dirty where their CVE's live intel changed since
    they were last scored. Returns counts."""
    from sqlalchemy import update

    from app.models.vulnerability import Vulnerability, VulnerabilityStatus

    db = session_factory()
    try:
        open_states = [VulnerabilityStatus.OPEN, VulnerabilityStatus.IN_PROGRESS]
        if cve_ids is None:
            cve_ids = [
                r[0] for r in db.query(Vulnerability.cve_id)
                .filter(Vulnerability.cve_id.isnot(None), Vulnerability.status.in_(open_states))
                .distinct().all()
            ]
        by_sig: Dict[str, List[str]] = {}
        for cve in cve_ids:
            by_sig.setdefault(intel_signature(live_intel(cve)), []).append(cve)
        vt = Vulnerability.__table__
        marked = 0
        now = datetime.utcnow()
        for sig, cves in by_sig.items():
            result = db.execute(
                update(vt)
                .where(
                    vt.c.cve_id.in_(cves),
                    vt.c.status.in_(open_states),
                    vt.c.sev_intel_sig.is_distinct_from(sig),
                    vt.c.sev_status.isnot(None),  # never-evaluated ones are dirty already
                )
                .values(sev_dirty=True, sev_dirty_at=now)
            )
            marked += result.rowcount or 0
        db.commit()
        return {"cves": sum(len(v) for v in by_sig.values()), "marked": marked}
    finally:
        db.close()
