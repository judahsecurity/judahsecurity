"""
Engagement Brain — persistent cross-run memory for Aegis Vanguard assessments.

Stores exhausted techniques, effective payloads, WAF fingerprints, confirmed
findings, and session notes so each run builds on the last rather than
starting cold.

Brain files live at:  ~/.aegis/brains/<target-hash>.json
"""
from __future__ import annotations

import hashlib
import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("agent.brain")

_BRAIN_DIR = Path.home() / ".aegis" / "brains"


class EngagementBrain:
    """Thread-safe persistent memory for a single target engagement.

    Survives process restarts; each run layer adds to the same file so
    agents never re-exhaust techniques that already failed.
    """

    def __init__(self, target_url: str):
        self.target_url = target_url
        # Short stable key derived from target so filenames are human-readable
        self._key = hashlib.sha1(target_url.encode()).hexdigest()[:14]
        self._path = _BRAIN_DIR / f"{self._key}.json"
        self._lock = threading.Lock()
        self._data = self._load()

    # ---------------------------------------------------------------- I/O

    def _load(self) -> dict:
        _BRAIN_DIR.mkdir(parents=True, exist_ok=True)
        if self._path.exists():
            try:
                data = json.loads(self._path.read_text())
                run_count = len(data.get("runs", []))
                logger.info(
                    "brain: loaded %s — run #%d, %d exhausted, %d confirmed",
                    self._path.name,
                    run_count,
                    sum(len(v) for v in data.get("exhausted_techniques", {}).values()),
                    len(data.get("confirmed_vulns", [])),
                )
                return data
            except Exception as exc:
                logger.warning(
                    "brain: corrupt file %s — starting fresh (%s)", self._path, exc
                )
        return self._empty()

    def _empty(self) -> dict:
        return {
            "target": self.target_url,
            "created_at": _now(),
            "waf_profile": {
                "detected": None,
                "vendor": None,
                "blocked_patterns": [],
                "bypass_levels_confirmed": [],
                "bypass_levels_failed": [],
            },
            # "endpoint::category" -> [technique_ids_already_tried]
            "exhausted_techniques": {},
            # "category" -> [most_effective_payloads_first]
            "effective_payloads": {},
            # confirmed findings across all runs
            "confirmed_vulns": [],
            # endpoints discovered across all runs
            "known_endpoints": [],
            # free-form timestamped observations from agents
            "session_notes": [],
            # run metadata (one entry per run_pentest.py invocation)
            "runs": [],
        }

    def save(self) -> None:
        """Atomically flush the brain state to disk."""
        with self._lock:
            self._data["updated_at"] = _now()
            tmp = self._path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._data, indent=2))
            tmp.replace(self._path)
            logger.debug("brain: saved → %s", self._path)

    def record_run_start(self, model: str, mode: str) -> None:
        with self._lock:
            self._data["runs"].append(
                {
                    "run_id": len(self._data["runs"]) + 1,
                    "started_at": _now(),
                    "model": model,
                    "mode": mode,
                }
            )

    def record_run_end(self, finding_count: int) -> None:
        with self._lock:
            runs = self._data.get("runs", [])
            if runs:
                runs[-1]["ended_at"] = _now()
                runs[-1]["finding_count"] = finding_count

    # --------------------------------------------------------- WAF profile

    def update_waf(
        self,
        *,
        detected: Optional[str] = None,
        vendor: Optional[str] = None,
        blocked: Optional[List[str]] = None,
        bypass_ok: Optional[List[str]] = None,
        bypass_fail: Optional[List[str]] = None,
    ) -> None:
        with self._lock:
            p = self._data["waf_profile"]
            if detected is not None:
                p["detected"] = detected
            if vendor is not None:
                p["vendor"] = vendor
            if blocked:
                existing = set(p["blocked_patterns"])
                existing.update(blocked)
                # Keep last 200 to avoid unbounded growth
                p["blocked_patterns"] = list(existing)[-200:]
            if bypass_ok:
                existing = set(p["bypass_levels_confirmed"])
                existing.update(bypass_ok)
                p["bypass_levels_confirmed"] = list(existing)
            if bypass_fail:
                existing = set(p["bypass_levels_failed"])
                existing.update(bypass_fail)
                p["bypass_levels_failed"] = list(existing)

    # ------------------------------------------------- exhausted techniques

    def mark_exhausted(self, endpoint: str, category: str, technique: str) -> None:
        """Record that `technique` was tried against `endpoint` for `category`."""
        key = f"{endpoint}::{category}"
        with self._lock:
            bucket = self._data["exhausted_techniques"].setdefault(key, [])
            if technique not in bucket:
                bucket.append(technique)

    def is_exhausted(self, endpoint: str, category: str, technique: str) -> bool:
        key = f"{endpoint}::{category}"
        return technique in self._data["exhausted_techniques"].get(key, [])

    def get_exhausted(self, endpoint: str, category: str) -> List[str]:
        return list(
            self._data["exhausted_techniques"].get(f"{endpoint}::{category}", [])
        )

    # -------------------------------------------------- effective payloads

    def add_effective_payload(self, category: str, payload: str) -> None:
        """Save a payload that actually worked (most recent first, capped at 50)."""
        with self._lock:
            bucket = self._data["effective_payloads"].setdefault(category, [])
            if payload not in bucket:
                bucket.insert(0, payload)
                self._data["effective_payloads"][category] = bucket[:50]

    def get_effective_payloads(self, category: str) -> List[str]:
        return list(self._data["effective_payloads"].get(category, []))

    # ------------------------------------------- confirmed vulns / endpoints

    def add_confirmed_vuln(
        self, title: str, vuln_type: str, endpoint: str, severity: str
    ) -> None:
        key = endpoint + vuln_type
        with self._lock:
            existing_keys = {
                v["endpoint"] + v["type"] for v in self._data["confirmed_vulns"]
            }
            if key not in existing_keys:
                self._data["confirmed_vulns"].append(
                    {
                        "ts": _now(),
                        "title": title[:200],
                        "type": vuln_type,
                        "endpoint": endpoint[:500],
                        "severity": severity,
                    }
                )

    def add_endpoint(self, endpoint: str) -> None:
        with self._lock:
            endpoints = self._data["known_endpoints"]
            if endpoint not in endpoints:
                endpoints.append(endpoint)
                self._data["known_endpoints"] = endpoints[-2000:]

    # -------------------------------------------------------------- notes

    def add_note(self, note: str) -> None:
        with self._lock:
            self._data["session_notes"].append(
                {"ts": _now(), "note": note[:2000]}
            )
            self._data["session_notes"] = self._data["session_notes"][-500:]

    # -------------------------------------------------- context / queries

    def to_context_summary(self) -> str:
        """Return a compact summary for injection into agent opening messages."""
        data = self._data
        run_count = len(data.get("runs", []))
        if run_count == 0:
            return (
                "**Engagement Brain**: First run against this target — "
                "no prior data. Use brain_add_note, brain_mark_exhausted, "
                "brain_add_payload to start building the brain."
            )

        waf = data["waf_profile"]
        exhausted_count = sum(
            len(v) for v in data.get("exhausted_techniques", {}).values()
        )
        payload_count = sum(
            len(v) for v in data.get("effective_payloads", {}).values()
        )
        confirmed = data.get("confirmed_vulns", [])

        lines: List[str] = [
            f"**Engagement Brain** — Run #{run_count + 1} "
            f"({run_count} prior run{'s' if run_count != 1 else ''})",
            f"WAF: {waf.get('detected') or 'not detected'}"
            + (f" ({waf['vendor']})" if waf.get("vendor") else ""),
        ]
        if waf["bypass_levels_confirmed"]:
            lines.append(
                f"  WAF bypass confirmed: {', '.join(waf['bypass_levels_confirmed'])}"
            )
        if waf["bypass_levels_failed"]:
            lines.append(
                f"  WAF bypass failed (skip): {', '.join(waf['bypass_levels_failed'])}"
            )
        lines += [
            f"Exhausted technique slots: {exhausted_count}",
            f"Effective payload library: {payload_count} payloads "
            f"across {len(data.get('effective_payloads', {}))} categories",
            f"Known endpoints: {len(data.get('known_endpoints', []))}",
        ]
        if confirmed:
            lines.append(f"Previously confirmed ({len(confirmed)} total):")
            for c in confirmed[-6:]:
                lines.append(
                    f"  [{c['severity'].upper()}] {c['type']} @ {c['endpoint']}"
                )

        notes = data.get("session_notes", [])[-3:]
        if notes:
            lines.append("Recent notes:")
            for n in notes:
                lines.append(f"  {n['note'][:180]}")

        lines.append(
            "\nTools: brain_query(topic) · brain_mark_exhausted(endpoint, category, technique) "
            "· brain_add_payload(category, payload) · brain_add_note(note) "
            "· brain_update_waf(detected, bypass_ok, bypass_fail)"
        )
        return "\n".join(lines)

    def query(self, topic: str) -> Dict[str, Any]:
        """Return brain data relevant to a keyword topic."""
        t = topic.lower()
        result: Dict[str, Any] = {"topic": topic, "waf_profile": self._data["waf_profile"]}

        payloads = {
            cat: pl
            for cat, pl in self._data.get("effective_payloads", {}).items()
            if t in cat.lower()
        }
        if payloads:
            result["effective_payloads"] = payloads

        exhausted = {
            key: techs
            for key, techs in self._data.get("exhausted_techniques", {}).items()
            if t in key.lower()
        }
        if exhausted:
            result["exhausted_techniques"] = exhausted

        vulns = [
            v
            for v in self._data.get("confirmed_vulns", [])
            if t in v.get("type", "").lower()
            or t in v.get("title", "").lower()
            or t in v.get("endpoint", "").lower()
        ]
        if vulns:
            result["confirmed_vulns"] = vulns

        notes = [
            n
            for n in self._data.get("session_notes", [])
            if t in n.get("note", "").lower()
        ][-20:]
        if notes:
            result["notes"] = notes

        endpoints = [e for e in self._data.get("known_endpoints", []) if t in e.lower()]
        if endpoints:
            result["matching_endpoints"] = endpoints[:50]

        return result


# =========================================================================
# Module-level singleton (initialised by run_pentest.py)
# =========================================================================

_brain: Optional[EngagementBrain] = None


def init_brain(target_url: str) -> EngagementBrain:
    """Initialise (or re-use) the global brain for target_url."""
    global _brain
    _brain = EngagementBrain(target_url)
    return _brain


def get_brain() -> Optional[EngagementBrain]:
    return _brain


# =========================================================================
# Helpers
# =========================================================================

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
