"""
Delphi - Vulnerability Priority Intelligence Service.

Delphi was the ancient Greek oracle — the place you went to ask "which of
these threats should I actually worry about?" This service answers the same
question for vulnerabilities by assessing the **likelihood of exploitation**:
how easy is this to exploit, is the vulnerable thing actually reachable, and
has anyone confirmed it being exploited in the wild?

Priority is driven by confirmed exploitation evidence and the concrete
*conditions required to exploit* — not probabilistic estimates. EPSS (Exploit
Prediction Scoring System) is fetched and stored for informational display but
does NOT affect the priority calculation. The FIRE report (cvedata.com) shows
that EPSS is a poor predictor of real-world financial losses, and FIRST.org
themselves caution that EPSS should not replace KEV-class signals.

Delphi is the fast, deterministic, no-LLM first pass. It runs on every finding
and always succeeds (even when the Oracle daemon is down). Oracle/OPES remains
the deep, asset-specific, LLM-driven layer; Delphi deliberately borrows only a
few cheap, high-signal asset facts (internet-facing, live, login portal) to
make its score reachability-aware without replicating Oracle's reasoning.

Exploitation-likelihood model
─────────────────────────────
Confirmed-exploitation facts sit at the top and floor the score:
  1. **CISA KEV** — confirmed in-the-wild exploitation (KEV + ransomware ranks
     highest of all).
  2. **Breach intel** — CVE appears in Mandiant M-Trends, CrowdStrike GTR, or
     FIRE insurance-loss data (documented attacker use).

Absent a confirmed-exploitation fact, a 0-100 `likelihood_score` is computed
from four factors, each normalized to [0, 1]:

    score = round(100 * S * E * R * C)

  • S — severity magnitude          = cvss_score / 10
  • E — exploitability conditions   = AV x AC x AT x PR x UI (from CVSS vector)
  • R — reachability                = internet-facing / live / WAF exposure
  • C — detection confidence        = exploit_confirmed .. version_only

The score maps to a tier (critical/high/elevated/moderate/low/none); facts set
a minimum tier so a KEV CVE is always at least `critical`. All factor weights
live in module-level tables below and are tunable.

EPSS is still fetched daily and surfaced in the UI as a reference data point.
Analysts can use it to understand relative exploit prediction among CVEs, but
it is explicitly marked as informational in all API responses.

Data sources:
    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
    https://epss.cyentia.com/epss_scores-current.csv.gz
    VulnCheck KEV (optional VULNCHECK_API_TOKEN)
    Shadowserver honeypot exploited (via CIRCL Vulnerability-Lookup)
    KEVIntel attestations (via CIRCL KEV catalog)
    FIRE / Mandiant / CrowdStrike breach intel (static + optional JSON overlays)

CISA KEV + EPSS are always fetched. Extended KEV feeds are gated by
`DELPHI_EXTENDED_KEV_ENABLED` and cached on-disk with the same refresh cadence.
"""

from __future__ import annotations

import csv
import gzip
import io
import json
import logging
import os
import threading
import time
import urllib.request
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from app.core.config import settings
from app.services.vuln_intel_feeds import (
    load_breach_overlay,
    load_extended_feeds,
    load_fire_cves,
)

logger = logging.getLogger(__name__)

# Public, no-auth endpoints
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

# EPSS percentile labels — used for display only, NOT for priority calculation.
# These ranges are from first.org guidance but EPSS does not drive Delphi priority.
_EPSS_DISPLAY_BUCKETS: List[Tuple[float, str]] = [
    (0.95, "top 5%"),
    (0.80, "top 20%"),
    (0.50, "top 50%"),
    (0.20, "bottom 80%"),
    (0.0,  "low"),
]


def _epss_display_label(percentile: float) -> str:
    """Return a display-only percentile label. Not used in priority scoring."""
    for threshold, label in _EPSS_DISPLAY_BUCKETS:
        if percentile >= threshold:
            return label
    return "low"


# ── Exploitation-likelihood factor tables ────────────────────────────────────
# Each factor is normalized to [0, 1]. Constants are intentionally centralized
# here so the model can be tuned without touching the scoring logic.

# Exploitability (E) = product of the CVSS-vector conditions below.
_AV_WEIGHTS: Dict[str, float] = {"N": 1.0, "A": 0.6, "L": 0.35, "P": 0.15}
_AC_WEIGHTS: Dict[str, float] = {"L": 1.0, "H": 0.6}
_PR_WEIGHTS: Dict[str, float] = {"N": 1.0, "L": 0.7, "H": 0.35}
# CVSS 3.x UI is N/R; CVSS 4.0 uses N/P/A. Any non-"N" value implies interaction.
_UI_WEIGHTS: Dict[str, float] = {"N": 1.0, "R": 0.65, "P": 0.65, "A": 0.65}
# Fallbacks when a vector component is absent — mildly optimistic, not punitive.
_AV_DEFAULT = 0.7
_AC_DEFAULT = 0.9
_PR_DEFAULT = 0.85
_UI_DEFAULT = 0.9
_AT_PRESENT = 0.7   # CVSS 4.0 attack requirements present → extra prep needed
_AT_ABSENT = 1.0

# Reachability (R) — only applied when the attack vector is network/adjacent
# (or unknown); local/physical vectors are not gated on internet exposure.
_R_INTERNET_LIVE = 1.0
_R_INTERNET_NOT_LIVE = 0.85
_R_INTERNAL = 0.4
_R_WAF_MULTIPLIER = 0.85
_R_UNKNOWN = 1.0    # no asset context (e.g. standalone /lookup) → neutral

# Detection confidence (C) — how sure we are the vulnerable feature is real
# and reachable, not merely a version match.
_CONFIDENCE_WEIGHTS: Dict[str, float] = {
    "exploit_confirmed": 1.0,
    "endpoint_confirmed": 0.9,
    "version_only": 0.65,
    "unknown": 0.8,
}
_CONFIDENCE_DEFAULT = 0.8

# Score → tier bands (lower bound inclusive). Checked high-to-low.
_TIER_BANDS: List[Tuple[int, str]] = [
    (80, "critical"),
    (60, "high"),
    (40, "elevated"),
    (20, "moderate"),
    (1,  "low"),
]

# Ordering used across the API for sorting/ranking tiers (lower = higher priority).
TIER_RANK: Dict[str, int] = {
    "critical": 0,
    "high": 1,
    "elevated": 2,
    "moderate": 3,
    "low": 4,
    "none": 5,
}

# Fact overrides — confirmed exploitation floors the score and minimum tier.
# Breach floor stays just inside the "high" band (60-79) so a breach-listed CVE
# is guaranteed at least "high" without being auto-promoted to "critical".
#
# VulnCheck KEV is treated as the broadest exploitation catalog (same floor as
# CISA KEV). CISA remains an authoritative corroborating government catalog.
# Extended attestations (Shadowserver / KEVIntel) sit just below.
_KEV_RANSOMWARE_FLOOR = 98
_KEV_FLOOR = 92            # CISA KEV and VulnCheck KEV share this floor
_EXTENDED_KEV_FLOOR = 85   # Shadowserver honeypot / KEVIntel attestation
_BREACH_FLOOR = 79


def _tier_from_score(score: int) -> str:
    """Map a 0-100 likelihood score to a priority tier."""
    for lower_bound, tier in _TIER_BANDS:
        if score >= lower_bound:
            return tier
    return "none"


# ── Static breach intel — mirrors aegis-oracle/internal/modules/enrichers/fire_ice.go
# CVEs from Mandiant M-Trends and CrowdStrike GTR breach investigation reports.
# Update annually when new reports are published.
# Last updated: M-Trends 2025, CrowdStrike GTR 2026.
_MANDIANT_MTRENDS_CVES: frozenset = frozenset({
    # M-Trends 2024 (2023 investigations)
    "CVE-2023-46805", "CVE-2024-21887",  # Ivanti Connect Secure
    "CVE-2023-34362",                     # MOVEit Transfer
    "CVE-2023-4966",                      # Citrix Bleed
    "CVE-2023-22518",                     # Atlassian Confluence
    "CVE-2023-3519",                      # Citrix ADC
    "CVE-2023-27350",                     # PaperCut
    "CVE-2022-47966",                     # Zoho ManageEngine
    "CVE-2021-44228",                     # Log4Shell
    # M-Trends 2025 (2024 investigations)
    "CVE-2024-3400",                      # Palo Alto GlobalProtect
    "CVE-2024-21762",                     # Fortinet FortiOS
    "CVE-2024-40711",                     # Veeam Backup
    "CVE-2024-55956",                     # Cleo MFT
    "CVE-2024-50623",                     # Cleo LexiCom/VLTrader
})

_CROWDSTRIKE_GTR_CVES: frozenset = frozenset({
    # GTR 2025 (2024 adversary activity)
    "CVE-2024-3400",                      # Palo Alto GlobalProtect
    "CVE-2024-21762",                     # Fortinet FortiOS
    "CVE-2024-55956",                     # Cleo MFT
    "CVE-2025-0282",                      # Ivanti Connect Secure
    "CVE-2024-40711",                     # Veeam Backup
    "CVE-2024-7965",                      # Google Chrome V8
    "CVE-2024-38193",                     # Windows AFD
    "CVE-2024-21338",                     # Windows Kernel
    # GTR 2026 (2025 adversary activity) — update when published
})

# FIRE dataset (Zywave insurance carrier data via cvedata.com).
# Empty by default — populate backend/data/breach_intel/fire_cves.json or set
# DELPHI_FIRE_CVE_PATH from a cvedata.com pipeline export.
_FIRE_CVES: frozenset = frozenset()


def _merged_breach_sets() -> Tuple[frozenset, frozenset, frozenset]:
    """Built-in Mandiant/CrowdStrike sets plus optional JSON overlays + FIRE file."""
    overlay_dir = getattr(settings, "DELPHI_BREACH_INTEL_DIR", None)
    mtrends = set(_MANDIANT_MTRENDS_CVES) | load_breach_overlay(
        "mandiant_mtrends.json", directory=overlay_dir
    )
    gtr = set(_CROWDSTRIKE_GTR_CVES) | load_breach_overlay(
        "crowdstrike_gtr.json", directory=overlay_dir
    )
    fire = set(_FIRE_CVES) | load_fire_cves(getattr(settings, "DELPHI_FIRE_CVE_PATH", None))
    return frozenset(mtrends), frozenset(gtr), frozenset(fire)


def _parse_cvss_vector(vector: Optional[str]) -> dict:
    """
    Parse a CVSS 3.x or 4.0 vector string into a component dict.
    Handles both 'CVSS:4.0/AV:N/AC:L/AT:P/...' and 'AV:N/AC:L/PR:N/...' formats.
    """
    if not vector:
        return {}
    # Strip 'CVSS:4.0/' or 'CVSS:3.1/' prefix
    clean = vector.strip()
    if "/" in clean and clean.split("/")[0].startswith("CVSS:"):
        clean = "/".join(clean.split("/")[1:])
    parts = {}
    for segment in clean.split("/"):
        if ":" in segment:
            k, v = segment.split(":", 1)
            parts[k.upper()] = v.upper()
    return parts


def _cache_dir() -> str:
    path = os.environ.get("DELPHI_CACHE_DIR") or "/tmp/delphi_cache"
    os.makedirs(path, exist_ok=True)
    return path


def _http_get(url: str, *, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "judahsecurity-asm-delphi/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec - static public URLs
        return resp.read()


class DelphiEnrichmentService:
    """
    Exploitation-likelihood enrichment. Lazy-loaded on first call and refreshed
    when on-disk caches are older than DELPHI_REFRESH_HOURS.

    Core feeds: CISA KEV + EPSS (display only).
    Extended feeds (optional): VulnCheck KEV, Shadowserver, KEVIntel.
    """

    def __init__(self) -> None:
        self.enabled: bool = getattr(settings, "DELPHI_ENRICHMENT_ENABLED", True)
        self.refresh_hours: int = int(getattr(settings, "DELPHI_REFRESH_HOURS", 24))
        self.extended_enabled: bool = getattr(settings, "DELPHI_EXTENDED_KEV_ENABLED", True)
        self._kev: Dict[str, Dict[str, Any]] = {}
        self._kev_meta: Dict[str, Any] = {}
        self._epss: Dict[str, Dict[str, float]] = {}
        self._epss_date: Optional[str] = None
        self._vulncheck_kev: Dict[str, Dict[str, Any]] = {}
        self._shadowserver: Set[str] = set()
        self._kevintel: Dict[str, Dict[str, Any]] = {}
        self._mtrends: frozenset = _MANDIANT_MTRENDS_CVES
        self._gtr: frozenset = _CROWDSTRIKE_GTR_CVES
        self._fire: frozenset = _FIRE_CVES
        self._last_load_ts: float = 0.0
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Cache / loading
    # ------------------------------------------------------------------

    def _kev_cache_path(self) -> str:
        return os.path.join(_cache_dir(), "cisa_kev.json")

    def _epss_cache_path(self) -> str:
        return os.path.join(_cache_dir(), "epss_scores_current.csv")

    def _cache_fresh(self, path: str) -> bool:
        if not os.path.exists(path):
            return False
        age_hours = (time.time() - os.path.getmtime(path)) / 3600.0
        return age_hours < self.refresh_hours

    def _fetch_kev(self, force: bool = False) -> None:
        path = self._kev_cache_path()
        if not force and self._cache_fresh(path):
            return
        try:
            raw = _http_get(KEV_URL, timeout=60)
            with open(path, "wb") as fh:
                fh.write(raw)
            logger.info("Delphi: refreshed CISA KEV cache (%d bytes)", len(raw))
        except Exception as exc:
            logger.warning("Delphi: KEV fetch failed (%s); using stale cache if present", exc)

    def _fetch_epss(self, force: bool = False) -> None:
        path = self._epss_cache_path()
        if not force and self._cache_fresh(path):
            return
        try:
            raw = _http_get(EPSS_URL, timeout=120)
            # EPSS is gzipped CSV
            try:
                decompressed = gzip.decompress(raw)
            except OSError:
                # Served as plain CSV
                decompressed = raw
            with open(path, "wb") as fh:
                fh.write(decompressed)
            logger.info("Delphi: refreshed EPSS cache (%d bytes decompressed)", len(decompressed))
        except Exception as exc:
            logger.warning("Delphi: EPSS fetch failed (%s); using stale cache if present", exc)

    def _load_kev(self) -> None:
        path = self._kev_cache_path()
        if not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            vulns = data.get("vulnerabilities") or []
            mapped: Dict[str, Dict[str, Any]] = {}
            for entry in vulns:
                cve = (entry.get("cveID") or "").strip().upper()
                if not cve:
                    continue
                mapped[cve] = {
                    "cve_id": cve,
                    "vendor_project": entry.get("vendorProject"),
                    "product": entry.get("product"),
                    "vulnerability_name": entry.get("vulnerabilityName"),
                    "date_added": entry.get("dateAdded"),
                    "short_description": entry.get("shortDescription"),
                    "required_action": entry.get("requiredAction"),
                    "due_date": entry.get("dueDate"),
                    "known_ransomware_use": entry.get("knownRansomwareCampaignUse"),
                    "notes": entry.get("notes"),
                    "cwes": entry.get("cwes"),
                }
            self._kev = mapped
            self._kev_meta = {
                "catalog_version": data.get("catalogVersion"),
                "date_released": data.get("dateReleased"),
                "count": data.get("count") or len(mapped),
            }
            logger.info("Delphi: loaded %d KEV entries", len(mapped))
        except Exception as exc:
            logger.error("Delphi: KEV parse failed: %s", exc)

    def _load_epss(self) -> None:
        path = self._epss_cache_path()
        if not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                # EPSS file begins with a comment line: "#model_version:...,score_date:..."
                text = fh.read()
            lines = text.splitlines()
            # Extract date from header if present
            self._epss_date = None
            data_start = 0
            for i, line in enumerate(lines):
                if line.startswith("#"):
                    if "score_date:" in line:
                        self._epss_date = line.split("score_date:", 1)[1].split(",")[0].strip()
                    data_start = i + 1
                else:
                    data_start = i
                    break

            reader = csv.DictReader(lines[data_start:])
            mapped: Dict[str, Dict[str, float]] = {}
            for row in reader:
                cve = (row.get("cve") or "").strip().upper()
                if not cve:
                    continue
                try:
                    score = float(row.get("epss") or 0.0)
                    percentile = float(row.get("percentile") or 0.0)
                except ValueError:
                    continue
                mapped[cve] = {"score": score, "percentile": percentile}
            self._epss = mapped
            logger.info("Delphi: loaded %d EPSS entries (date=%s)", len(mapped), self._epss_date)
        except Exception as exc:
            logger.error("Delphi: EPSS parse failed: %s", exc)

    def ensure_loaded(self, force_refresh: bool = False) -> None:
        """Lazy-load or refresh feeds. KEV is required; EPSS is best-effort (display only)."""
        with self._lock:
            # KEV is the critical feed — required for priority calculation.
            # EPSS is optional (display only), so we gate only on KEV for the
            # "already loaded" check.
            already_loaded = bool(self._kev)
            if already_loaded and not force_refresh:
                age = time.time() - self._last_load_ts
                if age < self.refresh_hours * 3600:
                    return
            self._fetch_kev(force=force_refresh)
            self._fetch_epss(force=force_refresh)
            self._load_kev()
            self._load_epss()

            # Extended exploitation feeds — best-effort, never block CISA path.
            try:
                token = (
                    getattr(settings, "VULNCHECK_API_TOKEN", None)
                    or os.environ.get("VULNCHECK_API_TOKEN")
                    or ""
                )
                # Prefer org/env-resolved token when callers have already set it.
                if not token:
                    try:
                        from app.models.api_config import ExternalService, resolve_api_key
                        from app.db.database import SessionLocal
                        db = SessionLocal()
                        try:
                            token = resolve_api_key(db, ExternalService.VULNCHECK) or ""
                        finally:
                            db.close()
                    except Exception:
                        token = token or ""
                vkev, shadow, kevintel, fire = load_extended_feeds(
                    vulncheck_token=token or "",
                    force=force_refresh,
                    refresh_hours=self.refresh_hours,
                    enabled=self.extended_enabled,
                )
                self._vulncheck_kev = vkev
                self._shadowserver = shadow
                self._kevintel = kevintel
                mtrends, gtr, fire_merged = _merged_breach_sets()
                # Prefer file-loaded FIRE when present; otherwise keep overlay merge.
                self._mtrends = mtrends
                self._gtr = gtr
                self._fire = frozenset(set(fire_merged) | set(fire))
            except Exception as exc:
                logger.warning("Delphi: extended feed load failed: %s", exc)

            self._last_load_ts = time.time()

    # ------------------------------------------------------------------
    # Public lookup / enrichment API
    # ------------------------------------------------------------------

    def _normalize_cve(self, cve_id: str) -> str:
        if not cve_id:
            return ""
        s = cve_id.strip().upper()
        if not s.startswith("CVE-"):
            s = f"CVE-{s}"
        return s

    def lookup(
        self,
        cve_id: str,
        *,
        cvss_score: Optional[float] = None,
        cvss_vector: Optional[str] = None,
        detection_confidence: Optional[str] = None,
        exposure: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Look up Delphi enrichment signals for a single CVE.

        Priority is an exploitation-likelihood assessment driven by confirmed
        exploitation facts (KEV, breach intel) and the concrete conditions
        required to exploit (CVSS vector, reachability, detection confidence).
        EPSS is NOT used — it is included for informational display only.

        Args:
            cve_id:               The CVE identifier.
            cvss_score:           CVSS base score (0-10), if known.
            cvss_vector:          CVSS 3.x/4.0 vector string, if known.
            detection_confidence: How deeply the scanner confirmed the
                                  vulnerable feature is active/reachable —
                                  one of exploit_confirmed | endpoint_confirmed
                                  | version_only | unknown.
            exposure:             Optional asset-reachability context with keys
                                  internet_facing (bool), is_live (bool),
                                  has_login_portal (bool), waf (str|None).
                                  Omit for CVE-intrinsic (asset-agnostic) lookups.

        Returns a dict with:
            cve_id, kev, epss (display only), priority, likelihood_score,
            priority_reason, priority_signals, factors (E/R/C/S breakdown)
        """
        cve = self._normalize_cve(cve_id)
        if not self.enabled or not cve:
            return {"cve_id": cve, "enriched": False, "reason": "disabled_or_empty"}

        self.ensure_loaded()

        kev_entry = self._kev.get(cve)
        vkev_entry = self._vulncheck_kev.get(cve)
        kevintel_entry = self._kevintel.get(cve)
        shadowserver_hit = cve in self._shadowserver
        epss_entry = self._epss.get(cve)

        # EPSS — fetched for display, not used in priority calculation.
        epss_out = None
        if epss_entry:
            pct = round(float(epss_entry.get("percentile") or 0), 6)
            epss_out = {
                "score": round(float(epss_entry.get("score") or 0), 6),
                "percentile": pct,
                "display_label": _epss_display_label(pct),
                "date": self._epss_date,
                # Explicit flag so UI can display the right context.
                "informational_only": True,
                "scoring_note": "EPSS is a probabilistic estimate. It is not used in Delphi priority scoring.",
            }

        priority, score, reason, signals, factors = self._assess_exploitation_likelihood(
            cve_id=cve,
            kev=kev_entry,
            vulncheck_kev=vkev_entry,
            shadowserver=shadowserver_hit,
            kevintel=kevintel_entry,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            detection_confidence=detection_confidence,
            exposure=exposure,
        )

        # VulnCheck first — broadest exploitation coverage.
        kev_sources: List[str] = []
        if vkev_entry:
            kev_sources.append("vulncheck_kev")
        if kev_entry:
            kev_sources.append("cisa_kev")
        if shadowserver_hit:
            kev_sources.append("shadowserver")
        if kevintel_entry:
            kev_sources.append("kevintel")

        return {
            "cve_id": cve,
            "enriched": bool(
                kev_entry or epss_entry or cvss_score or vkev_entry or shadowserver_hit or kevintel_entry
            ),
            "kev": kev_entry,
            "vulncheck_kev": vkev_entry,
            "kevintel": kevintel_entry,
            "shadowserver_exploited": shadowserver_hit,
            "kev_sources": kev_sources,
            "epss": epss_out,
            "priority": priority,
            "likelihood_score": score,
            "priority_reason": reason,
            "priority_signals": signals,
            "factors": factors,
        }

    # ------------------------------------------------------------------
    # Exploitation-likelihood scoring
    # ------------------------------------------------------------------

    @staticmethod
    def _exploitability_factor(vec: Dict[str, str], signals: List[str]) -> float:
        """
        E — how easy the vuln is to exploit, from the CVSS vector conditions.
        Product of attack vector, complexity, requirements, privileges, and
        user interaction. Missing components fall back to mildly optimistic
        defaults rather than penalizing an unknown.
        """
        av = vec.get("AV")
        ac = vec.get("AC")
        pr = vec.get("PR")
        ui = vec.get("UI")
        at_present = vec.get("AT") == "P"   # CVSS 4.0: attack requirements present

        av_w = _AV_WEIGHTS.get(av, _AV_DEFAULT)
        ac_w = _AC_WEIGHTS.get(ac, _AC_DEFAULT)
        pr_w = _PR_WEIGHTS.get(pr, _PR_DEFAULT)
        ui_w = _UI_WEIGHTS.get(ui, _UI_DEFAULT)
        at_w = _AT_PRESENT if at_present else _AT_ABSENT

        if av == "N":
            signals.append("av_network")
        elif av == "A":
            signals.append("av_adjacent")
        elif av in ("L", "P"):
            signals.append("av_local_or_physical")
        if ac == "H":
            signals.append("ac_high")
        if pr in ("N", "L"):
            signals.append("pr_none_or_low")
        elif pr == "H":
            signals.append("pr_high")
        if ui == "N":
            signals.append("no_ui_required")
        elif ui:
            signals.append("ui_required")
        if at_present:
            signals.append("at_preparation_required")

        return av_w * ac_w * pr_w * ui_w * at_w

    @staticmethod
    def _reachability_factor(
        vec: Dict[str, str],
        exposure: Optional[Dict[str, Any]],
        signals: List[str],
    ) -> float:
        """
        R — is the vulnerable thing actually reachable by an attacker?

        Only gates network/adjacent (or unknown) attack vectors; local and
        physical vectors are not limited by internet exposure. With no asset
        context (e.g. a standalone /lookup) reachability is neutral (1.0) and
        flagged as unknown so callers can display the right caveat.
        """
        av = vec.get("AV")
        # Local / physical exploitation is not gated on internet exposure.
        if av in ("L", "P"):
            return 1.0

        if not exposure:
            signals.append("reachability_unknown")
            return _R_UNKNOWN

        internet_facing = bool(exposure.get("internet_facing"))
        is_live = bool(exposure.get("is_live"))
        waf = exposure.get("waf")

        if internet_facing:
            if is_live:
                signals.append("internet_facing_live")
                r = _R_INTERNET_LIVE
            else:
                signals.append("internet_facing")
                r = _R_INTERNET_NOT_LIVE
        else:
            signals.append("internal_only")
            r = _R_INTERNAL

        if waf:
            signals.append("waf_in_path")
            r *= _R_WAF_MULTIPLIER

        return r

    @staticmethod
    def _confidence_factor(detection_confidence: Optional[str], signals: List[str]) -> float:
        """
        C — how sure we are the vulnerable feature is real and reachable,
        rather than a bare version match that may not be the vulnerable config.
        """
        key = (detection_confidence or "unknown").strip().lower()
        if key in _CONFIDENCE_WEIGHTS:
            signals.append(f"detection_{key}")
        return _CONFIDENCE_WEIGHTS.get(key, _CONFIDENCE_DEFAULT)

    def _assess_exploitation_likelihood(
        self,
        cve_id: str,
        kev: Optional[Dict[str, Any]] = None,
        cvss_score: Optional[float] = None,
        cvss_vector: Optional[str] = None,
        detection_confidence: Optional[str] = None,
        exposure: Optional[Dict[str, Any]] = None,
        vulncheck_kev: Optional[Dict[str, Any]] = None,
        shadowserver: bool = False,
        kevintel: Optional[Dict[str, Any]] = None,
    ) -> Tuple[str, int, str, List[str], Dict[str, Any]]:
        """
        Assess likelihood of exploitation. Returns
        (tier, likelihood_score, reason, signals, factors).

        Confirmed-exploitation facts (CISA KEV, VulnCheck KEV, Shadowserver,
        KEVIntel, breach intel) floor the score and set a minimum tier.
        Otherwise a 0-100 score is computed from the conditions required to
        exploit:

            score = round(100 * S * E * R * C)

        where S = severity magnitude, E = exploitability conditions,
        R = reachability, C = detection confidence. EPSS is intentionally
        excluded — it is a probabilistic estimate, not confirmed exploitation.
        """
        signals: List[str] = []
        factors: Dict[str, Any] = {}

        # ── Confirmed-exploitation facts ────────────────────────────────────
        # VulnCheck KEV has the broadest exploitation coverage; CISA KEV is the
        # authoritative US-government catalog. Either one floors at critical.
        fact_floor = 0
        fact_tier = "none"
        fact_reason: Optional[str] = None

        def _is_ransomware(entry: Optional[Dict[str, Any]]) -> bool:
            if not entry:
                return False
            return (entry.get("known_ransomware_use") or "").strip().lower() in ("known", "yes", "true")

        if kev or vulncheck_kev:
            if vulncheck_kev:
                signals.append("vulncheck_kev")
            if kev:
                signals.append("cisa_kev")
            ransom = _is_ransomware(vulncheck_kev) or _is_ransomware(kev)
            if ransom:
                signals.append("ransomware_campaign")
                fact_floor = _KEV_RANSOMWARE_FLOOR
            else:
                fact_floor = _KEV_FLOOR
            fact_tier = "critical"
            if vulncheck_kev and kev:
                fact_reason = (
                    "On VulnCheck KEV (broadest exploitation catalog) and CISA KEV"
                    + (" with known ransomware use" if ransom else "")
                )
            elif vulncheck_kev:
                fact_reason = (
                    "On VulnCheck KEV with known ransomware use"
                    if ransom
                    else "On VulnCheck KEV (confirmed exploitation — broadest catalog)"
                )
            else:
                fact_reason = (
                    "On CISA KEV with known ransomware campaign use"
                    if ransom
                    else "On CISA KEV (confirmed in-the-wild exploitation)"
                )
            if shadowserver:
                signals.append("shadowserver_exploited")
            if kevintel:
                signals.append("kevintel")
        elif shadowserver or kevintel:
            sources = []
            if shadowserver:
                signals.append("shadowserver_exploited")
                sources.append("Shadowserver honeypot")
            if kevintel:
                signals.append("kevintel")
                sources.append("KEVIntel")
            fact_floor = _EXTENDED_KEV_FLOOR
            fact_tier = "critical"
            fact_reason = f"Confirmed exploitation attestation: {', '.join(sources)}"
        else:
            cve_upper = (cve_id or "").upper()
            in_mtrends = cve_upper in self._mtrends
            in_gtr = cve_upper in self._gtr
            in_fire = cve_upper in self._fire
            if in_fire:
                signals.append("fire_insurance_loss")
            if in_mtrends:
                signals.append("mandiant_mtrends")
            if in_gtr:
                signals.append("crowdstrike_gtr")
            if in_fire or in_mtrends or in_gtr:
                sources = ", ".join(
                    s for s in ["FIRE (insurance loss)", "Mandiant M-Trends", "CrowdStrike GTR"]
                    if (in_fire and "FIRE" in s) or (in_mtrends and "Mandiant" in s) or (in_gtr and "CrowdStrike" in s)
                )
                fact_floor = _BREACH_FLOOR
                fact_tier = "high"
                fact_reason = f"Appears in breach investigation data: {sources}"

        # ── Conditions-to-exploit model ─────────────────────────────────────
        vec = _parse_cvss_vector(cvss_vector)
        computed_score = 0
        if cvss_score is not None:
            s_factor = max(0.0, min(float(cvss_score), 10.0)) / 10.0
            e_factor = self._exploitability_factor(vec, signals)
            r_factor = self._reachability_factor(vec, exposure, signals)
            c_factor = self._confidence_factor(detection_confidence, signals)
            computed_score = round(100 * s_factor * e_factor * r_factor * c_factor)
            factors = {
                "severity": round(s_factor, 4),
                "exploitability": round(e_factor, 4),
                "reachability": round(r_factor, 4),
                "confidence": round(c_factor, 4),
                "cvss_score": float(cvss_score),
            }
            signals.append(f"cvss_{float(cvss_score):.1f}")

        # ── Combine facts with computed conditions ──────────────────────────
        final_score = max(fact_floor, computed_score)
        tier_from_score = _tier_from_score(final_score)
        # Final tier is the stronger of the fact-floor tier and the score band.
        tier = min(
            (fact_tier, tier_from_score),
            key=lambda t: TIER_RANK.get(t, 99),
        )

        if final_score <= 0 and fact_reason is None:
            return "none", 0, "No CVE scoring data available", signals, factors

        # Build a human-readable reason.
        if fact_reason and computed_score and final_score == computed_score and computed_score > fact_floor:
            reason = f"{fact_reason}; exploitation-likelihood score {final_score}/100"
        elif fact_reason:
            reason = fact_reason
        else:
            reason = self._describe_conditions(cvss_score, factors, final_score)

        return tier, final_score, reason, signals, factors

    @staticmethod
    def _describe_conditions(
        cvss_score: Optional[float],
        factors: Dict[str, Any],
        score: int,
    ) -> str:
        """Render a short, defensible explanation of a condition-based score."""
        parts: List[str] = []
        if cvss_score is not None:
            parts.append(f"CVSS {float(cvss_score):.1f}")
        # Only surface reachability when it actually reduced the score, to avoid
        # misleadingly labelling local/physical or asset-agnostic lookups as
        # "reachable" (their factor is a neutral 1.0 by design).
        r = factors.get("reachability")
        if r is not None and r < 1.0:
            if r <= _R_INTERNAL:
                parts.append("limited reachability (internal)")
            else:
                parts.append("partially reachable")
        # version_only detection is the only confidence level low enough to call
        # out; endpoint/exploit-confirmed are strong enough to leave unremarked.
        c = factors.get("confidence")
        if c is not None and c < _CONFIDENCE_WEIGHTS["unknown"]:
            parts.append("version-only detection")
        detail = ", ".join(parts) if parts else "technical conditions"
        return f"Exploitation-likelihood score {score}/100 ({detail})"

    @staticmethod
    def _exposure_from_asset(vulnerability) -> Optional[Dict[str, Any]]:
        """
        Build the reachability-context dict Delphi's scorer expects from the
        vulnerability's asset. Returns None when there is no asset (keeps the
        lookup asset-agnostic and reachability neutral).
        """
        asset = getattr(vulnerability, "asset", None)
        if asset is None:
            return None
        return {
            "internet_facing": bool(getattr(asset, "is_public", False)),
            "is_live": bool(getattr(asset, "is_live", False)),
            "has_login_portal": bool(getattr(asset, "has_login_portal", False)),
        }

    def enrich_vulnerability(self, vulnerability) -> Dict[str, Any]:
        """
        Enrich a Vulnerability ORM object in-place on its metadata_.

        Passes CVSS score/vector, the scanner's detection confidence, and the
        asset's exposure to the lookup so the exploitation-likelihood score
        reflects the real conditions required to exploit this finding on this
        asset. Returns the lookup dict (regardless of whether it was persisted).
        """
        cve = getattr(vulnerability, "cve_id", None)
        if not cve:
            return {"enriched": False, "reason": "no_cve_id"}

        lookup = self.lookup(
            cve,
            cvss_score=getattr(vulnerability, "cvss_score", None),
            cvss_vector=getattr(vulnerability, "cvss_vector", None),
            detection_confidence=getattr(vulnerability, "detection_confidence", None),
            exposure=self._exposure_from_asset(vulnerability),
        )
        if not lookup.get("enriched"):
            return lookup

        meta = dict(vulnerability.metadata_ or {})
        meta["delphi"] = {
            "kev": lookup.get("kev"),
            "vulncheck_kev": lookup.get("vulncheck_kev"),
            "kevintel": lookup.get("kevintel"),
            "shadowserver_exploited": lookup.get("shadowserver_exploited"),
            "kev_sources": lookup.get("kev_sources", []),
            "epss": lookup.get("epss"),          # stored for display, not scoring
            "priority": lookup.get("priority"),
            "likelihood_score": lookup.get("likelihood_score"),
            "priority_reason": lookup.get("priority_reason"),
            "priority_signals": lookup.get("priority_signals", []),
            "factors": lookup.get("factors", {}),
            "enriched_at": datetime.utcnow().isoformat(),
        }
        vulnerability.metadata_ = meta

        # Update tags for filtering in the findings UI.
        tags = list(vulnerability.tags or [])
        if lookup.get("kev") and "cisa-kev" not in tags:
            tags.append("cisa-kev")
            if (lookup.get("kev") or {}).get("known_ransomware_use", "").lower() in ("known", "yes"):
                if "ransomware" not in tags:
                    tags.append("ransomware")
        if lookup.get("vulncheck_kev") and "vulncheck-kev" not in tags:
            tags.append("vulncheck-kev")
        if lookup.get("shadowserver_exploited") and "shadowserver" not in tags:
            tags.append("shadowserver")
        if lookup.get("kevintel") and "kevintel" not in tags:
            tags.append("kevintel")

        # Add breach intel tags when present.
        for signal in (lookup.get("priority_signals") or []):
            if signal == "mandiant_mtrends" and "mandiant-mtrends" not in tags:
                tags.append("mandiant-mtrends")
            if signal == "crowdstrike_gtr" and "crowdstrike-gtr" not in tags:
                tags.append("crowdstrike-gtr")
            if signal == "fire_insurance_loss" and "fire" not in tags:
                tags.append("fire")

        # Delphi priority tag (replaces EPSS-bucket tags).
        priority_tag = f"delphi-priority-{lookup.get('priority', 'none')}"
        if priority_tag not in tags and lookup.get("priority") not in ("none", None):
            tags.append(priority_tag)
        vulnerability.tags = tags

        return lookup

    def enrich_and_update(self, vulnerability_id: int) -> Dict[str, Any]:
        """Load a vulnerability, enrich it, persist, and return the lookup."""
        from app.db.database import SessionLocal
        from app.models.vulnerability import Vulnerability

        db = SessionLocal()
        try:
            vuln = db.query(Vulnerability).filter(Vulnerability.id == vulnerability_id).first()
            if not vuln:
                return {"error": "Vulnerability not found"}
            result = self.enrich_vulnerability(vuln)
            db.commit()
            return result
        except Exception as exc:
            logger.error("Delphi enrich_and_update failed: %s", exc)
            db.rollback()
            return {"error": str(exc)}
        finally:
            db.close()

    def batch_enrich(self, organization_id: int, *, limit: Optional[int] = None) -> Dict[str, Any]:
        """Enrich every CVE-bearing vulnerability for an organization."""
        from app.db.database import SessionLocal
        from app.models.asset import Asset
        from app.models.vulnerability import Vulnerability

        db = SessionLocal()
        try:
            q = (
                db.query(Vulnerability)
                .join(Asset, Vulnerability.asset_id == Asset.id)
                .filter(Asset.organization_id == organization_id)
                .filter(Vulnerability.cve_id.isnot(None))
            )
            if limit:
                q = q.limit(limit)
            vulns = q.all()

            kev_hits = 0
            epss_hits = 0
            no_signal = 0
            errors = 0

            for vuln in vulns:
                try:
                    out = self.enrich_vulnerability(vuln)
                    if out.get("kev"):
                        kev_hits += 1
                    if out.get("epss"):
                        epss_hits += 1
                    if not out.get("enriched"):
                        no_signal += 1
                except Exception as exc:
                    errors += 1
                    logger.debug("Delphi enrich failed on vuln %s: %s", vuln.id, exc)

            db.commit()
            return {
                "total": len(vulns),
                "kev_hits": kev_hits,
                "epss_hits": epss_hits,
                "no_signal": no_signal,
                "errors": errors,
            }
        except Exception as exc:
            logger.error("Delphi batch_enrich failed: %s", exc)
            db.rollback()
            return {"error": str(exc)}
        finally:
            db.close()

    def stats(self) -> Dict[str, Any]:
        """Return catalog stats for /delphi/status."""
        self.ensure_loaded()
        return {
            "enabled": self.enabled,
            "kev_entries": len(self._kev),
            "epss_entries": len(self._epss),
            "epss_score_date": self._epss_date,
            "epss_role": "informational_display_only",
            "kev_catalog_version": self._kev_meta.get("catalog_version"),
            "kev_date_released": self._kev_meta.get("date_released"),
            "extended_kev_enabled": self.extended_enabled,
            "vulncheck_kev_entries": len(self._vulncheck_kev),
            "shadowserver_exploited_entries": len(self._shadowserver),
            "kevintel_entries": len(self._kevintel),
            "breach_intel": {
                "mandiant_mtrends_cves": len(self._mtrends),
                "crowdstrike_gtr_cves": len(self._gtr),
                "fire_cves": len(self._fire),
            },
            "priority_drivers": [
                "vulncheck_kev",  # broadest exploitation catalog
                "cisa_kev",
                "shadowserver",
                "kevintel",
                "breach_intel",
                "exploit_conditions(cvss_vector)",
                "reachability(asset_exposure)",
                "detection_confidence",
            ],
            "priority_model": "exploitation_likelihood",
            "refresh_hours": self.refresh_hours,
            "last_loaded": datetime.utcfromtimestamp(self._last_load_ts).isoformat() if self._last_load_ts else None,
        }

    def refresh(self) -> Dict[str, Any]:
        """Force a cache refresh of both feeds."""
        self.ensure_loaded(force_refresh=True)
        return self.stats()


# Global singleton
_delphi_service: Optional[DelphiEnrichmentService] = None


def get_delphi_service() -> DelphiEnrichmentService:
    global _delphi_service
    if _delphi_service is None:
        _delphi_service = DelphiEnrichmentService()
    return _delphi_service
