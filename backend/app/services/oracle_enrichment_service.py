"""
Aegis Oracle enrichment service.

Bridges the ASM platform's `vulnerabilities` table to the Aegis Oracle daemon
so every vulnerability the platform tracks can carry Oracle's analyst-grade
analysis (OPES priority, attack path class, analyst brief, recommendation
narrative) alongside the existing Delphi enrichment.

Two enrichment paths are exposed:

  • `enrich_vulnerability_full(v)` — for a vulnerability that has both a CVE
    and an asset, run the full Oracle pipeline (Phase A + Phase B + OPES) by
    calling `POST /analyze`. This is the strongest signal: a complete OPES
    score plus the recommendation narrative scoped to *this* asset.

  • `enrich_vulnerability_intrinsic(v)` — when the vulnerability only has a
    CVE id (no Oracle-side asset), call `GET /cve/{id}` for the Phase-A
    intrinsic analysis: analyst brief, attack path class, preconditions, and
    observed exploitation evidence. Still high-signal — it just lacks
    asset-specific reachability and preconditions.

Both paths persist the result to `Vulnerability.metadata_["oracle"]`. The
key is namespaced so it never collides with the existing Delphi enrichment
under `metadata_["delphi"]`.

Why route through the bridge instead of writing directly to Oracle's own
findings table:

  • Oracle owns its own canonical CVE and asset rows. The ASM
    `Vulnerability` rows are detections (one per scan hit) and do not map
    1:1 to Oracle assets. Persisting the Oracle output on the
    `Vulnerability` row keeps the existing UI/queries working and avoids a
    new join.
  • Oracle's findings table remains the source of truth for full
    (CVE, asset) analyses; this service writes a denormalised summary.

The service is intentionally HTTP-client-only — it never imports Oracle's
Go code or its database directly. That keeps the ASM and Oracle services
independently deployable.
"""

from __future__ import annotations

import logging
import os
import re
import threading
import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional

import httpx
from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetType
from app.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)


def _utc_iso(dt: Optional[datetime]) -> str:
    """Return an RFC-3339 UTC string with a Z suffix.

    SQLAlchemy returns naive datetimes from TIMESTAMP WITHOUT TIME ZONE
    columns. Go's time.Time JSON unmarshaller rejects bare ISO strings like
    '2026-07-22T18:01:51.446024' — it requires a timezone (Z or offset).
    Naive datetimes are treated as UTC.
    """
    if dt is None:
        dt = datetime.now(timezone.utc)
    elif dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    # Prefer Z over +00:00 — both are RFC-3339, Z is what Go examples use.
    return dt.isoformat().replace("+00:00", "Z")


ORACLE_URL = os.getenv("ORACLE_URL", "http://aegis-oracle:8742").rstrip("/")
ORACLE_TIMEOUT = float(os.getenv("ORACLE_TIMEOUT", "180"))

# Maximum age of an existing enrichment before we refresh it on the next
# enrich_vulnerability_*() call. Lets the batch worker idempotently skip
# vulnerabilities that were enriched recently.
ENRICH_TTL_HOURS = int(os.getenv("ORACLE_ENRICH_TTL_HOURS", "168"))  # 7 days
EVIDENCE_TTL_HOURS = int(os.getenv("ORACLE_EVIDENCE_TTL_HOURS", "24"))


# Regex that recognises a well-formed CVE id. We accept up to 7 digits in
# the suffix so CVE-2026-1234567 is allowed; CVE.org's spec is "≥4 digits".
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)


# ─────────────────────────── Public surface ────────────────────────────────


class OracleUnavailable(Exception):
    """Raised when the Oracle daemon is unreachable.

    Callers should treat this as a transient — the batch worker, for
    instance, should leave the vulnerability untouched and retry on the
    next run instead of writing a stale/empty enrichment.
    """


class OracleInputError(ValueError):
    """Raised when a vulnerability can't be enriched due to bad inputs
    (missing or malformed CVE id, no matching asset, etc.). Permanent —
    retries won't help.
    """


def enrich_vulnerability(db: Session, vuln: Vulnerability, *, force: bool = False) -> Dict[str, Any]:
    """Enrich a single vulnerability with Oracle output.

    Picks the strongest enrichment path available:
      1. If both CVE id and a usable ASM asset exist → full `/analyze` with
         the asset payload supplied inline (Phase A + Phase B + OPES with
         asset-specific reachability scoring).
      2. Else if a CVE id exists → Phase-A `/cve/{id}` intrinsic analysis.
      3. Else → `/analyze-finding` for ASM-native findings such as leaked
         secrets, exposed services, cloud misconfigs, and anonymous databases.

    Returns the persisted `metadata_["oracle"]` payload. Idempotent: when
    `force=False` and the existing enrichment is within `ENRICH_TTL_HOURS`,
    returns the cached payload without an HTTP call.
    """
    oracle_asset = _build_oracle_asset(vuln.asset) if vuln.asset is not None else None
    context_hash = _context_hash(vuln, oracle_asset)
    if not force:
        cached = _existing_fresh_payload(vuln, context_hash=context_hash)
        if cached is not None:
            return cached

    cve_id = _normalise_cve_id(vuln.cve_id)
    if oracle_asset is not None:
        if cve_id:
            payload = _call_analyze(cve_id, oracle_asset)
        else:
            payload = _call_generic_finding(vuln, oracle_asset)
        payload["context_hash"] = context_hash
        return _persist(db, vuln, payload)
    if cve_id:
        payload = _call_intrinsic(cve_id)
        payload["context_hash"] = context_hash
        return _persist(db, vuln, payload)
    raise OracleInputError(f"vulnerability {vuln.id} has no usable cve_id and no usable asset context")


def enrich_many(db: Session, vulns: Iterable[Vulnerability], *, force: bool = False) -> Dict[str, int]:
    """Run `enrich_vulnerability` over a batch.

    Returns counts: {"enriched": n, "enriched_generic": n, "skipped_cached": n,
    "errors": n}. Continues on per-row failures so a single bad CVE id does
    not abort the batch.
    """
    counts = {"enriched": 0, "enriched_generic": 0, "skipped_cached": 0, "errors": 0}
    for v in vulns:
        try:
            cached = _existing_fresh_payload(v) if not force else None
            if cached is not None:
                counts["skipped_cached"] += 1
                continue
            payload = enrich_vulnerability(db, v, force=force)
            if payload.get("mode") == "generic_finding":
                counts["enriched_generic"] += 1
            else:
                counts["enriched"] += 1
        except OracleInputError as e:
            logger.info("oracle enrichment skipped: vuln=%s reason=%s", v.id, e)
            counts["errors"] += 1
        except OracleUnavailable as e:
            # Stop the batch on transient errors — retrying every row will
            # only hammer a down service. Re-raise so the worker can back off.
            logger.warning("oracle unavailable mid-batch; stopping: %s", e)
            raise
        except Exception as e:  # noqa: BLE001 — defensive boundary at the worker
            logger.exception("oracle enrichment failed for vuln=%s: %s", v.id, e)
            counts["errors"] += 1
    return counts


def get_oracle_payload(vuln: Vulnerability) -> Optional[Dict[str, Any]]:
    """Return the Oracle payload stored on a vulnerability, or None."""
    if not vuln.metadata_:
        return None
    payload = vuln.metadata_.get("oracle") if isinstance(vuln.metadata_, dict) else None
    return payload if isinstance(payload, dict) else None


def enqueue_background_enrichment(vuln_id: int, *, severity: str = "medium") -> None:
    """Submit a vulnerability to the universal scoring pipeline.

    Delegates to ScoringPipeline, which manages a shared priority queue and
    a fixed worker pool with retry/backoff. The pipeline automatically dedupes
    repeat submissions, so calling this function on a vuln_id that is already
    queued is a safe no-op.

    Note: In most cases you do NOT need to call this manually — the pipeline's
    SQLAlchemy event hooks fire automatically after every new Vulnerability
    commit. This function exists as an explicit escape hatch for callers that
    pre-date the universal hook (kept for backward compatibility).
    """
    try:
        from app.services.scoring_pipeline import get_scoring_pipeline
        pipeline = get_scoring_pipeline()
        if pipeline._running:
            pipeline.submit(vuln_id, severity=severity)
            return
    except Exception as exc:  # noqa: BLE001
        logger.debug("enqueue_background_enrichment: pipeline unavailable (%s), falling back to thread", exc)

    # Fallback: spawn a daemon thread if the pipeline isn't running yet
    # (e.g. during early startup before on_event("startup") fires).
    def _run(vid: int) -> None:
        try:
            from app.db.database import SessionLocal  # type: ignore[import]
            db: Session = SessionLocal()
            try:
                vuln = db.query(Vulnerability).filter(Vulnerability.id == vid).first()
                if vuln is None:
                    logger.debug("oracle background enrich: vuln %s not found", vid)
                    return
                enrich_vulnerability(db, vuln)
            except OracleUnavailable as exc:
                logger.warning("oracle background enrich: service unavailable for vuln %s: %s", vid, exc)
            except OracleInputError as exc:
                logger.info("oracle background enrich: skipped vuln %s: %s", vid, exc)
            except Exception as exc:  # noqa: BLE001
                logger.exception("oracle background enrich: unexpected error for vuln %s: %s", vid, exc)
            finally:
                db.close()
        except Exception as exc:  # noqa: BLE001
            logger.exception("oracle background enrich: session setup failed for vuln %s: %s", vid, exc)

    t = threading.Thread(target=_run, args=(vuln_id,), daemon=True, name=f"oracle-enrich-{vuln_id}")
    t.start()


# ─────────────────────────── Internals ─────────────────────────────────────


def _normalise_cve_id(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    s = raw.strip().upper()
    return s if _CVE_RE.match(s) else None


def _existing_fresh_payload(
    vuln: Vulnerability,
    *,
    context_hash: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Return the cached Oracle payload if it is still within TTL, else None.

    We treat any payload without an `enriched_at` timestamp as stale so the
    next call regenerates a structured one.
    """
    payload = get_oracle_payload(vuln)
    if not payload:
        return None
    expected_context_hash = context_hash or _context_hash(
        vuln,
        _build_oracle_asset(vuln.asset) if vuln.asset is not None else None,
    )
    if not payload.get("context_hash") or payload.get("context_hash") != expected_context_hash:
        return None
    stamp = payload.get("enriched_at")
    if not stamp:
        return None
    try:
        when = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    age_hours = (datetime.now(timezone.utc) - when).total_seconds() / 3600
    max_age_hours = min(ENRICH_TTL_HOURS, EVIDENCE_TTL_HOURS)
    return payload if age_hours <= max_age_hours else None


def _context_hash(vuln: Vulnerability, asset_payload: Optional[Dict[str, Any]]) -> str:
    """Hash the material finding and asset context used by Oracle.

    This makes cache invalidation event-driven: exposure, ports, detected
    software, authentication, finding evidence, and similar changes trigger a
    reassessment immediately instead of waiting for an age-only TTL.
    """
    material = {
        "cve_id": _normalise_cve_id(getattr(vuln, "cve_id", None)),
        "title": getattr(vuln, "title", None),
        "description": getattr(vuln, "description", None),
        "severity": str(getattr(vuln, "severity", "") or ""),
        "affected_component": getattr(vuln, "affected_component", None),
        "evidence": getattr(vuln, "evidence", None),
        "proof_of_concept": getattr(vuln, "proof_of_concept", None),
        "detection_confidence": getattr(vuln, "detection_confidence", None),
        "asset": asset_payload,
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:24]


def _component_key(name: str) -> str:
    """Return the canonical signal-path token for a detected component."""
    return re.sub(r"[^a-z0-9]+", "", name.lower())


def _evidence(
    path: str,
    value: Any,
    *,
    source: str,
    observed_at: Optional[datetime],
    scope: str,
) -> Dict[str, Any]:
    observed = observed_at or datetime.now(timezone.utc)
    if observed.tzinfo is None:
        observed = observed.replace(tzinfo=timezone.utc)
    valid_until = observed + timedelta(hours=EVIDENCE_TTL_HOURS)
    freshness = "fresh" if valid_until >= datetime.now(timezone.utc) else "stale"
    return {
        "signal_path": path,
        "value": str(value).lower() if isinstance(value, bool) else str(value),
        "source": source,
        "scope": scope,
        "collected_by": "judah-asm",
        "observed_at": _utc_iso(observed),
        "valid_until": _utc_iso(valid_until),
        "freshness": freshness,
    }


def _build_oracle_asset(asset: Asset) -> Optional[Dict[str, Any]]:
    """Project an ASM `Asset` ORM row into the Oracle daemon's
    `schema.Asset` JSON shape.

    Why we marshal inline instead of mirroring assets into Oracle's DB:
    the ASM is the source of truth for asset state. Pushing every detection
    update into Oracle would mean either a tight write-coupling or a
    background sync that's always slightly stale. Sending the asset payload
    inline with each `/analyze` call lets the analysis see exactly what the
    ASM currently knows — at the cost of a slightly larger request.

    Returns None when we don't have enough to do better than intrinsic-only
    analysis. The caller falls back to `GET /cve/{id}` in that case.

    Field mapping highlights (Oracle path ← ASM column):
      * `signals.network.internet_facing` ← `Asset.is_public`
      * `signals.network.open_ports`      ← `Asset.port_services`
      * `signals.http.server_banner`      ← `Asset.http_title`
      * `signals.tls.subject`/issuer       ← `Asset.ssl_info`
      * `signals.tech_stack[]`             ← `Asset.technologies` +
                                             port_services product/version
      * `signals.auth.required`            ← inferred from `has_login_portal`
      * `criticality`                      ← `Asset.criticality`
      * `exposure`                         ← `is_public` ? internet : internal
    """
    if asset is None:
        return None
    if not asset.value:
        return None

    asset_id = f"asm-{asset.id}"
    observed_at = asset.updated_at or datetime.now(timezone.utc)
    signal_evidence: Dict[str, List[Dict[str, Any]]] = {}

    def record(path: str, value: Any, source: str) -> None:
        signal_evidence.setdefault(path, []).append(
            _evidence(
                path,
                value,
                source=source,
                observed_at=observed_at,
                scope=asset_id,
            )
        )

    # Network signals — open ports + WAF detection from technologies.
    open_ports: List[int] = []
    if asset.port_services:
        seen = set()
        for ps in asset.port_services:
            if ps is None or ps.port is None:
                continue
            state = getattr(getattr(ps, "state", None), "value", None) or str(getattr(ps, "state", "")).lower()
            if state and state != "open":
                continue
            if ps.port in seen:
                continue
            seen.add(ps.port)
            open_ports.append(int(ps.port))

    waf_name = _detect_waf(asset)

    network: Dict[str, Any] = {}
    if asset.is_public is not None:
        network["internet_facing"] = bool(asset.is_public)
        record("network.internet_facing", bool(asset.is_public), "asm_inventory")
    if open_ports:
        network["open_ports"] = open_ports
        record("network.open_ports", ",".join(str(port) for port in open_ports), "asm_port_scan")
    if waf_name:
        network["waf"] = waf_name
        record("network.waf", waf_name, "asm_technology_detection")

    # HTTP signals — best-effort from indexer fields. Many assets won't
    # have a banner; Phase B treats missing as PreconditionUnknown rather
    # than penalising the score.
    http: Dict[str, Any] = {}
    if asset.http_headers and isinstance(asset.http_headers, dict):
        http["headers"] = {k: str(v) for k, v in asset.http_headers.items()}
    if asset.http_title:
        http["server_banner"] = asset.http_title

    # TLS signals — populated from the SSL inspector or per-port TLS data.
    tls: Dict[str, Any] = {}
    if asset.ssl_info and isinstance(asset.ssl_info, dict):
        if asset.ssl_info.get("subject"):
            tls["subject"] = str(asset.ssl_info["subject"])
        if asset.ssl_info.get("issuer"):
            tls["issuer"] = str(asset.ssl_info["issuer"])

    # Tech stack — combine Wappalyzer-detected Technology rows with the
    # service_product/service_version emitted by nmap. Both sources have
    # their blind spots; the union is usually more representative.
    tech_stack: List[Dict[str, Any]] = []
    seen_tech = set()
    for tech in asset.technologies or []:
        name = (tech.name or "").strip()
        if not name or name.lower() in seen_tech:
            continue
        seen_tech.add(name.lower())
        tech_stack.append({"name": name, "confidence": 0.9})
    for ps in asset.port_services or []:
        prod = (ps.service_product or "").strip()
        if not prod or prod.lower() in seen_tech:
            continue
        seen_tech.add(prod.lower())
        entry: Dict[str, Any] = {"name": prod, "confidence": 0.7}
        if ps.service_version:
            entry["version"] = ps.service_version
        tech_stack.append(entry)
    # If the ASM detected an operating system, surface it as a tech entry —
    # Phase A preconditions often reference OS names for OS-specific CVEs.
    if asset.operating_system:
        if asset.operating_system.lower() not in seen_tech:
            seen_tech.add(asset.operating_system.lower())
            tech_stack.append({"name": asset.operating_system, "confidence": 0.8})

    # Auth signals — we can rarely confirm "auth required" without a full
    # crawl, but a known login portal is strong evidence the service has
    # *some* auth surface. Phase B uses this to evaluate UI:R-style
    # preconditions.
    auth: Dict[str, Any] = {}
    if asset.has_login_portal:
        auth["required"] = True
        record("auth.required", True, "asm_http_probe")
        if asset.login_portals and isinstance(asset.login_portals, list):
            # Best-effort method inference: SAML/OIDC URLs tend to mention it
            for lp in asset.login_portals:
                if not isinstance(lp, dict):
                    continue
                url = (lp.get("url") or "").lower()
                if "saml" in url:
                    auth["method"] = "saml"
                    record("auth.method", "saml", "asm_http_probe")
                    break
                if "oidc" in url or "/oauth" in url:
                    auth["method"] = "oidc"
                    record("auth.method", "oidc", "asm_http_probe")
                    break

    # Extra signals — anything not in the formal Oracle schema goes here
    # so the LLM still sees it when reasoning about preconditions.
    extra: Dict[str, str] = {}
    if asset.device_class:
        extra["device_class"] = str(asset.device_class)
    if asset.device_subclass:
        extra["device_subclass"] = str(asset.device_subclass)
    if asset.system_type:
        extra["system_type"] = str(asset.system_type)
    if asset.hosting_type:
        extra["hosting_type"] = str(asset.hosting_type)
    if asset.hosting_provider:
        extra["hosting_provider"] = str(asset.hosting_provider)
    if asset.country_code:
        extra["country_code"] = str(asset.country_code)
    if asset.has_login_portal:
        extra["has_login_portal"] = "true"
    if asset.tags and isinstance(asset.tags, list) and asset.tags:
        extra["tags"] = ",".join(str(t) for t in asset.tags if t)
    asset_type_val = (
        asset.asset_type.value if isinstance(asset.asset_type, AssetType) else str(asset.asset_type or "")
    )
    if asset_type_val:
        extra["asset_type"] = asset_type_val

    for key, value in extra.items():
        record(f"extra.{key}", value, "asm_inventory")

    # Technology detection establishes presence only. It deliberately does
    # not infer enabled, used, executing, or attacker-reachable state.
    components: List[Dict[str, Any]] = []
    for tech in tech_stack:
        key = _component_key(str(tech.get("name") or ""))
        if not key:
            continue
        version = str(tech.get("version") or "")
        path = f"components.{key}.installed"
        observation = _evidence(
            path,
            True,
            source="asm_technology_detection",
            observed_at=observed_at,
            scope=asset_id,
        )
        component: Dict[str, Any] = {
            "name": key,
            "installed": True,
            "evidence": [observation],
        }
        if version:
            component["version"] = version
            record(f"tech_stack.{tech['name']}", version, "asm_technology_detection")
            record(f"tech_stack.{tech['name']}.version", version, "asm_technology_detection")
        components.append(component)

    signals: Dict[str, Any] = {}
    if network:
        signals["network"] = network
    if http:
        signals["http"] = http
    if tls:
        signals["tls"] = tls
    if tech_stack:
        signals["tech_stack"] = tech_stack
    if auth:
        signals["auth"] = auth
    if components:
        signals["components"] = components
    if extra:
        signals["extra"] = extra
    if signal_evidence:
        signals["signal_evidence"] = signal_evidence

    payload: Dict[str, Any] = {
        "asset_id": asset_id,
        "hostname": asset.value,
        "ip": asset.ip_address or "",
        "open_ports": open_ports,
        "signals": signals,
        "criticality": _normalise_criticality(asset.criticality),
        "exposure": "internet" if asset.is_public else "internal",
        "source": "asm",
        "updated_at": _utc_iso(asset.updated_at),
    }
    return payload


_VALID_CRITICALITY = {"critical", "high", "medium", "low", "unknown"}


def _normalise_criticality(raw: Optional[str]) -> str:
    """Map the ASM's free-form criticality string to Oracle's enum.

    ASM ships strings like "low", "medium", "high", "critical" (lowercase)
    but users can edit them, so we coerce anything unexpected to "unknown"
    rather than letting the Oracle daemon reject the payload.
    """
    if not raw:
        return "unknown"
    s = str(raw).strip().lower()
    return s if s in _VALID_CRITICALITY else "unknown"


def _detect_waf(asset: Asset) -> str:
    """Best-effort WAF detection from the asset's technology list. Returns
    a short identifier (e.g. "cloudflare") or "" when none are obvious.

    Phase A uses this in the rationale ("traffic transits Cloudflare WAF")
    and Phase B dampens the reachability score when a WAF sits in-path.
    """
    if not asset.technologies:
        return ""
    for tech in asset.technologies:
        if not tech or not tech.name:
            continue
        n = tech.name.lower()
        if "cloudflare" in n:
            return "cloudflare"
        if "akamai" in n:
            return "akamai"
        if "imperva" in n or "incapsula" in n:
            return "imperva"
        if "aws waf" in n or "aws-waf" in n:
            return "aws_waf"
        if "fastly" in n:
            return "fastly"
        if "azure front door" in n:
            return "azure_front_door"
        if "f5" in n or "big-ip" in n:
            return "f5"
    return ""


def _call_analyze(cve_id: str, asset_payload: Dict[str, Any]) -> Dict[str, Any]:
    """POST /analyze — full Phase A + Phase B + OPES pipeline with the
    asset supplied inline. Oracle never touches the ASM's asset DB.

    Oracle returns HTTP 200 in all non-input-error cases:
      • Normal path: analysis_status="complete", finding populated
      • Degraded path: analysis_status="failed", finding=nil, analysis_error set
        (LLM timeout, provider error, etc.)
    HTTP 4xx signals a permanent input problem; other errors are transient.
    """
    payload = {"cve_id": cve_id, "asset": asset_payload}
    try:
        with httpx.Client(base_url=ORACLE_URL, timeout=ORACLE_TIMEOUT) as client:
            resp = client.post("/analyze", json=payload)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPStatusError as e:
        # 4xx is a permanent input problem (malformed asset, unknown CVE
        # that even upstream sources don't have); 5xx is transient.
        if 400 <= e.response.status_code < 500:
            raise OracleInputError(_safe_oracle_error(e)) from e
        raise OracleUnavailable(_safe_oracle_error(e)) from e
    except httpx.RequestError as e:
        raise OracleUnavailable(f"oracle unreachable: {e}") from e

    finding = data.get("finding") or {}
    return _build_payload(
        mode="full",
        finding=finding,
        intrinsic=None,
        exploitation=data.get("exploitation") or {},
        analysis_status=data.get("analysis_status"),
        analysis_error=data.get("analysis_error"),
    )


def _call_intrinsic(cve_id: str) -> Dict[str, Any]:
    """GET /cve/{id} — Phase-A-only analysis. Used when no Oracle asset is
    available for the vulnerability."""
    try:
        with httpx.Client(base_url=ORACLE_URL, timeout=ORACLE_TIMEOUT) as client:
            resp = client.get(f"/cve/{cve_id}")
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPStatusError as e:
        if 400 <= e.response.status_code < 500:
            raise OracleInputError(_safe_oracle_error(e)) from e
        raise OracleUnavailable(_safe_oracle_error(e)) from e
    except httpx.RequestError as e:
        raise OracleUnavailable(f"oracle unreachable: {e}") from e

    return _build_payload(
        mode="intrinsic",
        finding=None,
        intrinsic=data.get("analysis") or {},
        exploitation=data.get("exploitation") or {},
        analysis_status=data.get("analysis_status"),
        analysis_error=data.get("analysis_error"),
    )


def _call_generic_finding(vuln: Vulnerability, asset_payload: Dict[str, Any]) -> Dict[str, Any]:
    """POST /analyze-finding — OPES-style enrichment for ASM-native findings
    that are not CVE-backed."""
    payload = {
        "vulnerability": _build_generic_vulnerability_payload(vuln),
        "asset": asset_payload,
    }
    try:
        with httpx.Client(base_url=ORACLE_URL, timeout=ORACLE_TIMEOUT) as client:
            resp = client.post("/analyze-finding", json=payload)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPStatusError as e:
        if 400 <= e.response.status_code < 500:
            raise OracleInputError(_safe_oracle_error(e)) from e
        raise OracleUnavailable(_safe_oracle_error(e)) from e
    except httpx.RequestError as e:
        raise OracleUnavailable(f"oracle unreachable: {e}") from e

    return _build_payload(
        mode="generic_finding",
        finding=data.get("finding") or {},
        intrinsic=None,
        exploitation=None,
        analysis_status=data.get("analysis_status"),
        analysis_error=data.get("analysis_error"),
    )


def _build_generic_vulnerability_payload(vuln: Vulnerability) -> Dict[str, Any]:
    metadata = vuln.metadata_ if isinstance(vuln.metadata_, dict) else {}
    return {
        "vulnerability_id": str(vuln.id),
        "title": vuln.title,
        "description": vuln.description or "",
        "severity": getattr(vuln.severity, "value", str(vuln.severity or "")),
        "cve_id": vuln.cve_id or "",
        "cwe_id": vuln.cwe_id or "",
        "cvss_score": vuln.cvss_score,
        "cvss_vector": vuln.cvss_vector or "",
        "affected_component": vuln.affected_component or "",
        "evidence": vuln.evidence or "",
        "proof_of_concept": vuln.proof_of_concept or "",
        "remediation": vuln.remediation or "",
        "detected_by": vuln.detected_by or "",
        "template_id": vuln.template_id or "",
        # Pass detection_confidence so Oracle can use it in OPES difficulty (E).
        # Fallback to "unknown" if the column is absent (older records).
        "detection_confidence": getattr(vuln, "detection_confidence", None) or "unknown",
        "tags": vuln.tags or [],
        "metadata": metadata,
        "created_at": _utc_iso(vuln.created_at) if vuln.created_at else None,
    }


def _build_payload(
    *,
    mode: str,
    finding: Optional[Dict[str, Any]],
    intrinsic: Optional[Dict[str, Any]],
    exploitation: Optional[Dict[str, Any]],
    analysis_status: Optional[str] = None,
    analysis_error: Optional[str] = None,
) -> Dict[str, Any]:
    """Build the denormalised payload we persist on `Vulnerability.metadata_`.

    The payload is the only Oracle data the ASM UI reads. We pick the
    fields most useful to a list view (so we don't have to fetch the full
    finding for each row) plus the full recommendation narrative for the
    detail view.
    """
    payload: Dict[str, Any] = {
        "mode": mode,
        "enriched_at": datetime.now(timezone.utc).isoformat(),
        "schema_version": 2,
    }
    if analysis_status:
        payload["analysis_status"] = analysis_status
    if analysis_error:
        payload["analysis_error"] = analysis_error

    if finding:
        opes = finding.get("opes") or {}
        payload.update({
            "finding_id": finding.get("finding_id"),
            "finding_class": finding.get("finding_class"),
            "vulnerability_id": finding.get("vulnerability_id"),
            "opes_score": opes.get("score"),
            "opes_category": opes.get("category"),
            "opes_label": opes.get("label"),
            "opes_confidence": opes.get("confidence"),
            "opes_components": opes.get("components"),
            "opes_dampener": opes.get("dampener"),
            "opes_override": opes.get("override"),
            "evaluator_version": opes.get("evaluator_version"),
            "attack_path_class": finding.get("attack_path_class"),
            "lateral_movement_potential": finding.get("lateral_movement_potential"),
            "analyst_brief": finding.get("analyst_brief"),
            "recommendation_text": finding.get("recommendation_text"),
            "cvss_reconciliation": finding.get("cvss_reconciliation"),
            "preconditions_evaluated": finding.get("preconditions_evaluated"),
            "contextual_assessment": finding.get("contextual_assessment"),
            "verification_tasks": finding.get("verification_tasks"),
            "exploitation_evidence": exploitation or {},
        })
        return payload

    if intrinsic:
        payload.update({
            "analysis_status": analysis_status or "complete",
            "attack_path_class": intrinsic.get("attack_path_class"),
            "lateral_movement_potential": intrinsic.get("lateral_movement_potential"),
            "analyst_brief": intrinsic.get("analyst_brief"),
            "preconditions": intrinsic.get("preconditions"),
            "cvss_reconciliation": intrinsic.get("cvss_reconciliation"),
            "remote_triggerability": intrinsic.get("remote_triggerability"),
            "exploit_complexity": intrinsic.get("exploit_complexity"),
            "attacker_capability": intrinsic.get("attacker_capability"),
            "attacker_starting_position": intrinsic.get("attacker_starting_position"),
            "affected_component": intrinsic.get("affected_component"),
            "realistic_workflow": intrinsic.get("realistic_workflow"),
            "input_source": intrinsic.get("input_source"),
            "attacker_influence": intrinsic.get("attacker_influence"),
            "resulting_capability": intrinsic.get("resulting_capability"),
            "exploit_paths": intrinsic.get("exploit_paths"),
            "transitions": intrinsic.get("transitions"),
            "confidence": intrinsic.get("confidence"),
            "exploitation_evidence": exploitation,
        })
    return payload


def _persist(db: Session, vuln: Vulnerability, payload: Dict[str, Any]) -> Dict[str, Any]:
    meta = dict(vuln.metadata_) if isinstance(vuln.metadata_, dict) else {}
    meta["oracle"] = payload
    vuln.metadata_ = meta

    # Promote key Oracle fields to dedicated columns for efficient querying.
    # Columns may not exist yet in older deployments; ignore AttributeError.
    try:
        from datetime import datetime as _dt
        vuln.oracle_opes_score      = payload.get("opes_score")
        vuln.oracle_opes_category   = payload.get("opes_category")
        vuln.oracle_opes_label      = payload.get("opes_label")
        vuln.oracle_opes_confidence = payload.get("opes_confidence")
        vuln.oracle_attack_path     = payload.get("attack_path_class")
        vuln.oracle_lateral_mvmt    = payload.get("lateral_movement_potential")
        vuln.oracle_mode            = payload.get("mode")
        vuln.oracle_analysis_status = payload.get("analysis_status")
        vuln.oracle_finding_id      = payload.get("finding_id")
        enriched_at_str = payload.get("enriched_at")
        if enriched_at_str:
            try:
                vuln.oracle_enriched_at = _dt.fromisoformat(
                    enriched_at_str.replace("Z", "+00:00")
                )
            except (ValueError, AttributeError):
                pass
    except AttributeError:
        pass

    # SQLAlchemy doesn't auto-detect JSON mutation; force a flush by
    # reassigning the dict (done above) plus an explicit commit by caller.
    db.add(vuln)
    db.commit()
    db.refresh(vuln)
    return payload


def _safe_oracle_error(e: httpx.HTTPStatusError) -> str:
    try:
        return e.response.json().get("error") or str(e)
    except Exception:  # noqa: BLE001
        return str(e)


# ─────────────────────────── Convenience helpers ───────────────────────────


def open_vulnerabilities_to_enrich(
    db: Session,
    *,
    organization_id: Optional[int] = None,
    limit: Optional[int] = 500,
) -> List[Vulnerability]:
    """Return open vulnerabilities eligible for Oracle enrichment, oldest-first.

    Used by the batch endpoint and the background worker. Scoped to an
    organization when the caller is not a superuser. Pass ``limit=None`` to
    return all matching rows (used by the backfill endpoint).
    """
    from app.models.vulnerability import VulnerabilityStatus
    q = (
        db.query(Vulnerability)
        .join(Asset, Vulnerability.asset_id == Asset.id)
        .filter(Vulnerability.status == VulnerabilityStatus.OPEN)
    )
    if organization_id is not None:
        q = q.filter(Asset.organization_id == organization_id)
    q = q.order_by(Vulnerability.created_at.asc())
    if limit is not None:
        q = q.limit(limit)
    return q.all()
