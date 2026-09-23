"""
Severity Evaluation — the platform's Likelihood × Impact risk model.

Runs on every finding in the ``vulnerabilities`` table, whether or not Aegis
Oracle analysed it. Oracle stays the exploitability engine (OPES plus the
evidence it gathers: KEV, exploit intel, preconditions, reachability); this
module turns that evidence — plus what the platform itself knows about the
finding, the asset, the organization's IP inventory and the business
application — into seven 0–4 factors and a risk score.

Every factor carries a reason and a source:

  auto     measured from evidence
  assumed  a default because the evidence is missing — needs an analyst
  agent    proposed by the gap agent — needs an analyst to confirm
  analyst  set by an analyst during triage

Pipeline: ``evaluate_finding`` computes the automatic factors and stores
them in ``metadata_["severity_eval"]``; ``apply_effective`` merges analyst
input (``metadata_["risk_overrides"]``) and writes the effective values to
the ``sev_*`` columns so the findings table can show, sort and filter them.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from app.services.risk_model import FACTOR_KEYS, merged_risk_model

logger = logging.getLogger(__name__)

EVALUATOR_VERSION = "sev/v1"

# ── Finding context ───────────────────────────────────────────────────────────

# Scanners that detect from outside without credentials: if they found it,
# attacker tooling can too.
EXTERNAL_AUTOMATED = {
    "nuclei", "port_scanner", "takeover_scanner", "graphql_scanner", "jsluice",
    "js_recon", "js_secret_scan", "auto_discovery", "scan_config", "logix_runtime",
    "github_secret_scanner", "trufflehog",
}
# Found by a person or an agent working the target by hand.
MANUAL_SOURCES = {"manual", "llm_red_team", "agent", "pentest"}
# Found only with credentials / an agent on the host / cloud API access.
CREDENTIALED_SOURCES = {"wiz", "tenable_agent", "tenable_credentialed", "qualys_agent", "crowdstrike"}

# Weakness classes whose exploitation is widely taught (CWE ceiling ≤ 3.0 in
# Oracle's difficulty model): they never need specialist skill.
WELL_DOCUMENTED_CWES = {
    "CWE-798", "CWE-259", "CWE-306", "CWE-288", "CWE-287", "CWE-284", "CWE-540",
    "CWE-200", "CWE-312", "CWE-319", "CWE-89", "CWE-78", "CWE-77", "CWE-94",
    "CWE-22", "CWE-23",
}

SEVERITY_SCORE = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "informational": 0}


@dataclass
class Precond:
    id: str
    description: str
    blocker: bool
    status: str  # satisfied | unsatisfied | unknown | "" (not evaluated)


@dataclass
class FindingContext:
    """Everything the rules read, flattened from the finding, Oracle's
    payload, the asset and the organization."""

    title: str = ""
    cve_id: str = ""
    cwe_id: str = ""
    scanner_severity: str = ""
    detected_by: str = ""
    template_id: str = ""
    is_manual: bool = False
    detection_confidence: str = ""  # exploit_confirmed | endpoint_confirmed | version_only | unknown
    validation_verdict: str = ""  # confirmed | false_positive | needs_more_evidence

    published_cvss: Optional[float] = None
    reconciled_cvss: Optional[float] = None
    cvss_vector: str = ""

    exploitation: Dict[str, Any] = field(default_factory=dict)
    attack_path: str = ""
    attacker_capability: str = ""
    exploit_complexity: str = ""
    remote_triggerability: str = ""
    preconditions: List[Precond] = field(default_factory=list)

    asset_criticality: str = ""
    exposure: str = ""  # internet | internal | isolated | ""
    hosting_type: str = ""  # owned | third_party | internal | unknown
    hosting_basis: str = ""
    hosting_provider: str = ""
    organization_name: str = ""
    auth_required: bool = False
    waf: str = ""

    business_app_name: str = ""
    business_app_criticality: Optional[int] = None  # 1 (most critical) – 4

    nuclei_templates: int = 0  # public Nuclei templates for the CVE (live intel)
    intel_sig: str = ""  # signature of the live intel merged in


# ── Factors ───────────────────────────────────────────────────────────────────

Factor = Dict[str, Any]


def _f(score: int, rating: str, reason: str, source: str = "auto") -> Factor:
    return {"score": score, "rating": rating, "reason": reason, "source": source}


def _vector_field(vector: str, key: str) -> str:
    for part in (vector or "").split("/"):
        k, _, v = part.partition(":")
        if k == key:
            return v
    return ""


def business_impact(ctx: FindingContext) -> Factor:
    # ServiceNow business application criticality is the authoritative
    # business view; asset criticality is the fallback.
    snow = {1: (4, "Critical"), 2: (3, "High"), 3: (2, "Medium"), 4: (1, "Low")}
    if ctx.business_app_criticality in snow:
        score, rating = snow[ctx.business_app_criticality]
        return _f(score, rating, f"Business application {ctx.business_app_name} is {rating.lower()} criticality (ServiceNow)")
    crit = (ctx.asset_criticality or "").lower()
    table = {"critical": (4, "Critical"), "high": (3, "High"), "low": (1, "Low")}
    if crit in table:
        score, rating = table[crit]
        return _f(score, rating, f"Asset classified {crit}")
    # "medium" is the platform default for every new asset, so it is not
    # evidence that anyone assessed the business impact.
    return _f(2, "Medium",
              "No business application linked and asset criticality is the default (medium); assumed medium",
              "assumed")


def org_hosted_rating(org_name: str) -> str:
    return f"{(org_name or '').strip() or 'Organization'} Hosted"


def network_location(ctx: FindingContext) -> Factor:
    hosting = (ctx.hosting_type or "").lower()
    basis = ctx.hosting_basis
    exposure = ctx.exposure
    if hosting in ("internal", "private"):
        exposure = "internal"
    if exposure == "isolated":
        return _f(0, "Segmented Network", "Asset is isolated / air-gapped")
    if exposure == "internal":
        return _f(1, "Internal Only", basis or "Asset is not internet-facing")
    if exposure == "internet":
        if hosting in ("third_party", "cloud", "cdn"):
            return _f(2, "Third Party Hosted", basis or f"Internet-facing on third-party infrastructure ({ctx.hosting_provider or hosting})")
        if hosting == "owned":
            return _f(4, org_hosted_rating(ctx.organization_name), basis or "Internet-facing on the organization's own infrastructure")
        return _f(4, org_hosted_rating(ctx.organization_name),
                  (basis or "Internet-facing; hosting not classified") + "; assumed organization-hosted until confirmed", "assumed")
    return _f(2, "Unknown", "Exposure unknown", "assumed")


def vulnerability_severity(ctx: FindingContext) -> Factor:
    cvss = ctx.reconciled_cvss or ctx.published_cvss
    if cvss:
        label = f"CVSS {cvss:.1f}"
        if ctx.reconciled_cvss:
            label += " (reconciled"
            if ctx.published_cvss and abs(ctx.published_cvss - ctx.reconciled_cvss) > 0.05:
                label += f"; published {ctx.published_cvss:.1f}"
            label += ")"
        for threshold, score, rating in ((9.0, 4, "Critical"), (7.0, 3, "High"), (4.0, 2, "Medium"), (0.1, 1, "Low")):
            if cvss >= threshold:
                return _f(score, rating, label)
    risk = float(ctx.exploitation.get("misconfig_breach_risk") or 0)
    if risk > 0:
        cls = ctx.exploitation.get("misconfig_breach_class") or "misconfiguration"
        if risk >= 8.5:
            return _f(4, "Critical", f"No CVSS; {cls} leads to full compromise in breach data")
        if risk >= 7.5:
            return _f(3, "High", f"No CVSS; {cls} exposes significant data or access")
        return _f(2, "Medium", f"No CVSS; {cls} has limited impact")
    sev = (ctx.scanner_severity or "").lower()
    if sev in SEVERITY_SCORE:
        score = SEVERITY_SCORE[sev]
        rating = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Informational"}[score]
        return _f(score, rating, f"No CVSS; rated {sev} by {ctx.detected_by or 'the scanner'}")
    return _f(2, "Medium", "No CVSS or scanner severity; assumed medium", "assumed")


def exploit_realism(ctx: FindingContext) -> Dict[str, Any]:
    """Can the known exploit realistically work against this asset?"""
    blocked: List[str] = []
    conditional: List[str] = []
    verified: List[str] = []

    for p in ctx.preconditions:
        if not p.blocker:
            continue
        desc = p.description or p.id
        if p.status == "unsatisfied":
            blocked.append(f"required condition not met: {desc}")
        elif p.status == "satisfied":
            verified.append(f"required condition met: {desc}")
    if ctx.exposure == "isolated":
        blocked.append("asset is isolated / air-gapped")

    av = _vector_field(ctx.cvss_vector, "AV")
    if av == "A" and ctx.exposure == "internet":
        conditional.append("needs adjacent-network access (AV:A), not reachable from the internet")
    elif av in ("L", "P"):
        conditional.append(f"needs local or physical access (AV:{av})")

    if ctx.remote_triggerability == "no":
        conditional.append("cannot be triggered remotely")
    elif ctx.remote_triggerability == "conditional":
        conditional.append("only remotely triggerable under specific conditions")
    path_needs = {
        "lateral_movement_required": "attacker needs a foothold on the network first",
        "valid_credentials_required": "attacker needs valid credentials first",
        "phishing_delivery": "attacker needs a victim to open or click something",
    }
    if ctx.attack_path in path_needs:
        conditional.append(path_needs[ctx.attack_path])
    if ctx.attacker_capability == "code_execution_required":
        conditional.append("attacker needs existing code execution")
    elif ctx.attacker_capability == "physical":
        conditional.append("attacker needs physical access")
    elif ctx.attacker_capability == "unauthenticated_network":
        if ctx.auth_required:
            conditional.append("unauthenticated exploit, but the asset requires authentication in front")
        if ctx.waf:
            conditional.append(f"unauthenticated exploit, but a WAF ({ctx.waf}) sits in front")

    if ctx.detection_confidence == "exploit_confirmed" or ctx.validation_verdict == "confirmed":
        why = "exploit or vulnerable code path confirmed on this asset"
        why += " by validation" if ctx.validation_verdict == "confirmed" else " by our scanner"
        return {"score": 4, "tier": "confirmed", "reasons": [why]}
    if blocked:
        return {"score": 0, "tier": "blocked",
                "reasons": blocked + ["documented exploit paths do not work here today; not a guarantee against other paths"]}
    if conditional:
        return {"score": 2, "tier": "conditional", "reasons": conditional}
    if ctx.detection_confidence == "endpoint_confirmed" or verified:
        reasons = (["vulnerable feature confirmed live on this asset"] if ctx.detection_confidence == "endpoint_confirmed" else []) + verified
        return {"score": 4, "tier": "likely", "reasons": reasons}
    if float(ctx.exploitation.get("misconfig_breach_risk") or 0) > 0 and not ctx.cve_id:
        return {"score": 4, "tier": "likely", "reasons": ["exposure observed directly on this asset"]}
    if ctx.detected_by in EXTERNAL_AUTOMATED and not ctx.cve_id:
        return {"score": 4, "tier": "likely", "reasons": [f"issue observed directly on this asset by {ctx.detected_by}"]}
    if ctx.detection_confidence == "version_only":
        return {"score": 3, "tier": "unverified",
                "reasons": ["no asset evidence that the exploit applies (version match only); verify before treating as exploitable"]}
    return {"score": 3, "tier": "unverified", "reasons": ["no asset evidence either way; verify before treating as exploitable"]}


SKILL_RATINGS = {4: "No Technical Skills", 3: "Some Technical Skills", 2: "Advanced Computer User",
                 1: "Security Penetration Skills", 0: "Not Feasible"}


def _tooling_floor(ctx: FindingContext) -> Tuple[int, str]:
    e = ctx.exploitation
    if e.get("metasploit_available"):
        return 4, "Metasploit module"
    if e.get("vulncheck_weaponized"):
        return 4, "Weaponized exploit (VulnCheck)"
    if ctx.detection_confidence == "exploit_confirmed":
        return 4, "Automated scanner exploit check"
    if e.get("exploitdb_found") or e.get("vulncheck_public_exploit") or int(e.get("attackerkb_exploitability") or 0) >= 4:
        return 3, "Public exploit (Exploit-DB / VulnCheck)"
    if e.get("public_poc_found") or e.get("trickest_found"):
        return 2, "Public PoC"
    return 0, ""


def skill_level(ctx: FindingContext, realism: Dict[str, Any]) -> Factor:
    """OWASP threat-agent skill: how hard the flaw is to exploit, then
    lowered by tooling that automates it (never past what realism allows)."""
    vector = ctx.cvss_vector
    if not vector and not ctx.attacker_capability:
        risk = float(ctx.exploitation.get("misconfig_breach_risk") or 0)
        if risk >= 7.5:
            return _f(4, SKILL_RATINGS[4], "Exposure is usable with standard clients, no exploitation technique needed")
        if risk > 0:
            return _f(3, SKILL_RATINGS[3], "Misconfiguration abusable with basic security knowledge")
        floor, tool = _tooling_floor(ctx)
        if floor:
            return _f(floor, SKILL_RATINGS[floor], f"No CVSS vector; {tool} available")
        return _f(2, SKILL_RATINGS[2], "No CVSS vector or exploit analysis; assumed advanced user", "assumed")

    points = 1.0
    why: List[str] = []

    def add(v: float, reason: str) -> None:
        nonlocal points
        points += v
        why.append(reason)

    if _vector_field(vector, "AC") == "H":
        add(1.5, "high attack complexity (AC:H)")
    if _vector_field(vector, "AT") == "P":
        add(1.0, "attack requirements present (AT:P)")
    if _vector_field(vector, "UI") == "R":
        add(0.5, "needs user interaction (UI:R)")

    capability = ctx.attacker_capability
    cap_points = {
        "unauthenticated_network": (-1.0, "unauthenticated network attack"),
        "authenticated_low_priv": (0.0, "needs a low-privilege account"),
        "authenticated_high_priv": (1.0, "needs a high-privilege account"),
        "local_user": (1.0, "needs local access"),
        "code_execution_required": (2.0, "needs existing code execution"),
        "physical": (2.0, "needs physical access"),
    }
    if capability in cap_points:
        add(*cap_points[capability])
    else:
        pr = _vector_field(vector, "PR")
        if pr == "N":
            add(-1.0, "no privileges required (PR:N)")
        elif pr == "L":
            why.append("low privileges required (PR:L)")
        elif pr == "H":
            add(1.0, "high privileges required (PR:H)")

    if ctx.exploit_complexity == "low":
        add(-0.5, "low exploit complexity")
    elif ctx.exploit_complexity == "high":
        add(1.5, "high exploit complexity")
    path_points = {
        "lateral_movement_required": (1.0, "requires lateral movement from a foothold"),
        "valid_credentials_required": (0.5, "requires valid credentials"),
        "phishing_delivery": (0.5, "requires phishing delivery"),
    }
    if ctx.attack_path in path_points:
        add(*path_points[ctx.attack_path])
    blockers = sum(1 for p in ctx.preconditions if p.blocker)
    if blockers:
        add(min(blockers * 0.5, 1.5), f"{blockers} blocking precondition(s)")

    score = max(1, min(4, int(math.floor(4 - points + 0.5))))
    cwe = (ctx.cwe_id or "").upper()
    if cwe in WELL_DOCUMENTED_CWES and score < 2:
        score = 2
        why.append(f"{cwe} is a well-documented technique")
    if not why:
        why.append("standard exploitation, no special conditions")

    floor, tool = _tooling_floor(ctx)
    if floor > score:
        if capability in ("code_execution_required", "physical"):
            floor = min(floor, 2)
        floor = min(floor, realism["score"])
        if floor > score:
            why.append(f"{tool} automates exploitation (difficulty alone: {score})")
            score = floor
    return _f(score, SKILL_RATINGS[score], "; ".join(why))


def ease_of_discovery(ctx: FindingContext) -> Factor:
    tier = ctx.exploitation.get("attacker_discoverability_tier") or ""
    if tier == "mass_scanned":
        return _f(4, "Automated Tools Available", f"Mass-scanned in the wild ({ctx.exploitation.get('otx_pulse_count') or 0} OTX pulses)")
    if tier == "remote_exploit":
        return _f(4, "Automated Tools Available", "Remote scanner signatures detect it (Nuclei / Tenable remote)")
    if tier == "version_detectable":
        return _f(4, "Automated Tools Available", "Vulnerable version visible remotely to scanners")
    detector = (ctx.detected_by or "").lower()
    if ctx.nuclei_templates and tier != "credentialed_only":
        return _f(4, "Automated Tools Available", f"Public Nuclei template{'s' if ctx.nuclei_templates > 1 else ''} for this CVE")
    if detector in EXTERNAL_AUTOMATED or ctx.template_id:
        what = f"template {ctx.template_id}" if ctx.template_id else detector
        return _f(4, "Automated Tools Available", f"Found from outside by an automated scanner ({what}), so attacker tooling can too")
    if tier == "credentialed_only" or detector in CREDENTIALED_SOURCES:
        return _f(2, "Difficult", "Only detectable with credentials or an agent; an external attacker is blind to it")
    if ctx.is_manual or detector in MANUAL_SOURCES:
        return _f(3, "Easy", "Found by manual testing")
    if ctx.detection_confidence in ("exploit_confirmed", "endpoint_confirmed", "version_only"):
        return _f(4, "Automated Tools Available", "Detected by an automated check")
    if ctx.cve_id:
        return _f(3, "Easy", "Public CVE; no scanner coverage data", "assumed")
    return _f(3, "Easy", "No discoverability data; assumed detectable with effort", "assumed")


EASE_RATINGS = {4: "Automated Tools Available", 3: "Easy", 2: "Difficult", 1: "Practically Impossible", 0: "Not Exploitable Here"}


def ease_of_exploit(ctx: FindingContext, realism: Dict[str, Any]) -> Factor:
    e = ctx.exploitation
    risk = float(e.get("misconfig_breach_risk") or 0)
    if ctx.detection_confidence == "exploit_confirmed" or ctx.validation_verdict == "confirmed":
        f = _f(4, EASE_RATINGS[4], "Exploit confirmed against this asset")
    elif risk >= 7.5:
        f = _f(4, EASE_RATINGS[4], "Exposure is directly usable (no exploit needed)")
    elif e.get("metasploit_available") or e.get("vulncheck_weaponized"):
        f = _f(4, EASE_RATINGS[4], "Metasploit module or weaponized exploit available")
    elif e.get("exploitdb_found") or e.get("vulncheck_public_exploit") or e.get("public_poc_found") or e.get("trickest_found") or risk > 0:
        f = _f(3, EASE_RATINGS[3], "Public PoC / Exploit-DB entry; may need modification")
    elif ctx.exploit_complexity and ctx.exploit_complexity != "high":
        f = _f(2, EASE_RATINGS[2], "No public exploit; a working exploit must be built")
    elif not ctx.cve_id and ctx.detected_by in EXTERNAL_AUTOMATED:
        f = _f(3, EASE_RATINGS[3], f"Issue reproduced by {ctx.detected_by}; abuse follows directly from the finding")
    else:
        f = _f(1, EASE_RATINGS[1], "No known working exploit")
    if f["score"] > realism["score"]:
        f = _f(realism["score"], EASE_RATINGS[realism["score"]],
               f"{f['reason']}, but on this asset: {'; '.join(realism['reasons'])}")
    return f


def awareness(ctx: FindingContext) -> Factor:
    e = ctx.exploitation
    kev = e.get("in_kev_sources") or []

    def public(reason: str) -> Factor:
        return _f(4, "Public Knowledge", reason)

    if "cisa_kev" in kev:
        return public("Listed in CISA KEV (actively exploited)")
    if kev:
        return public(f"Listed in {', '.join(kev)} (actively exploited)")
    if e.get("ransomware_associated") or e.get("vulncheck_ransomware_count"):
        return public("Used by ransomware operators")
    if e.get("breach_confirmed") or e.get("fire_linked") or e.get("mandiant_mtrends") or e.get("crowdstrike_gtr"):
        return public("Linked to confirmed breaches")
    if (e.get("enisa_exploited") or e.get("vulncheck_reported_exploited") or e.get("zero_day_confirmed")
            or e.get("observation_sources") or e.get("vulncheck_threat_actor_count") or e.get("vulncheck_botnet_count")):
        return public("Exploitation observed in the wild")
    if (e.get("otx_active_campaign") or int(e.get("attackerkb_value") or 0) >= 4
            or e.get("cisa_ssvc_decision") in ("Immediate", "Out-of-Cycle") or e.get("metasploit_available")):
        return public("Widespread security-community attention")
    if ctx.cve_id:
        return public("Publicly disclosed CVE")
    risk = float(e.get("misconfig_breach_risk") or 0)
    if risk >= 7.5:
        return public("Exposure class is well known to attackers")
    if risk > 0 or ctx.detected_by in EXTERNAL_AUTOMATED:
        return _f(3, "Obvious", "Visible to anyone who scans the asset")
    if ctx.is_manual or ctx.detected_by in MANUAL_SOURCES:
        return _f(2, "Hidden", "Found by manual testing; not publicly disclosed")
    return _f(1, "Unknown", "No public disclosure (internal discovery)", "assumed")


def evaluate_context(ctx: FindingContext) -> Dict[str, Any]:
    """Compute the automatic factors for one finding."""
    realism = exploit_realism(ctx)
    factors = {
        "business_impact": business_impact(ctx),
        "network_location": network_location(ctx),
        "vulnerability_severity": vulnerability_severity(ctx),
        "skill_level": skill_level(ctx, realism),
        "ease_of_discovery": ease_of_discovery(ctx),
        "ease_of_exploit": ease_of_exploit(ctx, realism),
        "awareness": awareness(ctx),
    }
    return {
        "factors": factors,
        "exploit_realism": realism,
        "needs_analyst": [k for k in FACTOR_KEYS if factors[k]["source"] == "assumed"],
        "version": EVALUATOR_VERSION,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }


# ── Building the context from the database ────────────────────────────────────

def _preconditions(oracle: Dict[str, Any]) -> List[Precond]:
    evaluated = oracle.get("preconditions_evaluated") or (oracle.get("contextual_assessment") or {}).get("preconditions") or []
    out: List[Precond] = []
    for e in evaluated:
        p = e.get("precondition") or {}
        out.append(Precond(
            id=str(p.get("id") or ""),
            description=str(p.get("description") or ""),
            blocker=p.get("severity") == "blocker",
            status=str(e.get("status") or ""),
        ))
    if out:
        return out
    for p in oracle.get("preconditions") or []:  # intrinsic-only payload
        out.append(Precond(id=str(p.get("id") or ""), description=str(p.get("description") or ""),
                           blocker=p.get("severity") == "blocker", status=""))
    return out


def build_context(db: Session, vuln: Any) -> FindingContext:
    from app.models.asset import Asset
    from app.services.hosting_classification import classify_asset_hosting

    meta = vuln.metadata_ if isinstance(vuln.metadata_, dict) else {}
    oracle = meta.get("oracle") or {}
    recon = oracle.get("cvss_reconciliation") or {}
    contextual = oracle.get("contextual_assessment") or {}

    ctx = FindingContext(
        title=vuln.title or "",
        cve_id=(vuln.cve_id or "").strip(),
        cwe_id=(vuln.cwe_id or "").strip(),
        scanner_severity=getattr(vuln.severity, "value", str(vuln.severity or "")),
        detected_by=(vuln.detected_by or "").strip().lower(),
        template_id=vuln.template_id or "",
        is_manual=bool(vuln.is_manual),
        detection_confidence=(vuln.detection_confidence or "").lower(),
        validation_verdict=(vuln.last_validation_verdict or "").lower(),
        published_cvss=vuln.cvss_score,
        reconciled_cvss=recon.get("correct_score") or None,
        cvss_vector=recon.get("correct_vector") or vuln.cvss_vector or "",
        exploitation=dict(oracle.get("exploitation_evidence") or {}),
        attack_path=oracle.get("attack_path_class") or "",
        attacker_capability=oracle.get("attacker_capability") or contextual.get("required_capability") or "",
        exploit_complexity=oracle.get("exploit_complexity") or "",
        remote_triggerability=oracle.get("remote_triggerability") or "",
        preconditions=_preconditions(oracle),
    )

    # Live exploitation intel (KEV lists, exploit index, Nuclei) from the
    # local feed caches, so new exploitation re-scores without waiting for
    # Oracle to re-enrich.
    if ctx.cve_id:
        from app.services.severity_intel import intel_signature, live_intel, merge_evidence

        intel = live_intel(ctx.cve_id)
        ctx.exploitation = merge_evidence(ctx.exploitation, intel)
        ctx.nuclei_templates = int(intel.get("nuclei_template_count") or 0)
        ctx.intel_sig = intel_signature(intel)

    asset = db.query(Asset).filter(Asset.id == vuln.asset_id).first()
    if asset is not None:
        ctx.asset_criticality = (asset.criticality or "").lower()
        ctx.exposure = "internet" if asset.is_public else "internal"
        try:
            hosting = classify_asset_hosting(db, asset)
            ctx.hosting_type = hosting["hosting_type"]
            ctx.hosting_basis = hosting["basis"]
            ctx.hosting_provider = hosting["hosting_provider"]
            ctx.organization_name = hosting["organization_name"]
        except Exception as exc:  # noqa: BLE001
            logger.debug("hosting classification failed for asset %s: %s", asset.id, exc)
        if getattr(asset, "has_login_portal", False):
            ctx.auth_required = True

    app = _business_app(db, vuln, asset)
    if app is not None:
        ctx.business_app_name = app.name or app.app_id or ""
        ctx.business_app_criticality = app.criticality_level
    return ctx


def _business_app(db: Session, vuln: Any, asset: Any) -> Any:
    try:
        from app.models.business_application import BusinessApplication
    except ImportError:
        return None
    app_id = getattr(vuln, "business_app_id", None) or getattr(asset, "business_app_id", None)
    if not app_id:
        return None
    return db.query(BusinessApplication).filter(BusinessApplication.id == app_id).first()


# ── Persistence ───────────────────────────────────────────────────────────────

SEV_FACTOR_COLUMNS = {
    "business_impact": "sev_business_impact",
    "network_location": "sev_network_location",
    "vulnerability_severity": "sev_vulnerability_severity",
    "skill_level": "sev_skill_level",
    "ease_of_discovery": "sev_ease_of_discovery",
    "ease_of_exploit": "sev_ease_of_exploit",
    "awareness": "sev_awareness",
}


def apply_effective(db: Session, vuln: Any, org_name: Optional[str] = None) -> Dict[str, Any]:
    """Merge automatic factors with analyst input and write the sev_* columns."""
    # Stamp first and don't autoflush mid-way: the dirty tracker recognises
    # evaluator writes by this stamp, so scoring never re-triggers itself.
    vuln.sev_evaluated_at = datetime.utcnow()
    with db.no_autoflush:
        return _apply_effective(db, vuln, org_name)


def _apply_effective(db: Session, vuln: Any, org_name: Optional[str]) -> Dict[str, Any]:
    from app.models.asset import Asset
    from app.models.organization import Organization

    meta = vuln.metadata_ if isinstance(vuln.metadata_, dict) else {}
    org = (
        db.query(Organization.name, Organization.risk_weight_defaults)
        .join(Asset, Asset.organization_id == Organization.id)
        .filter(Asset.id == vuln.asset_id)
        .first()
    )
    if org_name is None:
        org_name = org[0] if org else ""
    view = merged_risk_model(meta.get("severity_eval"), meta.get("risk_overrides"), org_name, org[1] if org else None)
    for key, column in SEV_FACTOR_COLUMNS.items():
        f = view["factors"].get(key)
        setattr(vuln, column, f["score"] if f else None)
    realism = view.get("exploit_realism") or {}
    vuln.sev_exploit_realism = realism.get("tier")
    vuln.sev_score = view.get("score")
    vuln.sev_level = view.get("level")
    vuln.sev_status = view["status"]
    vuln.sev_pending = len(view["needs_analyst"])
    vuln.sev_evaluated_at = datetime.utcnow()
    return view


def evaluate_finding(db: Session, vuln: Any) -> Dict[str, Any]:
    """Run the rules on one finding, store the result and update columns.
    The caller commits."""
    vuln.sev_evaluated_at = datetime.utcnow()
    with db.no_autoflush:
        ctx = build_context(db, vuln)
    result = evaluate_context(ctx)
    meta = dict(vuln.metadata_ or {})
    # Keep any gap-agent proposals that still apply.
    previous = meta.get("severity_eval") or {}
    if previous.get("agent_proposals"):
        result["agent_proposals"] = previous["agent_proposals"]
    _apply_agent_proposals(result)
    meta["severity_eval"] = result
    vuln.metadata_ = meta
    flag_modified(vuln, "metadata_")
    vuln.sev_intel_sig = ctx.intel_sig or None
    return apply_effective(db, vuln, ctx.organization_name or None)


def _apply_agent_proposals(result: Dict[str, Any]) -> None:
    """Replace assumed factors with the gap agent's proposals (still flagged
    for analyst confirmation)."""
    # Start from the assumptions so a re-run replaces earlier proposals.
    for key, f in list(result["factors"].items()):
        if f.get("source") == "agent" and f.get("assumed"):
            result["factors"][key] = {"score": f["assumed"]["score"], "rating": f["assumed"].get("rating", f["rating"]),
                                      "reason": f["assumed"]["reason"], "source": "assumed"}
    proposals = result.get("agent_proposals") or {}
    for key, p in proposals.items():
        f = result["factors"].get(key)
        if f is None or f["source"] != "assumed":
            continue  # evidence now exists; the proposal no longer applies
        result["factors"][key] = {
            "score": int(p["score"]),
            "rating": p.get("rating") or f["rating"],
            "reason": p.get("rationale") or "Proposed by severity agent",
            "source": "agent",
            "confidence": p.get("confidence"),
            "assumed": {"score": f["score"], "rating": f["rating"], "reason": f["reason"]},
        }


# ── Scheduled re-evaluation (severity worker) ─────────────────────────────────

def evaluate_by_id(session_factory, vuln_id: int) -> bool:
    """Re-evaluate one finding in its own session and clear its dirty flag
    unless it changed again meanwhile. Never raises."""
    from app.models.vulnerability import Vulnerability
    from app.services.severity_dirty import clear_dirty

    started = datetime.utcnow()
    db = session_factory()
    try:
        vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
        if vuln is None:
            return False
        view = evaluate_finding(db, vuln)
        db.flush()
        clear_dirty(db, [vuln_id], started)
        db.commit()
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        logger.warning("Severity evaluation failed for vuln %s: %s", vuln_id, exc)
        return False
    finally:
        db.close()

    # Optionally ask the gap agent to estimate what the rules could not.
    from app.services import severity_agent

    if severity_agent.auto_enabled() and view.get("status") == "needs_analyst":
        meta = (vuln.metadata_ or {}).get("severity_eval") or {}
        if not meta.get("agent_run_at"):
            severity_agent.submit(vuln_id)
    return True


def run_dirty_batch(session_factory, limit: int = 500) -> Dict[str, int]:
    """Re-evaluate up to ``limit`` open findings whose inputs changed."""
    from app.models.vulnerability import Vulnerability, VulnerabilityStatus

    db = session_factory()
    try:
        ids = [
            row[0]
            for row in db.query(Vulnerability.id)
            .filter(
                Vulnerability.sev_dirty.is_(True),
                Vulnerability.status.in_([VulnerabilityStatus.OPEN, VulnerabilityStatus.IN_PROGRESS]),
            )
            .order_by(Vulnerability.sev_dirty_at.asc().nullsfirst(), Vulnerability.id)
            .limit(limit)
            .all()
        ]
    finally:
        db.close()
    ok = sum(1 for vid in ids if evaluate_by_id(session_factory, vid))
    return {"selected": len(ids), "evaluated": ok, "failed": len(ids) - ok}
