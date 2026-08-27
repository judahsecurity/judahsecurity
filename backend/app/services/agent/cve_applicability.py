"""CVE applicability from a passive homepage fingerprint.

Glasswing's cheap path for a named CVE (or versioned plugins): look up what
the CVE affects, GET the URL like a browser, compare product+version. That
verdict is a finding when the live version is in range — not leftover Nuclei.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from app.services.agent.passive_stack import (
    format_passive_stack,
    origin_from_url,
)


CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.I)
_URL_RE = re.compile(r"https?://[^\s\"'<>]+|(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s\"'<>]*)?", re.I)
_FULL_ASSESS_RE = re.compile(
    r"\b(full (?:scan|assessment)|pentest|authorized.{0,60}assessment|"
    r"find (?:all )?vulnerabilit|hunt (?:the )?(?:site|app|host)|"
    r"perform an? .{0,40}assessment)\b",
    re.I,
)
_APPLICABILITY_RE = re.compile(
    r"\b(applicab|check if|does .{0,60}affect|is .{0,40}vulnerable to|"
    r"in[- ]scope for|applies to)\b",
    re.I,
)

# Product name aliases used when matching vulnx / NVD prose to a live fingerprint.
_ALIASES: Dict[str, Tuple[str, ...]] = {
    "yoast seo": ("yoast", "yoast seo", "wordpress seo", "wordpress-seo", "yoast-seo", "yoastseo"),
    "wordpress": ("wordpress", "wordpress core", "wp", "wordpress.org"),
    "woocommerce": ("woocommerce", "woo commerce"),
    "elementor": ("elementor",),
    "contact form 7": ("contact form 7", "contact-form-7", "cf7"),
    "apache": ("apache", "apache httpd", "httpd", "apache http server"),
    "nginx": ("nginx",),
    "php": ("php",),
    "jetpack": ("jetpack",),
}

_RANGE_RES = (
    re.compile(
        r"(?:up to(?: and including)?|through|<=|≤|and below|or earlier|"
        r"all versions? (?:up to|through))\s*v?(\d+(?:\.\d+)*)",
        re.I,
    ),
    re.compile(r"(?:before|prior to|<)\s*v?(\d+(?:\.\d+)*)", re.I),
    re.compile(r"(?:fixed in|patched in|>)\s*v?(\d+(?:\.\d+)*)", re.I),
)


def parse_version_tuple(raw: str) -> Tuple[int, ...]:
    parts = [int(p) for p in re.split(r"[^\d]+", (raw or "").strip()) if p.isdigit()]
    return tuple(parts) if parts else (0,)


def version_cmp(a: str, b: str) -> int:
    ta, tb = parse_version_tuple(a), parse_version_tuple(b)
    n = max(len(ta), len(tb))
    ta = ta + (0,) * (n - len(ta))
    tb = tb + (0,) * (n - len(tb))
    if ta < tb:
        return -1
    if ta > tb:
        return 1
    return 0


def parse_affected_range(text: str) -> Dict[str, str]:
    """Best-effort upper bound from CVE prose / vulnx description."""
    blob = text or ""
    out: Dict[str, str] = {}
    m = _RANGE_RES[0].search(blob)
    if m:
        out["op"] = "<="
        out["version"] = m.group(1)
        return out
    m = _RANGE_RES[1].search(blob)
    if m:
        out["op"] = "<"
        out["version"] = m.group(1)
        return out
    m = _RANGE_RES[2].search(blob)
    if m:
        out["op"] = "<"
        out["version"] = m.group(1)
        return out
    return out


def version_in_range(live: str, spec: Dict[str, str]) -> Optional[bool]:
    if not live or not spec.get("version"):
        return None
    op = spec.get("op") or "<="
    cmp = version_cmp(live, spec["version"])
    if op == "<=":
        return cmp <= 0
    if op == "<":
        return cmp < 0
    if op == ">=":
        return cmp >= 0
    if op == ">":
        return cmp > 0
    return None


def _alias_set(name: str) -> set:
    key = (name or "").strip().lower()
    extra = _ALIASES.get(key, ())
    tokens = {key, key.replace(" ", "-"), key.replace("-", " ")}
    tokens.update(extra)
    return {t for t in tokens if t}


GENERIC_PLATFORMS = frozenset({"wordpress", "wp", "apache", "nginx", "php"})


def _norm_name(name: str) -> str:
    return re.sub(r"[-_]+", " ", (name or "").lower()).strip()


def products_match(cve_product: str, stack_name: str) -> bool:
    a = _alias_set(cve_product)
    b = _alias_set(stack_name)
    if a & b:
        return True
    ca, cb = _norm_name(cve_product), _norm_name(stack_name)
    if not ca or not cb:
        return False
    # "wordpress" must not match the plugin "wordpress seo" / wordpress-seo.
    if cb in GENERIC_PLATFORMS and ca != cb and not ca.startswith(cb + " core"):
        return False
    if ca in GENERIC_PLATFORMS and cb != ca and not cb.startswith(ca + " core"):
        return False
    if len(cb) >= 5 and cb in ca:
        return True
    if len(ca) >= 5 and ca in cb:
        return True
    return False


def cve_ids_in_text(text: str) -> List[str]:
    seen = []
    for m in CVE_RE.finditer(text or ""):
        cid = m.group(0).upper()
        if cid not in seen:
            seen.append(cid)
    return seen


def url_from_text(text: str) -> str:
    for m in _URL_RE.finditer(text or ""):
        raw = m.group(0).rstrip(".,);")
        if raw.lower().startswith("cve-"):
            continue
        if "://" not in raw and "." not in raw:
            continue
        origin = origin_from_url(raw)
        if origin:
            return origin
    return ""


def objective_text(state: Optional[Dict[str, Any]] = None) -> str:
    state = state or {}
    parts = [
        str(state.get("original_objective") or ""),
        str(state.get("objective") or ""),
    ]
    info = state.get("target_info") or {}
    parts.append(str(info.get("primary_target") or ""))
    return " ".join(parts)


def is_cve_applicability_question(state: Optional[Dict[str, Any]] = None) -> bool:
    """True when the operator asked 'does this CVE apply to this host?' — not a full pentest."""
    text = objective_text(state)
    if not cve_ids_in_text(text):
        return False
    if _FULL_ASSESS_RE.search(text):
        return False
    if _APPLICABILITY_RE.search(text):
        return True
    return bool(url_from_text(text)) and len(text) < 500


def cve_check_ran(state: Optional[Dict[str, Any]] = None) -> bool:
    for step in (state or {}).get("execution_trace") or []:
        if not isinstance(step, dict):
            continue
        if str(step.get("tool_name") or "") == "check_cve_applicability":
            return True
    return False


def last_cve_check_output(state: Optional[Dict[str, Any]] = None) -> str:
    for step in reversed((state or {}).get("execution_trace") or []):
        if not isinstance(step, dict):
            continue
        if str(step.get("tool_name") or "") == "check_cve_applicability":
            return str(step.get("tool_output") or "")
    return ""


def last_cve_verdict(state: Optional[Dict[str, Any]] = None) -> str:
    out = last_cve_check_output(state).lower()
    if "verdict: applicable" in out:
        return "applicable"
    if "verdict: not_applicable" in out:
        return "not_applicable"
    if cve_check_ran(state):
        return "unknown"
    return ""


def _trace_steps(state: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    return [
        s for s in ((state or {}).get("execution_trace") or [])
        if isinstance(s, dict)
    ]


def create_finding_succeeded(state: Optional[Dict[str, Any]] = None) -> bool:
    """True only when create_finding actually published — not a JUDGE GATE bounce."""
    for step in _trace_steps(state):
        if str(step.get("tool_name") or "") != "create_finding":
            continue
        if step.get("success") is False:
            continue
        out = str(step.get("tool_output") or "")
        low = out.lower()
        if "judge gate" in low or low.startswith("error"):
            continue
        return True
    return False


def validate_finding_submitted(state: Optional[Dict[str, Any]] = None) -> bool:
    for step in reversed(_trace_steps(state)):
        if str(step.get("tool_name") or "") != "validate_finding":
            continue
        out = str(step.get("tool_output") or "")
        return '"verdict": "SUBMIT"' in out or '"verdict":"SUBMIT"' in out
    return False


def applicability_pending_finding(state: Optional[Dict[str, Any]] = None) -> bool:
    """True when the check said applicable and a finding has not been published."""
    if last_cve_verdict(state) != "applicable":
        return False
    return not create_finding_succeeded(state)


CVE_ONLY_BLOCKED_TOOLS = frozenset({
    "fireteam_dispatch",
    "execute_wpscan",
    "execute_interceptor",
    "execute_deep_crawl",
    "execute_nuclei",
    "spawn_recon_workers",
    "wait_recon_workers",
    "execute_feroxbuster",
    "execute_ffuf",
    "sync_engagement_brain",
    "compare_requests",
    "execute_curl",
    "execute_sqlmap",
})


def cve_only_tool_block(
    tool_name: str,
    state: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    """Refuse hunt tools on a named-CVE applicability question."""
    if not tool_name or not is_cve_applicability_question(state):
        return None
    if tool_name not in CVE_ONLY_BLOCKED_TOOLS:
        return None
    return (
        f"Blocked: '{tool_name}' is a full-assessment hunt tool. This question is "
        "CVE applicability only. check_cve_applicability, then if VERDICT is "
        "applicable call validate_finding then create_finding (same title/target), "
        "then complete. Do not WPScan, Interceptor, fireteam, or admin-ajax. "
        "Version-in-range is the proof — WPScan is not required."
    )


def detect_applicability_hunt_loop(
    state: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Catch the Clearpath-style loop: named CVE question, then a pentest.

    After check_cve_applicability, hunt tools (WPScan, fireteam, admin-ajax
    compare_requests, Interceptor) mean Joshua wandered off the writeup path.
    """
    from collections import Counter

    if not is_cve_applicability_question(state) or not cve_check_ran(state):
        return None
    hunt: List[str] = []
    judge_bounce = False
    no_diff = 0
    for step in _trace_steps(state):
        name = str(step.get("tool_name") or "")
        out = str(step.get("tool_output") or "")
        low = out.lower()
        if name == "create_finding" and "judge gate" in low:
            judge_bounce = True
        if name in CVE_ONLY_BLOCKED_TOOLS:
            hunt.append(name)
        if name == "compare_requests" and "no_material_diff" in low:
            no_diff += 1
    if not hunt:
        return None
    counts = Counter(hunt)
    return {
        "loop": True,
        "kind": "cve_applicability_hunt",
        "hunt_tools": dict(counts),
        "judge_gate_bounce": judge_bounce,
        "pending_finding": applicability_pending_finding(state),
        "compare_no_diff": no_diff,
        "next": (
            "STOP the pentest. validate_finding → create_finding → complete. "
            "Do not WPScan, fireteam, or retry admin-ajax."
        ),
    }


def format_applicability_hunt_loop_note(hit: Dict[str, Any]) -> str:
    tools = hit.get("hunt_tools") or {}
    listed = ", ".join(f"{k}×{v}" for k, v in sorted(tools.items()))
    bounce = " JUDGE GATE bounce then kept hunting." if hit.get("judge_gate_bounce") else ""
    return (
        "\n\n## Loop detected — CVE applicability hunt\n"
        f"This is a named-CVE applicability question, not a pentest.{bounce} "
        f"Off-path hunt tools: {listed or 'none'}. "
        f"{hit.get('next') or ''}\n"
    )


def applicability_finding_fields(state: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    state = state or {}
    ids = cve_ids_in_text(objective_text(state))
    cve_id = ids[0] if ids else "CVE"
    url = url_from_text(objective_text(state))
    if not url:
        info = state.get("target_info") or {}
        url = origin_from_url(str(info.get("primary_target") or "")) or str(
            info.get("primary_target") or ""
        )
    out = last_cve_check_output(state)
    product, version = "fingerprinted product", ""
    m = re.search(r"-\s*(.+?)\s+(\d[\d.]*)\s+[→-]+\s+IN RANGE", out, re.I)
    if m:
        product, version = m.group(1).strip(), m.group(2)
    title = f"{cve_id} applicable — {product} {version} in published affected range".strip()
    description = (
        f"Passive homepage fingerprint places live {product} {version} inside the "
        f"published affected range for {cve_id}. This is Glasswing version-in-range "
        "applicability, not a working exploit payload. Auth preconditions from intel "
        "apply (Contributor+ stored XSS is Medium, not RCE)."
    )
    return {
        "title": title,
        "description": description,
        "severity": "medium",
        "target": url,
        "evidence": (out or "")[:2500],
        "cve_id": cve_id,
        "remediation": (
            "Upgrade the affected component past the fixed release in the CVE advisory. "
            "For Yoast SEO CVE-2026-1293 that is 26.9+."
        ),
    }


def cve_applicability_writeup_forced_step(
    state: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """After an applicable check: force validate_finding then create_finding."""
    if not is_cve_applicability_question(state):
        return None
    if last_cve_verdict(state) != "applicable":
        return None
    fields = applicability_finding_fields(state)
    if not validate_finding_submitted(state):
        return {
            "tool_name": "validate_finding",
            "tool_args": {
                "title": fields["title"],
                "description": fields["description"],
                "severity": fields["severity"],
                "target": fields["target"],
                "evidence": fields["evidence"],
                "cve_id": fields["cve_id"],
                "remediation": fields["remediation"],
            },
            "thought": (
                "Named CVE is version-applicable. Solomon gate first: validate_finding "
                "then create_finding. Do not WPScan or fireteam."
            ),
        }
    if not create_finding_succeeded(state):
        return {
            "tool_name": "create_finding",
            "tool_args": {
                "title": fields["title"],
                "description": fields["description"],
                "severity": fields["severity"],
                "target": fields["target"],
                "evidence": fields["evidence"],
                "cve_id": fields["cve_id"],
                "remediation": fields["remediation"],
                "not_demonstrated": (
                    "No exploit payload, no Contributor login, no WPScan. "
                    "Proof is live product+version inside the published range."
                ),
            },
            "thought": (
                "validate_finding submitted. Publish the version-in-range finding, "
                "then complete — this is not a full pentest."
            ),
        }
    return None


def cve_applicability_should_complete(state: Optional[Dict[str, Any]] = None) -> bool:
    """True when the named-CVE question is answered and Joshua must stop hunting."""
    if not is_cve_applicability_question(state):
        return False
    if not cve_check_ran(state):
        return False
    if last_cve_verdict(state) == "applicable":
        return create_finding_succeeded(state)
    return True


def match_cve_to_stack(
    *,
    cve_id: str,
    intel_text: str,
    products: Sequence[Dict[str, str]],
    affected_products: Optional[Sequence[Any]] = None,
) -> Dict[str, Any]:
    """Compare live fingerprints to CVE intel. Pure — no network."""
    cve_id = (cve_id or "").strip().upper()
    intel_text = intel_text or ""
    spec = parse_affected_range(intel_text)
    names_from_intel: List[str] = []
    for p in affected_products or []:
        if isinstance(p, dict):
            names_from_intel.append(str(p.get("product") or p.get("name") or ""))
            names_from_intel.append(str(p.get("vendor") or ""))
        else:
            names_from_intel.append(str(p))
    # Also scrape product names from prose
    blob_l = intel_text.lower()
    plugin_cve = bool(re.search(r"\bplugin\b", blob_l))
    for canonical, aliases in _ALIASES.items():
        if canonical in GENERIC_PLATFORMS and plugin_cve and " core" not in blob_l:
            continue
        if any(re.search(rf"\b{re.escape(a)}\b", blob_l) for a in aliases if len(a) >= 4):
            names_from_intel.append(canonical)

    hits: List[Dict[str, Any]] = []
    product_present = False
    for live in products or []:
        lname = str(live.get("name") or "")
        matched = any(products_match(n, lname) for n in names_from_intel if n)
        if not matched:
            continue
        product_present = True
        live_ver = str(live.get("version") or "")
        in_range = version_in_range(live_ver, spec) if live_ver and spec else None
        hits.append({
            "product": lname,
            "version": live_ver,
            "evidence": live.get("evidence") or "",
            "source": live.get("source") or "",
            "in_range": in_range,
            "range": spec,
        })

    verdict = "unknown"
    if not products:
        verdict = "unknown"
    elif not product_present:
        verdict = "not_applicable"
    else:
        ranged = [h for h in hits if h.get("in_range") is True]
        out_of = [h for h in hits if h.get("in_range") is False]
        if ranged:
            verdict = "applicable"
        elif out_of and not ranged:
            verdict = "not_applicable"
        elif product_present and not spec:
            verdict = "product_present_version_unknown"
        else:
            verdict = "product_present_version_unknown"

    return {
        "cve_id": cve_id,
        "verdict": verdict,
        "affected_range": spec,
        "hits": hits,
        "product_present": product_present,
    }


def format_applicability_report(
    *,
    url: str,
    products: Sequence[Dict[str, str]],
    match: Optional[Dict[str, Any]] = None,
    intel: str = "",
    extra: str = "",
) -> str:
    lines = [
        f"# CVE applicability (passive fingerprint)",
        f"URL: {url}",
        format_passive_stack(products),
        "",
    ]
    if match:
        verdict = str(match.get("verdict") or "unknown")
        lines.append(f"CVE: {match.get('cve_id') or '?'}")
        lines.append(f"VERDICT: {verdict}")
        spec = match.get("affected_range") or {}
        if spec:
            lines.append(f"Affected range (from intel): {spec.get('op')} {spec.get('version')}")
        for h in match.get("hits") or []:
            ir = h.get("in_range")
            flag = "IN RANGE" if ir is True else ("OUT OF RANGE" if ir is False else "VERSION UNCOMPARED")
            lines.append(
                f"  - {h.get('product')} {h.get('version') or '?'} → {flag}"
                + (f" ({h.get('source')})" if h.get("source") else "")
            )
            if h.get("evidence"):
                lines.append(f"    evidence: {h['evidence']}")
        lines.append("")
        if verdict == "applicable":
            lines.append(
                "This is a finding: live product+version is inside the published "
                "affected range. Quote the evidence and the range. Note auth "
                "preconditions from intel (Contributor+ XSS is Medium, not RCE). "
                "Do NOT require a working exploit payload. Next: validate_finding "
                "then create_finding with the same title/target. Then complete. "
                "Do not WPScan, Interceptor, or fireteam."
            )
        elif verdict == "not_applicable":
            lines.append(
                "Not applicable: the affected product is absent, or the live "
                "version is outside the affected range."
            )
        else:
            lines.append(
                "Inconclusive on version math — product may still be present. "
                "Do not declare the host clean of this CVE."
            )
    if intel:
        lines.append("")
        lines.append("## CVE intel (truncated)")
        lines.append(intel[:2500])
    if extra:
        lines.append("")
        lines.append(extra)
    return "\n".join(lines)


def cve_applicability_forced_step(
    state: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Deterministic next tool when a CVE ID is in the objective."""
    state = state or {}
    ids = cve_ids_in_text(objective_text(state))
    if not ids:
        return None
    if cve_check_ran(state):
        return None
    url = url_from_text(objective_text(state))
    if not url:
        info = state.get("target_info") or {}
        url = origin_from_url(str(info.get("primary_target") or ""))
    if not url:
        return None
    return {
        "tool_name": "check_cve_applicability",
        "tool_args": {"cve_id": ids[0], "url": url},
        "thought": (
            "Glasswing observe: look up the named CVE and passively fingerprint "
            "the live homepage (generator / plugin comments / Server header) "
            "before Interceptor or WPScan."
        ),
    }


def wordpress_cve_map_forced_step(
    origin: str,
    state: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Map versioned WP plugins to CVEs when no named CVE was in the question."""
    if not origin:
        return None
    if cve_check_ran(state):
        return None
    if cve_ids_in_text(objective_text(state)):
        return None
    return {
        "tool_name": "check_cve_applicability",
        "tool_args": {"url": origin},
        "thought": (
            "Glasswing observe: homepage plugin/core versions are in-play. "
            "Map them to published CVEs before REST enum / ajax SQLi."
        ),
    }
