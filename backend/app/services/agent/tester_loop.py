"""
Curious-tester control loop.

Joshua (the scheduler) must observe, enumerate, and hunt unknown bugs — not
fingerprint and stop. A 404 / empty root is a reason to brute directories, not
to declare the host clean. Parameter mining and fireteam dispatch are required
before complete on web targets.

Known-CVE spray (Nuclei) is coverage leftover, never a substitute for this loop.
Informational Nuclei (tech/exposure/panel) runs as a parallel recon stream
(`nuclei_recon`) and does not count as that leftover coverage pass.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set
from urllib.parse import urlparse

_CRAWL_TOOLS = {
    "execute_interceptor",
    "execute_deep_crawl",
    "scoped_browser_crawl",
    "recon_worker:katana_urls",
    "execute_katana",
}
_DIR_BRUTE_TOOLS = {
    "execute_feroxbuster",
    "execute_ffuf",
    "recon_worker:ferox_dirs",
}
_PARAM_TOOLS = {
    "discover_parameters",
    "execute_arjun",
}
_BRAIN_TOOLS = {"sync_engagement_brain", "fireteam_dispatch"}
_JS_SURFACE_TOOLS = ("fingerprint_api", "fetch_lazy_chunks", "extract_js_endpoints")

_404_TEXT_RE = re.compile(
    r"\b(404|not found|doesn'?t exist|does not exist|page not found|cannot get|no route)\b",
    re.I,
)
_WEB_HINT_RE = re.compile(r"https?://|\bwww\.|\.(com|net|io|org|app)\b", re.I)
OBSERVED_INPUT_SOURCES = frozenset({
    "observed_form", "form_action", "captured_api", "browser_traffic",
    "browser_request", "page_url", "browser_link", "api_endpoint",
    "application_operation",
})


def _steps(trace: Optional[Iterable[Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for step in trace or []:
        if isinstance(step, dict):
            out.append(step)
    return out


def normalized_tools_run(trace: Optional[Iterable[Any]]) -> Set[str]:
    """Tool names plus aliases (recon_worker:ferox_dirs ≡ execute_feroxbuster)."""
    names: Set[str] = set()
    for step in _steps(trace):
        # A timed-out crawl or scanner is an attempt, not coverage. Counting it
        # as completed lets the agent skip the browser fallback and testing.
        if step.get("success") is False:
            continue
        name = str(step.get("tool_name") or "").strip()
        if not name:
            continue
        names.add(name)
        args = step.get("tool_args") or {}
        pack = ""
        kinds: Sequence[Any] = []
        if isinstance(args, dict):
            pack = str(args.get("pack") or "").lower()
            raw_kinds = args.get("kinds") or []
            if isinstance(raw_kinds, str):
                kinds = [raw_kinds]
            elif isinstance(raw_kinds, (list, tuple)):
                kinds = raw_kinds
        kinds_blob = " ".join(str(k) for k in kinds).lower()
        if name == "spawn_recon_workers":
            if pack in ("enrich", "full") or "ferox" in kinds_blob:
                names.add("dir_brute_started")
            if pack in ("enrich", "full") or "katana" in kinds_blob:
                names.add("crawl_enrich_started")
        if name == "recon_worker:ferox_dirs":
            names.add("execute_feroxbuster")
        if name == "recon_worker:katana_urls":
            names.add("execute_katana")
        if name == "execute_interceptor":
            names.add("execute_deep_crawl")
        if (name == "scoped_browser_assessment" and isinstance(args, dict)
                and args.get("operation") in ("crawl", "inspect_js")):
            names.add("scoped_browser_crawl")
    return names


def _kickoff_step(trace: Optional[Iterable[Any]]) -> Dict[str, Any]:
    for step in _steps(trace):
        if step.get("tool_name") == "assessment_kickoff":
            return step
    return {}


def surface_looks_empty(state: Optional[Dict[str, Any]] = None) -> bool:
    """True when the root looks like 404 / forbidden / empty — brute dirs."""
    state = state or {}
    if state.get("needs_dir_brute"):
        return True
    args = (_kickoff_step(state.get("execution_trace")).get("tool_args") or {})
    if isinstance(args, dict) and args.get("needs_dir_brute"):
        return True
    status = args.get("root_status") if isinstance(args, dict) else None
    try:
        if int(status) in (404, 403, 410):
            return True
    except (TypeError, ValueError):
        pass
    blob = " ".join(
        [
            str((_kickoff_step(state.get("execution_trace")).get("tool_output") or ""))[:1500],
            str(state.get("kickoff_brief") or "")[:1500],
        ]
    )
    if re.search(r"Root:\s*status=40[134]", blob) or _404_TEXT_RE.search(blob[:400]):
        return True
    cmap = state.get("capability_map") or {}
    pages = cmap.get("pages_visited") or []
    apis = cmap.get("api_endpoints") or []
    if cmap and not pages and not apis:
        return True
    notes = " ".join(str(n) for n in (cmap.get("notes") or [])[:6])
    if "thin" in notes.lower() and len(pages) <= 1 and not apis:
        return True
    return False


def is_web_target(state: Optional[Dict[str, Any]] = None) -> bool:
    state = state or {}
    cmap = state.get("capability_map") or {}
    if cmap:
        return True
    target = primary_web_target(state)
    if target:
        return True
    blob = " ".join(
        [
            str(state.get("objective") or ""),
            str(state.get("original_objective") or ""),
            str((state.get("target_info") or {}).get("primary_target") or ""),
        ]
    )
    return bool(_WEB_HINT_RE.search(blob) or "http" in blob.lower())


def primary_web_target(state: Optional[Dict[str, Any]] = None) -> str:
    state = state or {}
    info = state.get("target_info") or {}
    for raw in (
        info.get("primary_target"),
        (state.get("capability_map") or {}).get("target"),
        state.get("objective"),
        state.get("original_objective"),
    ):
        text = str(raw or "").strip()
        if not text:
            continue
        if text.startswith("http://") or text.startswith("https://"):
            return text.split()[0].rstrip(".,)")
        m = re.search(r"https?://[^\s\"']+", text)
        if m:
            return m.group(0).rstrip(".,)")
        parsed = urlparse("https://" + text.split()[0])
        if parsed.netloc and "." in parsed.netloc:
            return f"https://{parsed.netloc}"
    return ""


def observed_input_signature(state: Optional[Dict[str, Any]] = None) -> str:
    """Stable, value-free key for browser-observed inputs ready for a hunt wave."""
    cmap = (state or {}).get("capability_map") or {}
    if not isinstance(cmap, dict) or not cmap.get("target"):
        return ""
    from app.services.agent.parameter_inventory import _origin, collect_parameter_inventory

    active_origin = _origin(primary_web_target(state))
    if (not active_origin or _origin(str(cmap.get("target") or "")) != active_origin
            or (cmap.get("scope") and _origin(str(cmap["scope"])) != active_origin)):
        return ""

    inputs = sorted({
        (
            row["host"], row["method"], row["path"], row["location"],
            row["name"], row["identity"],
        )
        for row in collect_parameter_inventory(cmap)
        if row.get("testable") and row.get("source") in OBSERVED_INPUT_SOURCES
    })
    if not inputs:
        return ""
    return hashlib.sha256(json.dumps(inputs, separators=(",", ":")).encode()).hexdigest()[:16]


def _dispatched_input_signature(trace: List[Dict[str, Any]], signature: str) -> bool:
    return bool(signature) and any(
        step.get("tool_name") == "fireteam_dispatch"
        and (step.get("tool_args") or {}).get("surface_signature") == signature
        for step in trace
    )


def _full_fireteam_completed(trace: List[Dict[str, Any]]) -> bool:
    return any(
        step.get("tool_name") == "fireteam_dispatch"
        and step.get("success") is not False
        and (step.get("tool_args") or {}).get("mode") not in {
            "observed_inputs", "cms_followup", "coverage_followup",
        }
        and not (step.get("tool_args") or {}).get("surface_signature")
        for step in trace
    )


def cms_followup_product(state: Optional[Dict[str, Any]] = None) -> str:
    """Return a CMS with a concrete fingerprint in current assessment state."""
    state = state or {}
    from app.services.agent.wordpress_surface import wordpress_detected

    if wordpress_detected(state):
        return "WordPress"
    cmap = state.get("capability_map") or {}
    info = state.get("target_info") or {}
    signals = [
        *(info.get("technologies") or []),
        *((cmap.get("notes") or []) if isinstance(cmap, dict) else []),
        *((cmap.get("capabilities") or []) if isinstance(cmap, dict) else []),
    ]
    blob = " ".join(str(item) for item in signals)
    for product in ("Drupal", "Joomla", "Magento"):
        if re.search(rf"\b{product}\b", blob, re.I):
            return product
    return ""


def _cms_followup_dispatched(trace: List[Dict[str, Any]]) -> bool:
    return any(
        step.get("tool_name") == "fireteam_dispatch"
        and "cms_followup" in ((step.get("tool_args") or {}).get("specialists") or [])
        for step in trace
    )


def _untested_observed_input_count(state: Dict[str, Any]) -> int:
    brain = state.get("engagement_brain") or {}
    return sum(
        1
        for cell in (brain.get("coverage_cells") or [])
        if isinstance(cell, dict)
        and cell.get("source") == "parameter_inventory"
        and cell.get("observation_source") in OBSERVED_INPUT_SOURCES
        and cell.get("specialist") in {"xss", "sqli"}
        and cell.get("status") == "untested"
    )


def _pending_first_pass_count(state: Dict[str, Any]) -> int:
    from app.services.agent.observed_input_batch import pending_first_pass_cells

    return len(pending_first_pass_cells(
        state.get("engagement_brain") or {}, target=primary_web_target(state),
    ))


def _observed_input_batch_step(
    state: Dict[str, Any], trace: List[Dict[str, Any]], signature: str,
) -> Optional[Dict[str, Any]]:
    from app.services.agent.observed_input_batch import pending_first_pass_cells

    pending_cells = pending_first_pass_cells(
        state.get("engagement_brain") or {}, target=primary_web_target(state),
    )
    if not signature or not pending_cells:
        return None
    # The queue count can stay flat or grow when crawling discovers new inputs
    # while a batch is running. Compare the actual pending work instead.
    pending_signature = hashlib.sha256(json.dumps(sorted(
        str(cell.get("id") or "|".join(str(cell.get(key) or "") for key in (
            "host", "method", "path", "parameter", "test_type",
        ))) for cell in pending_cells
    ), separators=(",", ":")).encode()).hexdigest()[:16]
    prior = next((
        step for step in reversed(trace)
        if step.get("tool_name") == "probe_observed_input_batch"
        and (step.get("tool_args") or {}).get("surface_signature") == signature
    ), None)
    # Avoid a tight retry loop only when the same exact queue failed or made
    # no progress. A newly discovered input deserves its own first pass.
    if prior and (prior.get("tool_args") or {}).get("pending_batch_signature") == pending_signature:
        return None
    return {
        "tool_name": "probe_observed_input_batch",
        "tool_args": {
            "max_checks": 8, "max_seconds": 180,
            "target": primary_web_target(state),
            "surface_signature": signature,
            "pending_batch_signature": pending_signature,
            "pending_input_count": len(pending_cells),
        },
        "thought": "Run bounded SQLi and XSS first passes across observed inputs before deeper specialist work.",
    }


def _pending_candidate_verify_step(
    state: Dict[str, Any], trace: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    for candidate in ((state.get("engagement_brain") or {}).get("candidates") or []):
        if not isinstance(candidate, dict) or candidate.get("status") != "pending":
            continue
        if (candidate.get("vulnerability_class") not in {"sql_injection", "xss"}
                and candidate.get("specialist") not in {"sqli", "xss"}):
            continue
        candidate_id = str(candidate.get("id") or "")
        revision = max(1, int(candidate.get("revision") or 1))
        attempts = sum(
            step.get("tool_name") == "independent_verify"
            and (step.get("tool_args") or {}).get("candidate_id") == candidate_id
            and int((step.get("tool_args") or {}).get("candidate_revision") or 1) == revision
            for step in trace
        )
        if not candidate_id or attempts >= 2:
            continue
        return {
            "tool_name": "independent_verify",
            "tool_args": {"candidate_id": candidate_id,
                          "candidate_revision": revision, "max_parallel": 1},
            "thought": "Repeat the positive input proof independently before more discovery work.",
        }
    return None


def _unsubmitted_first_pass_proofs(
    state: Dict[str, Any], target: str,
) -> List[Dict[str, Any]]:
    """Find proof receipts that never made it across the candidate handoff."""
    from app.services.agent.parameter_inventory import _origin

    active_origin = _origin(target)
    if not active_origin:
        return []
    scheme = urlparse(active_origin).scheme
    brain = state.get("engagement_brain") or {}
    candidates = [row for row in (brain.get("candidates") or [])
                  if isinstance(row, dict)]
    return [
        cell for cell in (brain.get("coverage_cells") or [])
        if isinstance(cell, dict)
        and cell.get("source") == "parameter_inventory"
        and cell.get("test_type") in {"sqli", "xss"}
        and cell.get("specialist") == cell.get("test_type")
        and cell.get("first_pass_outcome") == "proof_signal"
        and cell.get("first_pass_evidence_id")
        and cell.get("id")
        and not any(
            row.get("coverage_cell_id") == cell["id"]
            and cell["first_pass_evidence_id"] in (row.get("evidence_ids") or [])
            for row in candidates
        )
        and str(cell.get("path") or "").startswith("/")
        and _origin(f"{scheme}://{cell.get('host') or ''}") == active_origin
    ]


def _failed_first_pass_handoffs(
    state: Dict[str, Any], target: str,
) -> List[Dict[str, Any]]:
    """Find attempted probe handoffs that never produced a proof receipt."""
    from app.services.agent.parameter_inventory import _origin

    active_origin = _origin(target)
    if not active_origin:
        return []
    scheme = urlparse(active_origin).scheme
    return [
        cell for cell in ((state.get("engagement_brain") or {}).get("coverage_cells") or [])
        if isinstance(cell, dict)
        and cell.get("source") == "parameter_inventory"
        and cell.get("test_type") in {"sqli", "xss"}
        and cell.get("first_pass_outcome") == "unattempted"
        and cell.get("first_pass_handoff_error")
        and _origin(f"{scheme}://{cell.get('host') or ''}") == active_origin
    ]


def _pending_first_pass_candidate_step(
    state: Dict[str, Any], trace: List[Dict[str, Any]], target: str,
) -> Optional[Dict[str, Any]]:
    from app.services.agent.parameter_inventory import _origin

    active_origin = _origin(target)
    for cell in _unsubmitted_first_pass_proofs(state, target):
        attempts = sum(
            step.get("tool_name") == "submit_finding_candidate"
            and (step.get("tool_args") or {}).get("coverage_cell_id") == cell["id"]
            for step in trace
        )
        if attempts >= 2:
            continue
        method = str(cell.get("method") or "GET").upper()
        _, _, parameter = str(cell.get("parameter") or "").partition(":")
        specialist = str(cell["specialist"])
        evidence_id = str(cell["first_pass_evidence_id"])
        return {
            "tool_name": "submit_finding_candidate",
            "tool_args": {
                "title": f"{specialist.upper()} proof on {method} {cell['path']} ({parameter})",
                "description": "Bounded observed-input probe returned an execution-owned proof signal.",
                "target": f"{active_origin}{cell['path']}",
                "evidence": f"First-pass proof receipt: {evidence_id}",
                "specialist": specialist,
                "coverage_cell_id": cell["id"],
                "evidence_ids": [evidence_id],
                "vulnerability_class": "sql_injection" if specialist == "sqli" else "xss",
            },
            "thought": "Hand the saved positive input proof to independent verification.",
        }
    return None


def _observed_input_specialists(state: Dict[str, Any]) -> List[str]:
    cells = (state.get("engagement_brain") or {}).get("coverage_cells") or []
    pending = {
        cell.get("specialist")
        for cell in cells
        if isinstance(cell, dict)
        and cell.get("source") == "parameter_inventory"
        and cell.get("observation_source") in OBSERVED_INPUT_SOURCES
        and cell.get("status") == "untested"
    }
    return [name for name in ("xss", "sqli") if name in pending] or ["xss", "sqli"]


def _input_wave_made_progress(
    state: Dict[str, Any], trace: List[Dict[str, Any]], signature: str
) -> bool:
    """Continue a leased input queue only when the last wave consumed work."""
    prior = next((
        step for step in reversed(trace)
        if step.get("tool_name") == "fireteam_dispatch"
        and (step.get("tool_args") or {}).get("surface_signature") == signature
    ), None)
    if not prior:
        return False
    previous = (prior.get("tool_args") or {}).get("pending_input_count")
    current = _untested_observed_input_count(state)
    return isinstance(previous, int) and 0 < current < previous


def _observed_input_wave(
    target: str, signature: str, pending_count: int, specialists: List[str],
    cms_product: str = "",
) -> Dict[str, Any]:
    chosen = [*specialists, *(["cms_followup"] if cms_product else [])]
    return {
        "tool_name": "fireteam_dispatch",
        "tool_args": {
            "specialists": chosen,
            "mode": "observed_inputs",
            "targets": [target],
            "surface_signature": signature,
            "pending_input_count": pending_count,
            "mission": (
                "Test browser-observed inputs for XSS and SQL injection first. "
                "Lease one concrete input per specialist; use live evidence "
                "and approved actions. "
                + (f"In parallel, investigate fingerprinted {cms_product} components and configuration. "
                   if cms_product else "")
                + "Other bug classes run in the full wave."
            ),
        },
        "thought": "Dispatch a parallel hunt wave on observed inputs now.",
    }


def _coverage_followup_wave(
    state: Dict[str, Any], trace: List[Dict[str, Any]], target: str,
) -> Optional[Dict[str, Any]]:
    """Give each applicable non-SQLi/XSS check one bounded first pass."""
    from app.services.agent.coverage_cells import CELL_OPEN, CELL_TERMINAL

    all_cells = [
        row for row in ((state.get("engagement_brain") or {}).get("coverage_cells") or [])
        if isinstance(row, dict)
        and row.get("source") in {"parameter_inventory", "surface_applicability", "js_inventory"}
        and row.get("test_type") not in {"xss", "sqli", "js_secret_review"}
    ]
    unattempted = [
        row for row in all_cells
        if row.get("status") in {*CELL_OPEN, "leased"}
        and not int(row.get("attempts") or 0)
        and not (row.get("first_pass_outcome") or row.get("candidate_id")
                 or row.get("probe_artifact_ids") or row.get("service_probe_artifact_ids"))
    ]
    cells = [row for row in unattempted if row.get("status") in CELL_OPEN]
    if not cells:
        return None
    prior_waves = [
        step for step in trace
        if step.get("tool_name") == "fireteam_dispatch"
        and (step.get("tool_args") or {}).get("mode") == "coverage_followup"
    ]
    if len(prior_waves) >= 64:
        return None
    if prior_waves:
        previous = (prior_waves[-1].get("tool_args") or {}).get("pending_coverage_count")
        if not isinstance(previous, int) or len(unattempted) >= previous:
            return None
    classes_by_specialist: Dict[str, set[str]] = {}
    for row in cells:
        specialist = str(row.get("specialist") or "")
        if specialist and specialist not in {"sqli", "js_secrets"}:
            classes_by_specialist.setdefault(specialist, set()).add(
                str(row.get("test_type") or "")
            )
    specialists = sorted(classes_by_specialist)[:6]
    if not specialists:
        return None
    classes = sorted({kind for name in specialists for kind in classes_by_specialist[name]})
    return {
        "tool_name": "fireteam_dispatch",
        "tool_args": {
            "specialists": specialists,
            "mode": "coverage_followup",
            "targets": [target],
            "pending_coverage_count": len(unattempted),
            "completed_coverage_count": sum(
                row.get("status") in CELL_TERMINAL for row in all_cells
            ),
            "mission": (
                "Execute the leased observed input, endpoint, or JavaScript lead "
                "for its assigned vulnerability class. For JavaScript, reproduce "
                "behavior on an observed page; the script URL is the source artifact. "
                "Use a baseline and a class-specific discriminating control; "
                "record a live evidence ID on the exact coverage cell. An unexecuted, "
                "blocked, or inconclusive probe stays open. Applicable classes: "
                + ", ".join(classes)
            ),
        },
        "thought": "Dispatch specialists on untested applicable vulnerability classes.",
    }


def _cms_followup_wave(target: str, product: str) -> Dict[str, Any]:
    return {
        "tool_name": "fireteam_dispatch",
        "tool_args": {
            "specialists": ["cms_followup"],
            "mode": "cms_followup",
            "targets": [target],
            "mission": (
                f"Investigate fingerprinted {product} core, plugin/theme, and "
                "configuration leads on the scoped host. Submit evidence-backed "
                "candidates for independent verification."
            ),
        },
        "thought": "Run CMS follow-up analysis while path enrichment continues.",
    }


def _confirmed_candidate_publication_step(
    state: Dict[str, Any], trace: List[Dict[str, Any]], target: str,
) -> Optional[Dict[str, Any]]:
    """File a verified claim with its exact fields before more hunt work."""
    from app.services.agent.independent_verify import verify_receipt_key

    brain = state.get("engagement_brain") or {}
    receipts = brain.get("verification_receipts") or {}
    scope_host = urlparse(target).hostname
    if not scope_host:
        return None
    for candidate in brain.get("candidates") or []:
        if not isinstance(candidate, dict):
            continue
        if candidate.get("status") != "confirmed" or candidate.get("finding_id"):
            continue
        title = str(candidate.get("title") or "")
        claim_target = str(candidate.get("target") or "")
        parsed_claim = urlparse(claim_target)
        if (
            not title or parsed_claim.scheme not in {"http", "https"}
            or parsed_claim.hostname != scope_host
        ):
            continue
        receipt = receipts.get(verify_receipt_key(title, claim_target)) or {}
        if (
            receipt.get("verdict") != "confirmed"
            or receipt.get("candidate_id") != candidate.get("id")
            or receipt.get("title") != title
            or receipt.get("target") != claim_target
            or receipt.get("revision") != candidate.get("revision")
            or receipt.get("run_id") != candidate.get("verifier_run_id")
            or not receipt.get("nonce_observed")
            or receipt.get("nonce") != candidate.get("nonce")
            or not receipt.get("evidence_ids")
            or not set(receipt["evidence_ids"]).issubset(set(candidate.get("evidence_ids") or []))
            or not candidate.get("verified_at")
        ):
            continue
        description = str(candidate.get("description") or "")
        severity = str(candidate.get("severity") or "medium")
        if severity.strip().lower() not in {"medium", "high", "critical"}:
            continue
        # A model may have tried to rewrite the claim. Retry once with the
        # exact verified fields, but do not loop on a failed exact submission.
        prior_attempts = [
            step for step in trace
            if step.get("tool_name") == "create_finding"
            and (step.get("tool_args") or {}).get("title") == title
            and (step.get("tool_args") or {}).get("target") == claim_target
        ]
        if len(prior_attempts) >= 2:
            continue
        if any(
            all((step.get("tool_args") or {}).get(key) == value for key, value in (
                ("title", title), ("target", claim_target),
                ("description", description), ("severity", severity),
            ))
            for step in prior_attempts
        ):
            continue
        evidence = "\n\n".join(filter(None, (
            str(candidate.get("evidence") or ""),
            str(candidate.get("verifier_evidence") or ""),
        )))[:5000]
        args = {
            "title": title,
            "description": description,
            "severity": severity,
            "target": claim_target,
            "evidence": evidence,
        }
        if candidate.get("claimed_request"):
            args["steps_to_reproduce"] = str(candidate["claimed_request"])[:10000]
        return {
            "tool_name": "create_finding",
            "tool_args": args,
            "thought": "Publish the independently confirmed candidate with its verified claim fields.",
        }
    return None


def tester_loop_progress(state: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Checklist a curious tester must finish before calling the host clean.

    ready_to_complete here is the *surface* loop (crawl / dirs / params / fireteam).
    Methodology cards (prove/kill) are gated separately.
    """
    state = state or {}
    ran = normalized_tools_run(state.get("execution_trace"))
    empty = surface_looks_empty(state)
    crawled = bool(ran & _CRAWL_TOOLS)
    waits = sum(
        1 for s in _steps(state.get("execution_trace"))
        if s.get("tool_name") == "wait_recon_workers"
    )
    dir_brute = bool(ran & _DIR_BRUTE_TOOLS) or (
        "dir_brute_started" in ran and waits >= 2
    )
    params = bool(ran & _PARAM_TOOLS)
    fireteam = _full_fireteam_completed(_steps(state.get("execution_trace")))
    js_surface = all(t in ran for t in _JS_SURFACE_TOOLS)
    brain = bool(ran & _BRAIN_TOOLS) or bool(
        ((state.get("engagement_brain") or {}).get("hypotheses") or [])
    )
    web = is_web_target(state)
    registry_only = False
    try:
        from app.services.agent.registry_surface import is_registry_primary

        registry_only = is_registry_primary(state)
    except Exception:
        pass
    pipeline = web and not registry_only
    handoff_failures = (_failed_first_pass_handoffs(state, primary_web_target(state))
                        if pipeline else [])

    missing: List[Dict[str, str]] = []
    try:
        from app.services.agent.cve_applicability import (
            create_finding_succeeded,
            cve_check_ran,
            is_cve_applicability_question,
            last_cve_verdict,
            validate_finding_submitted,
        )

        if is_cve_applicability_question(state):
            if not cve_check_ran(state):
                missing.append({
                    "id": "cve_applicability",
                    "title": "Named CVE not checked against the live homepage",
                    "next": "check_cve_applicability — lookup the CVE, GET the URL, compare product+version",
                })
            elif last_cve_verdict(state) == "applicable":
                if not validate_finding_submitted(state):
                    missing.append({
                        "id": "cve_validate",
                        "title": "Applicable CVE not judged",
                        "next": "validate_finding with the version evidence, then create_finding",
                    })
                elif not create_finding_succeeded(state):
                    missing.append({
                        "id": "cve_finding",
                        "title": "Applicable CVE not filed",
                        "next": "create_finding (same title/target as validate_finding)",
                    })
            next_action = missing[0]["next"] if missing else "complete — applicability is answered; do not pentest"
            return {
                "is_web": web,
                "surface_empty": empty,
                "crawled": crawled,
                "dir_brute": dir_brute,
                "js_surface": js_surface,
                "params": params or fireteam,
                "fireteam": fireteam,
                "brain": brain,
                "missing": missing,
                "ready_to_complete": not missing,
                "next_action": next_action,
                "cve_applicability_only": True,
                "summary": (
                    f"CVE applicability check: ran={cve_check_ran(state)} "
                    f"missing={len(missing)}"
                ),
            }
    except Exception:
        pass
    if state.get("assessment_resume") and pipeline:
        pending = (_pending_first_pass_count(state)
                   if observed_input_signature(state) else 0)
        missing = ([{
            "id": "observed_input_first_pass",
            "title": f"{pending} observed SQLi/XSS checks need a first pass",
            "next": "probe_observed_input_batch on the current assessment target",
        }] if pending else [])
        unsubmitted = _unsubmitted_first_pass_proofs(state, primary_web_target(state))
        if unsubmitted:
            missing.append({
                "id": "candidate_handoff",
                "title": f"{len(unsubmitted)} positive input proofs lack finding candidates",
                "next": "submit_finding_candidate with each saved proof receipt",
            })
        if handoff_failures:
            missing.append({
                "id": "first_pass_handoff",
                "title": f"{len(handoff_failures)} observed inputs failed before probing",
                "next": "Inspect first_pass_handoff_error and repair the exact input mapping or lease",
            })
        return {
            "is_web": web,
            "surface_empty": empty,
            "crawled": True,
            "dir_brute": True,
            "js_surface": True,
            "params": True,
            "fireteam": True,
            "brain": True,
            "missing": missing,
            "ready_to_complete": not missing,
            "next_action": (missing[0]["next"] if missing else
                            "Test the latest scoped follow-up objective with saved evidence"),
            "summary": (f"Resumed mapped assessment; {pending} observed first-pass "
                        "checks remain on the current target"),
        }
    if pipeline and not crawled:
        missing.append({
            "id": "crawl",
            "title": "Walk the app (execute_interceptor or execute_deep_crawl)",
            "next": "execute_interceptor (or execute_deep_crawl) on the primary URL",
        })
    if pipeline and (empty or not dir_brute):
        why = (
            "Root looks empty/404 — directory brute-force is mandatory"
            if empty and not dir_brute
            else "Bounded directory/path enum not run"
        )
        if not dir_brute:
            missing.append({
                "id": "dir_brute",
                "title": why,
                "next": "spawn_recon_workers(pack='enrich') or execute_feroxbuster with /opt/wordlists/app-dirs-common.txt",
            })
    if pipeline and crawled and not js_surface:
        if "fingerprint_api" not in ran:
            missing.append({
                "id": "fingerprint",
                "title": "API fingerprint from captured XHR not run",
                "next": "fingerprint_api — sibling API hosts + coverage matrix (not Caido)",
            })
        if "fetch_lazy_chunks" not in ran:
            missing.append({
                "id": "lazy_chunks",
                "title": "Lazy/code-split JS chunks not reconstructed",
                "next": "fetch_lazy_chunks(dry_run then download) on first-party runtime",
            })
        if "extract_js_endpoints" not in ran:
            missing.append({
                "id": "js_endpoints",
                "title": "JS endpoint extraction not run",
                "next": "extract_js_endpoints then ingest_urls_into_map",
            })
    if pipeline and not fireteam:
        missing.append({
            "id": "fireteam",
            "title": "Fireteam never dispatched — no specialist hunted unknown bugs",
            "next": "fireteam_dispatch(specialists='auto') — content_api mines params on live paths",
        })
    if pipeline and not params and not fireteam:
        missing.append({
            "id": "params",
            "title": "Parameter discovery not run (forms, query, hidden, JS, Arjun)",
            "next": "discover_parameters on live URLs, then execute_arjun, or fireteam_dispatch so content_api mines params",
        })
    if pipeline and not brain:
        missing.append({
            "id": "brain",
            "title": "Threat model / methodology cards not seeded",
            "next": "sync_engagement_brain (or build_threat_model) — aim before fireteam",
        })
    if pipeline:
        unsubmitted = _unsubmitted_first_pass_proofs(state, primary_web_target(state))
        if unsubmitted:
            missing.append({
                "id": "candidate_handoff",
                "title": f"{len(unsubmitted)} positive input proofs lack finding candidates",
                "next": "submit_finding_candidate with each saved proof receipt",
            })
        if handoff_failures:
            missing.append({
                "id": "first_pass_handoff",
                "title": f"{len(handoff_failures)} observed inputs failed before probing",
                "next": "Inspect first_pass_handoff_error and repair the exact input mapping or lease",
            })
    try:
        from app.services.agent.registry_surface import registry_missing_probes

        missing.extend(registry_missing_probes(state))
    except Exception:
        pass
    try:
        from app.services.agent.wordpress_surface import wordpress_missing_probes

        missing.extend(wordpress_missing_probes(state))
    except Exception:
        pass

    next_action = missing[0]["next"] if missing else ""
    return {
        "is_web": web,
        "surface_empty": empty,
        "crawled": crawled,
        "dir_brute": dir_brute,
        "js_surface": js_surface,
        "params": params or fireteam,
        "fireteam": fireteam,
        "brain": brain,
        "missing": missing,
        "ready_to_complete": (not web) or (not missing),
        "next_action": next_action,
        "summary": (
            f"Tester loop: crawl={crawled} dir_brute={dir_brute} "
            f"js_surface={js_surface} params={params or fireteam} "
            f"fireteam={fireteam} empty_surface={empty} missing={len(missing)}"
        ),
    }


def format_tester_loop_for_prompt(progress: Dict[str, Any], state: Optional[Dict[str, Any]] = None) -> str:
    if not progress or not progress.get("is_web"):
        return ""
    if (state or {}).get("assessment_resume") and not progress.get("cve_applicability_only"):
        message = (
            "### Resumed assessment\n"
            "The first-turn surface loop already ran. Use the saved map and "
            "evidence to test the latest scoped objective. Do not restart broad "
            "discovery or fireteam dispatch solely because this turn's trace is empty."
        )
        if progress.get("missing"):
            message += ("\n" + progress["summary"] + ". Next: "
                        + progress["next_action"] + ".")
        return message
    if progress.get("cve_applicability_only"):
        lines = [
            "### CVE applicability (Glasswing observe — do this before Interceptor)",
            progress.get("summary") or "",
        ]
        missing = progress.get("missing") or []
        if missing:
            lines.append("Do NOT complete and do NOT crawl yet:")
            for row in missing:
                lines.append(f"  - {row.get('title')}: {row.get('next')}")
        else:
            lines.append(
                "Applicability is answered. If a finding was required it is filed. "
                "COMPLETE now. Do not WPScan, Interceptor, fireteam, or admin-ajax. "
                "This question is not a full pentest."
            )
        return "\n".join(lines)
    lines = [
        "### Curious tester loop (mandatory — unknown bugs, not just known CVEs)",
        progress.get("summary") or "",
    ]
    if progress.get("surface_empty"):
        lines.append(
            "Root looks like 404/empty. A 404 is not 'no attack surface'. "
            "Run bounded ferox/ffuf, then mine parameters on anything that answers."
        )
    missing = progress.get("missing") or []
    if missing:
        lines.append("Do NOT complete. Next tester steps:")
        for row in missing:
            lines.append(f"  - {row.get('title')}: {row.get('next')}")
    else:
        lines.append(
            "Surface loop done. Hunt unknown vulns via fireteam summaries "
            "(authz, params, SSRF/URL-fetch, logic) — Nuclei is coverage leftover only."
        )
    cmap = (state or {}).get("capability_map") or {}
    assessment = cmap.get("assessment") if isinstance(cmap, dict) else None
    if assessment:
        from app.services.agent.page_assessment import format_page_assessment_for_prompt
        brief = format_page_assessment_for_prompt(assessment)
        if brief:
            lines.append(brief)
    return "\n".join(lines)


def complete_blocked_reason(
    state: Optional[Dict[str, Any]] = None,
    *,
    completion_reason: str = "",
) -> Optional[str]:
    """Return a block message, or None if complete is allowed."""
    if (state or {}).get("mode") == "pilot":
        # The full tester loop requires crawlers, directory brute force and
        # fireteam tools that the bounded pilot deliberately cannot run.
        return None
    reason = (completion_reason or "").lower()
    if any(
        token in reason
        for token in ("force complete", "defer methodologies", "defer remaining", "non-browser")
    ):
        return None
    progress = tester_loop_progress(state)
    if progress.get("is_web") and not progress.get("ready_to_complete"):
        missing = progress.get("missing") or []
        blocker_txt = "; ".join(
            f"{b.get('id')}: {b.get('title')}" for b in missing[:5]
        ) or "tester loop incomplete"
        return (
            "Cannot complete yet — curious-tester loop incomplete.\n"
            f"{progress.get('summary')}\n"
            f"Blocking: {blocker_txt}\n\n"
            f"Next: {progress.get('next_action')}\n"
            "Fingerprint-only recon is not an assessment. Crawl, brute dirs "
            "(especially on 404), fingerprint APIs, reconstruct lazy JS chunks, "
            "extract endpoints, mine parameters, dispatch the fireteam, then "
            "prove or kill methodology cards. If WordPress was fingerprinted, "
            "REST user enum and admin-ajax timing must have run. "
            "If *.azurecr.io is in inventory or the target, "
            "probe_registry_anonymous must have run. "
            "Named CVE + URL: check_cve_applicability (homepage fingerprint) "
            "runs first — version-in-range is a finding. "
            "Nuclei spray is leftover coverage, not a substitute for that observe pass.\n"
            "Or set completion_reason to include 'defer methodologies' / "
            "'force complete' if intentionally skipping."
        )
    return None


def forced_next_step(state: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """
    Deterministic next tool for a web assessment.

    Joshua does not get to choose fingerprint-and-stop. Start a hunt wave as
    soon as the browser exposes real inputs; background enrichment continues
    and a changed input inventory can trigger another wave.
    """
    state = state or {}
    if state.get("mode") == "pilot":
        target = primary_web_target(state)
        ran = normalized_tools_run(_steps(state.get("execution_trace")))
        if target and "execute_browser" not in ran:
            import json

            return {
                "tool_name": "execute_browser",
                "tool_args": {"args": json.dumps({"actions": [
                    {"action": "navigate", "url": target},
                    {"action": "get_source"},
                ]})},
                "thought": "Bounded pilot: inspect the exact target origin before testing inputs.",
            }
        port_steps = [step for step in _steps(state.get("execution_trace"))
                      if step.get("tool_name") == "probe_pilot_ports"]
        probed_protocols = {
            str((step.get("tool_args") or {}).get("protocol") or "").lower()
            for step in port_steps
        }
        if target and "tcp" not in probed_protocols:
            from app.models.scan_schedule import CRITICAL_PORTS

            priority = [
                *CRITICAL_PORTS["web"],
                *CRITICAL_PORTS["remote_access"],
                *CRITICAL_PORTS["databases"],
            ]
            ports = list(dict.fromkeys(priority))[:20]
            return {
                "tool_name": "probe_pilot_ports",
                "tool_args": {"protocol": "tcp", "ports": ports},
                "thought": "Check the platform's priority TCP service ports under the shared pilot budget.",
            }
        if target and "udp" not in probed_protocols:
            return {
                "tool_name": "probe_pilot_ports",
                "tool_args": {"protocol": "udp", "ports": [53, 69, 123, 161, 162, 500, 1434, 1900, 4500, 5353]},
                "thought": "Check priority UDP ports; no response will remain inconclusive.",
            }
        # The remaining choices must come from the pilot allowlist in the
        # dedicated planner prompt; never force the normal scanner pipeline.
        return None
    try:
        from app.services.agent.registry_surface import (
            is_registry_primary,
            registry_forced_step,
        )

        reg_step = registry_forced_step(state)
        if reg_step:
            return reg_step
        if is_registry_primary(state):
            # Registry hosts are not websites — do not Interceptor-crawl /v2/.
            return None
    except Exception:
        pass
    if not is_web_target(state):
        return None
    try:
        from app.services.agent.cve_applicability import (
            cve_applicability_forced_step,
            cve_applicability_writeup_forced_step,
            is_cve_applicability_question,
        )

        cve_step = cve_applicability_forced_step(state)
        if cve_step:
            return cve_step
        writeup = cve_applicability_writeup_forced_step(state)
        if writeup:
            return writeup
        if is_cve_applicability_question(state):
            return None
    except Exception:
        pass
    target = primary_web_target(state)
    if not target:
        return None
    trace = _steps(state.get("execution_trace"))
    publication = _confirmed_candidate_publication_step(state, trace, target)
    if publication:
        return publication
    candidate_handoff = _pending_first_pass_candidate_step(state, trace, target)
    if candidate_handoff:
        return candidate_handoff
    verification = _pending_candidate_verify_step(state, trace)
    if verification:
        return verification
    if state.get("assessment_resume"):
        signature = observed_input_signature(state)
        batch = _observed_input_batch_step(state, trace, signature)
        if batch:
            return batch
        return None
    ran = normalized_tools_run(trace)
    crawled = bool(ran & _CRAWL_TOOLS)
    dir_done = bool(ran & _DIR_BRUTE_TOOLS)
    dir_started = "dir_brute_started" in ran or dir_done
    full_fireteam = _full_fireteam_completed(trace)
    input_signature = observed_input_signature(state)
    input_dispatched = _dispatched_input_signature(trace, input_signature)
    cms_product = cms_followup_product(state)
    cms_dispatched = _cms_followup_dispatched(trace)
    waits = sum(1 for s in trace if s.get("tool_name") == "wait_recon_workers")

    if not crawled:
        interceptor_failed = any(
            step.get("tool_name") == "execute_interceptor"
            and step.get("success") is False
            for step in trace
        )
        if state.get("interceptor_job_id") and not interceptor_failed:
            return {
                "tool_name": "execute_interceptor",
                "tool_args": {
                    "args": (
                        f'{{"url":"{target}","depth":3,"max_pages":20,"interact":true}}'
                    ),
                },
                "thought": (
                    "Assessment pipeline: walk the app in a real browser "
                    "(Interceptor already queued)."
                ),
            }
        # The built-in scoped browser is a distinct fallback when deep crawl
        # cannot complete. Do not retry either operation indefinitely.
        if any(step.get("tool_name") == "execute_deep_crawl"
               and step.get("success") is False for step in trace):
            if state.get("mode") == "agent" and not any(
                step.get("tool_name") == "scoped_browser_assessment"
                and isinstance(step.get("tool_args"), dict)
                and step["tool_args"].get("operation") == "crawl"
                for step in trace
            ):
                return {
                    "tool_name": "scoped_browser_assessment",
                    "tool_args": {"operation": "crawl", "url": target, "max_pages": 10},
                    "thought": "Prowl: recover the application map with the built-in scoped browser.",
                }
            return None
        return {
            "tool_name": "execute_deep_crawl",
            "tool_args": {
                "args": f'{{"url":"{target}","depth":3,"interact":true}}',
            },
            "thought": (
                "Assessment pipeline: crawl the primary URL before any "
                "'no vulns' conclusion."
            ),
        }

    if state.get("mode") == "agent" and not input_signature and not any(
        step.get("tool_name") == "scoped_browser_assessment"
        and isinstance(step.get("tool_args"), dict)
        and step["tool_args"].get("operation") == "inspect_js"
        for step in trace
    ):
        return {
            "tool_name": "scoped_browser_assessment",
            "tool_args": {"operation": "inspect_js", "url": target,
                          "max_pages": 4, "max_actions": 3},
            "thought": "Prowl: capture browser actions, inputs, and first-party API traffic for specialist work.",
        }

    # Launch enrichment without waiting for it before testing real browser inputs.
    if not dir_started:
        return {
            "tool_name": "spawn_recon_workers",
            "tool_args": {"pack": "enrich", "target": target},
            "thought": "Start bounded directory and URL enrichment in the background.",
        }

    if input_signature and not input_dispatched:
        if "sync_engagement_brain" not in ran and "build_threat_model" not in ran:
            return {
                "tool_name": "sync_engagement_brain",
                "tool_args": {},
                "thought": "Seed observed input hypotheses while enrichment continues.",
            }
        batch = _observed_input_batch_step(state, trace, input_signature)
        if batch:
            return batch
        return _observed_input_wave(
            target, input_signature, _untested_observed_input_count(state),
            _observed_input_specialists(state),
            cms_product if not cms_dispatched else "",
        )

    if cms_product and not cms_dispatched:
        return _cms_followup_wave(target, cms_product)

    if input_signature:
        batch = _observed_input_batch_step(state, trace, input_signature)
        if batch:
            return batch

    if input_signature and _input_wave_made_progress(state, trace, input_signature):
        return _observed_input_wave(
            target, input_signature, _untested_observed_input_count(state),
            _observed_input_specialists(state),
        )

    try:
        from app.services.agent.wordpress_surface import wordpress_forced_step

        wp_step = wordpress_forced_step(state)
        if wp_step:
            return wp_step
    except Exception:
        pass

    if not dir_done and waits < 2:
        return {
            "tool_name": "wait_recon_workers",
            "tool_args": {"timeout_sec": 45},
            "thought": "Join background enrichment for additional paths and inputs.",
        }

    if "fingerprint_api" not in ran:
        return {
            "tool_name": "fingerprint_api",
            "tool_args": {},
            "thought": (
                "Assessment pipeline: fingerprint API hosts/tech from captured "
                "XHR (not Caido). Blocked/no-data is OK — continue."
            ),
        }
    if "fetch_lazy_chunks" not in ran:
        return {
            "tool_name": "fetch_lazy_chunks",
            "tool_args": {"dry_run": False},
            "thought": (
                "Assessment pipeline: reconstruct webpack/Vite/Next lazy chunks "
                "the crawl never loaded."
            ),
        }
    if "extract_js_endpoints" not in ran:
        return {
            "tool_name": "extract_js_endpoints",
            "tool_args": {},
            "thought": (
                "Assessment pipeline: mine /api, IDOR, and SSRF/redirect leads "
                "from first-party JS + fetched chunks."
            ),
        }

    if "sync_engagement_brain" not in ran and "build_threat_model" not in ran:
        return {
            "tool_name": "sync_engagement_brain",
            "tool_args": {},
            "thought": (
                "Assessment pipeline: aim — threat-model the app (actors, assets, "
                "ranked outcomes, focus areas) before dispatching hunters. "
                "This is the map; vulns are the metal detector."
            ),
        }

    if not full_fireteam:
        return {
            "tool_name": "fireteam_dispatch",
            "tool_args": {
                "specialists": "auto",
                "targets": [target],
                "mission": (
                    "Hunt unknown bugs on mapped and brute-forced surfaces: "
                    "unauth APIs, hidden params, URL-fetch/SSRF, authz, default creds. "
                    "Prove with a live request. Nuclei is leftover coverage only."
                ),
            },
            "thought": (
                "Assessment pipeline: dispatch fireteam (content_api, api_authz, "
                "xss, sqli, ssrf, …). Fingerprints are not an assessment."
            ),
        }

    followup = _coverage_followup_wave(state, trace, target)
    if followup:
        return followup

    try:
        from app.services.agent.wordpress_surface import wordpress_forced_step

        wp_step = wordpress_forced_step(state)
        if wp_step:
            return wp_step
    except Exception:
        pass
    try:
        from app.services.agent.registry_surface import registry_forced_step

        reg_step = registry_forced_step(state)
        if reg_step:
            return reg_step
    except Exception:
        pass
    return None
