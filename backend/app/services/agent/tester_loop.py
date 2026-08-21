"""
Curious-tester control loop.

Joshua (the scheduler) must observe, enumerate, and hunt unknown bugs — not
fingerprint and stop. A 404 / empty root is a reason to brute directories, not
to declare the host clean. Parameter mining and fireteam dispatch are required
before complete on web targets.

Known-CVE spray (Nuclei) is coverage leftover, never a substitute for this loop.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set
from urllib.parse import urlparse

_CRAWL_TOOLS = {
    "execute_interceptor",
    "execute_deep_crawl",
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
_FIRETEAM_TOOLS = {"fireteam_dispatch"}
_BRAIN_TOOLS = {"sync_engagement_brain", "fireteam_dispatch"}
_JS_SURFACE_TOOLS = ("fingerprint_api", "fetch_lazy_chunks", "extract_js_endpoints")

_404_TEXT_RE = re.compile(
    r"\b(404|not found|doesn'?t exist|does not exist|page not found|cannot get|no route)\b",
    re.I,
)
_WEB_HINT_RE = re.compile(r"https?://|\bwww\.|\.(com|net|io|org|app)\b", re.I)


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
    fireteam = bool(ran & _FIRETEAM_TOOLS)
    js_surface = all(t in ran for t in _JS_SURFACE_TOOLS)
    brain = bool(ran & _BRAIN_TOOLS) or bool(
        ((state.get("engagement_brain") or {}).get("hypotheses") or [])
    )
    web = is_web_target(state)

    missing: List[Dict[str, str]] = []
    if web and not crawled:
        missing.append({
            "id": "crawl",
            "title": "Walk the app (execute_interceptor or execute_deep_crawl)",
            "next": "execute_interceptor (or execute_deep_crawl) on the primary URL",
        })
    if web and (empty or not dir_brute):
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
    if web and crawled and not js_surface:
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
    if web and not fireteam:
        missing.append({
            "id": "fireteam",
            "title": "Fireteam never dispatched — no specialist hunted unknown bugs",
            "next": "fireteam_dispatch(specialists='auto') — content_api mines params on live paths",
        })
    if web and not params and not fireteam:
        missing.append({
            "id": "params",
            "title": "Parameter discovery not run (forms, query, hidden, JS, Arjun)",
            "next": "discover_parameters on live URLs, then execute_arjun, or fireteam_dispatch so content_api mines params",
        })
    if web and not brain:
        missing.append({
            "id": "brain",
            "title": "Engagement brain / methodology cards not seeded",
            "next": "sync_engagement_brain after the crawl/dir-brute map updates",
        })

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


def format_tester_loop_for_prompt(progress: Dict[str, Any]) -> str:
    if not progress or not progress.get("is_web"):
        return ""
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
    return "\n".join(lines)


def complete_blocked_reason(
    state: Optional[Dict[str, Any]] = None,
    *,
    completion_reason: str = "",
) -> Optional[str]:
    """Return a block message, or None if complete is allowed."""
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
            "prove or kill methodology cards. Nuclei/known-CVE spray is last, not first.\n"
            "Or set completion_reason to include 'defer methodologies' / "
            "'force complete' if intentionally skipping."
        )
    return None


def forced_next_step(state: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """
    Deterministic next tool for a web assessment.

    Joshua does not get to choose fingerprint-and-stop. Returns tool_name +
    tool_args, or None once crawl + dir brute + JS/API recon + fireteam have run.
    """
    state = state or {}
    if not is_web_target(state):
        return None
    target = primary_web_target(state)
    if not target:
        return None
    trace = _steps(state.get("execution_trace"))
    ran = normalized_tools_run(trace)
    crawled = bool(ran & _CRAWL_TOOLS)
    dir_done = bool(ran & _DIR_BRUTE_TOOLS)
    dir_started = "dir_brute_started" in ran or dir_done
    fireteam = bool(ran & _FIRETEAM_TOOLS)
    waits = sum(1 for s in trace if s.get("tool_name") == "wait_recon_workers")

    if not crawled:
        if state.get("interceptor_job_id"):
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

    if not dir_done:
        if dir_started and waits < 2:
            return {
                "tool_name": "wait_recon_workers",
                "tool_args": {"timeout_sec": 45},
                "thought": (
                    "Assessment pipeline: join ferox/katana enrich, then hunt "
                    "whatever paths answered."
                ),
            }
        if not dir_started:
            return {
                "tool_name": "spawn_recon_workers",
                "tool_args": {"pack": "enrich", "target": target},
                "thought": (
                    "Assessment pipeline: bounded directory brute-force + URL "
                    "enrich (404/thin pages still have unlinked paths)."
                ),
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

    if not fireteam:
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
                "injection, …). Fingerprints are not an assessment."
            ),
        }
    return None

