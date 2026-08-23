"""ACR / Docker Registry surface: inventory → mandatory anonymous-pull probe.

Prompt-only hunt cards never ran. Same shape as wordpress_surface: fingerprint
hosts from state/inventory, force a read-only token+catalog check, block
complete until it ran. Do not pull images, push, or reuse recovered tokens.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

_ACR_HOST_RE = re.compile(
    r"\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.azurecr\.io)\b",
    re.I,
)
_GENERIC_REGISTRY_RE = re.compile(r"/v2/_catalog|docker.?registry", re.I)

_TOKEN_PATH_MARKERS = (
    "/oauth2/token",
    "registry:catalog",
    "probe_registry_anonymous",
    "/v2/_catalog",
)


def _g(cmap: Any, key: str, default: Any = None) -> Any:
    if cmap is None:
        return default
    if isinstance(cmap, dict):
        return cmap.get(key, default)
    return getattr(cmap, key, default)


def _blob(state: Optional[Dict[str, Any]]) -> str:
    state = state or {}
    cmap = state.get("capability_map") or {}
    info = state.get("target_info") or {}
    parts = [
        str(state.get("objective") or ""),
        str(state.get("original_objective") or ""),
        str(state.get("kickoff_brief") or ""),
        str(info.get("primary_target") or ""),
        " ".join(str(t) for t in (info.get("technologies") or [])[:20]),
        " ".join(str(h) for h in (info.get("hosts") or info.get("subdomains") or [])[:40]),
        str(_g(cmap, "target") or ""),
        " ".join(str(p) for p in (_g(cmap, "pages_visited") or [])[:40]),
        " ".join(str(n) for n in (_g(cmap, "notes") or [])[:12]),
    ]
    for step in state.get("execution_trace") or []:
        if not isinstance(step, dict):
            continue
        parts.append(str(step.get("tool_name") or ""))
        parts.append(str(step.get("tool_args") or "")[:2000])
        parts.append(str(step.get("tool_output") or "")[:4000])
    return " ".join(parts)


def _normalize_host(raw: str) -> str:
    h = (raw or "").strip().lower()
    if "://" in h:
        parsed = urlparse(h)
        h = parsed.netloc or parsed.path
    h = h.split("/")[0].split("?")[0].split("#")[0]
    h = h.split("@")[-1]
    h = h.split(":")[0]
    return h.rstrip(".")


def host_is_azurecr(raw: str) -> bool:
    return _normalize_host(raw).endswith(".azurecr.io")


def registry_hosts_from_state(state: Optional[Dict[str, Any]] = None) -> List[str]:
    """ACR hostnames (and catalog-hinted hosts) already in session evidence."""
    blob = _blob(state)
    seen: List[str] = []
    for match in _ACR_HOST_RE.finditer(blob):
        host = _normalize_host(match.group(1))
        if host and host not in seen:
            seen.append(host)
    return seen


def registry_detected(state: Optional[Dict[str, Any]] = None) -> bool:
    return bool(registry_hosts_from_state(state)) or bool(
        _GENERIC_REGISTRY_RE.search(_blob(state))
    )


def is_registry_primary(state: Optional[Dict[str, Any]] = None) -> bool:
    hosts = registry_hosts_from_state(state)
    if not hosts:
        return False
    state = state or {}
    primary = " ".join(
        [
            str((state.get("target_info") or {}).get("primary_target") or ""),
            str((state.get("capability_map") or {}).get("target") or ""),
            str(state.get("original_objective") or ""),
        ]
    ).lower()
    return any(h in primary for h in hosts)


def _trace_blob(step: Dict[str, Any]) -> str:
    return " ".join(
        [
            str(step.get("tool_name") or ""),
            str(step.get("tool_args") or ""),
            str(step.get("tool_output") or "")[:3000],
        ]
    ).lower()


def registry_probe_status(state: Optional[Dict[str, Any]] = None) -> Dict[str, bool]:
    """host → whether an anonymous token/catalog probe already ran for it."""
    hosts = registry_hosts_from_state(state)
    probed = {h: False for h in hosts}
    for step in (state or {}).get("execution_trace") or []:
        if not isinstance(step, dict):
            continue
        blob = _trace_blob(step)
        name = str(step.get("tool_name") or "")
        # Kickoff may mention oauth2 URLs in the brief without being the probe.
        if name == "assessment_kickoff":
            continue
        if name != "probe_registry_anonymous" and not any(
            m in blob for m in _TOKEN_PATH_MARKERS
        ):
            continue
        for host in hosts:
            if host in blob:
                probed[host] = True
    return probed


def unprobed_registry_hosts(state: Optional[Dict[str, Any]] = None) -> List[str]:
    status = registry_probe_status(state)
    return [h for h, done in status.items() if not done]


def inventory_query_ran(state: Optional[Dict[str, Any]] = None) -> bool:
    for step in (state or {}).get("execution_trace") or []:
        if not isinstance(step, dict):
            continue
        if str(step.get("tool_name") or "") != "query_assets":
            continue
        blob = _trace_blob(step)
        if "azurecr" in blob:
            return True
    return False


def registry_missing_probes(
    state: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, str]]:
    missing: List[Dict[str, str]] = []
    unprobed = unprobed_registry_hosts(state)
    if unprobed:
        host = unprobed[0]
        missing.append({
            "id": "acr_anonymous_pull",
            "title": f"ACR anonymous-pull probe not run ({host})",
            "next": (
                f"probe_registry_anonymous(host='{host}') — unauth oauth2 token "
                "+ catalog names. Do not pull images."
            ),
        })
    elif (state or {}).get("organization_id") and not inventory_query_ran(state):
        missing.append({
            "id": "acr_inventory",
            "title": "Org inventory not searched for *.azurecr.io",
            "next": "query_assets(search='azurecr.io', limit=30) then probe each live registry",
        })
    return missing


def registry_forced_step(
    state: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Deterministic next registry probe, or inventory lookup."""
    unprobed = unprobed_registry_hosts(state)
    if unprobed:
        host = unprobed[0]
        return {
            "tool_name": "probe_registry_anonymous",
            "tool_args": {"host": host},
            "thought": (
                f"Registry surface — {host} is in-play. Prove or kill "
                "anonymousPullEnabled with oauth2 token + catalog (no image pull)."
            ),
        }
    if (state or {}).get("organization_id") and not inventory_query_ran(state):
        return {
            "tool_name": "query_assets",
            "tool_args": {"search": "azurecr.io", "limit": 30},
            "thought": (
                "Registry surface — search org inventory for *.azurecr.io "
                "before calling the cloud attack surface clean."
            ),
        }
    return None


def stamp_registry_on_map(
    cmap: Optional[Dict[str, Any]],
    state: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    if not isinstance(cmap, dict):
        return cmap
    hosts = registry_hosts_from_state({**(state or {}), "capability_map": cmap})
    if not hosts:
        return cmap
    notes = list(cmap.get("notes") or [])
    marker = "Azure Container Registry in-play"
    if not any(marker in str(n) for n in notes):
        notes.append(
            f"{marker} ({', '.join(hosts[:8])}) — anonymous oauth2 token + "
            "/v2/_catalog must run. Do not pull images."
        )
    patched = dict(cmap)
    patched["notes"] = notes
    if not patched.get("target") and hosts:
        patched["target"] = f"https://{hosts[0]}"
    pages = list(patched.get("pages_visited") or [])
    for host in hosts[:8]:
        url = f"https://{host}/v2/"
        if url not in pages:
            pages.append(url)
    patched["pages_visited"] = pages
    try:
        from app.services.agent.capability_map import build_capability_map_from_dict

        return build_capability_map_from_dict(patched).to_dict()
    except Exception:
        return patched


def registry_hunt_note(state: Optional[Dict[str, Any]] = None) -> str:
    hosts = registry_hosts_from_state(state)
    missing = registry_missing_probes(state)
    if not hosts and not missing:
        return ""
    lines = [
        "\n\n## Azure Container Registry / Docker registry — probe NOW",
        "Anonymous pull is a live check, not a Nuclei banner. "
        "Do not crawl these hosts as websites. Do not pull image layers.",
    ]
    if hosts:
        status = registry_probe_status(state)
        pending = [h for h, done in status.items() if not done]
        done = [h for h, d in status.items() if d]
        if pending:
            lines.append(
                "Unprobed: "
                + ", ".join(pending[:8])
                + f" — probe_registry_anonymous(host='{pending[0]}'). "
                "If access_token + repositories: create_finding High (Critical if "
                "a later bounded secret scan recovers ghp_*)."
            )
        if done:
            lines.append(
                "Already probed: "
                + ", ".join(done[:8])
                + " — if the tool said anonymous=true, create_finding now."
            )
    elif missing:
        lines.append(missing[0]["next"])
    return "\n".join(lines)


def redact_token_json(body: str) -> str:
    """Keep proof of access_token without shipping the JWT."""
    text = body or ""
    try:
        data = json.loads(text)
    except Exception:
        return text[:800]
    token = data.get("access_token") or data.get("token") or data.get("refresh_token")
    if isinstance(token, str) and len(token) > 12:
        data["access_token"] = token[:8] + "...REDACTED"
        for key in ("token", "refresh_token"):
            if key in data and isinstance(data[key], str):
                data[key] = str(data[key])[:8] + "...REDACTED"
    return json.dumps(data)[:800]


def parse_catalog_names(body: str) -> List[str]:
    try:
        data = json.loads(body or "")
    except Exception:
        return []
    repos = data.get("repositories")
    if not isinstance(repos, list):
        return []
    return [str(r) for r in repos if r][:50]


def token_was_issued(body: str) -> bool:
    try:
        data = json.loads(body or "")
    except Exception:
        return False
    token = data.get("access_token") or data.get("token")
    return bool(isinstance(token, str) and len(token) > 20)


async def probe_anonymous_pull(host: str, *, timeout: float = 15.0) -> Dict[str, Any]:
    """Read-only ACR/Docker anonymous-pull check. Never pulls layers."""
    import httpx

    host = _normalize_host(host)
    if not host or "." not in host:
        return {"host": host, "error": "invalid_host", "anonymous": False}
    if not host.endswith(".azurecr.io"):
        return {
            "host": host,
            "error": "not_a_registry_host",
            "anonymous": False,
            "hint": "Pass an *.azurecr.io hostname.",
        }

    base = f"https://{host}"
    result: Dict[str, Any] = {
        "host": host,
        "anonymous": False,
        "token_issued": False,
        "catalog_status": None,
        "repository_count": 0,
        "sample_repositories": [],
        "verdict": "KILL",
        "next": "Anonymous token denied or catalog closed — not a finding.",
    }
    headers = {"User-Agent": "JudahASM-RegistryProbe/1.0"}
    try:
        async with httpx.AsyncClient(verify=True, headers=headers, follow_redirects=True) as client:
            token_url = (
                f"{base}/oauth2/token?service={host}&scope=registry:catalog:*"
            )
            tok = await client.get(token_url, timeout=timeout)
            token_body = redact_token_json(tok.text or "")
            result["token_status"] = int(tok.status_code)
            result["token_body"] = token_body
            issued = token_was_issued(tok.text or "")
            result["token_issued"] = issued
            bearer = ""
            try:
                raw = json.loads(tok.text or "")
                bearer = str(raw.get("access_token") or raw.get("token") or "")
            except Exception:
                bearer = ""

            cat_headers = dict(headers)
            if bearer:
                cat_headers["Authorization"] = f"Bearer {bearer}"
            catalog = await client.get(
                f"{base}/v2/_catalog?n=50",
                headers=cat_headers,
                timeout=timeout,
            )
            names = parse_catalog_names(catalog.text or "")
            result["catalog_status"] = int(catalog.status_code)
            result["repository_count"] = len(names)
            result["sample_repositories"] = names[:20]
            if issued and names:
                result["anonymous"] = True
                result["verdict"] = "SUBMIT"
                result["severity"] = "high"
                result["next"] = (
                    "create_finding title='Azure Container Registry Anonymous Pull Enabled' "
                    f"severity=high target=https://{host} — {len(names)} repositories. "
                    "queue_finding_followups(vuln_type='docker_registry'). "
                    "Do not pull the catalog; do not authenticate recovered PATs."
                )
            elif issued and catalog.status_code == 200:
                result["anonymous"] = True
                result["verdict"] = "SUBMIT"
                result["severity"] = "high"
                result["next"] = (
                    "Anonymous token issued (empty catalog still proves anonymousPullEnabled). "
                    "create_finding High."
                )
            else:
                result["verdict"] = "KILL"
                result["next"] = (
                    "Anonymous token not issued or catalog 401/403 — kill the card."
                )
    except Exception as exc:
        result["error"] = str(exc)[:240]
        result["verdict"] = "INCONCLUSIVE"
        result["next"] = "Probe failed — retry once; do not assume closed."
    return result
