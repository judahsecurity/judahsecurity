"""How a human tester would start — from what the page actually shows.

Fingerprints (Wappalyzer, httpx) are orientation. This module turns observed
surface (title, login, IDs in URLs, search, webhooks, SPA JS, empty root) into
a ranked *start here* list so Joshua dispatches like a person who just clicked
around — not an OWASP checklist.

Deterministic: no LLM. Safe to run in tests and before fireteam.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Sequence
from urllib.parse import urlparse

_WP_RE = re.compile(r"wordpress|wp-json|wp-admin|wp-content", re.I)
_ID_RE = re.compile(
    r"(?:[?&](?:id|user_?id|account_?id|org_?id|tenant_?id|uid|uuid)=|/api/\w+/\d+)",
    re.I,
)
_SEARCH_RE = re.compile(r"(?:[?&](?:q|query|search|s|keyword|term)=|/search\b)", re.I)
_SSRF_RE = re.compile(
    r"webhook|callback|proxy|import|preview|datasource|requesturl|/execute",
    re.I,
)
_APPSMITH_RE = re.compile(r"\bappsmith\b|x-appsmith-request-id", re.I)
_LOGIN_RE = re.compile(r"/login|/signin|/account/login|wp-login", re.I)
_ADMIN_RE = re.compile(r"/admin|/dashboard|/manage|/console", re.I)
_SETTINGS_WRITE_RE = re.compile(
    r"/api/settings|savesettings|getsettings|/api/\w+/(save|update|write)\w*|"
    r"/api/[A-Z][A-Za-z]+/[A-Z][A-Za-z]+",
)
_EMAIL_CHANGE_RE = re.compile(
    r"reset_email|change_email|update_email|/api/auth/users",
    re.I,
)
_SOCKETIO_RE = re.compile(r"socket\.io|get_stream|url_key", re.I)
_ML_PIPELINE_RE = re.compile(
    r"/api/v1/train|celery-task|logixtwin|/api/v1/optimize",
    re.I,
)
_EMPTY_RE = re.compile(
    r"\b(404|not found|doesn'?t exist|page not found|cannot get)\b",
    re.I,
)

_KIND_ORDER = (
    "empty",
    "wordpress",
    "login_wall",
    "spa",
    "api",
    "saas",
    "admin",
    "marketing",
    "mixed",
)


def _blob(cmap: Any) -> str:
    if isinstance(cmap, dict):
        pages = cmap.get("pages_visited") or []
        apis = cmap.get("api_endpoints") or []
        forms = cmap.get("forms") or []
        tech = cmap.get("technologies") or []
        target = cmap.get("target") or ""
        notes = cmap.get("notes") or []
        title = cmap.get("title") or ""
        js_files = cmap.get("js_files") or []
    else:
        pages = getattr(cmap, "pages_visited", None) or []
        apis = getattr(cmap, "api_endpoints", None) or []
        forms = getattr(cmap, "forms", None) or []
        tech = getattr(cmap, "technologies", None) or []
        target = getattr(cmap, "target", None) or ""
        notes = getattr(cmap, "notes", None) or []
        title = getattr(cmap, "title", None) or ""
        js_files = getattr(cmap, "js_files", None) or []
    api_txt = " ".join(
        f"{e.get('method', '')} {e.get('path', '')}" if isinstance(e, dict) else str(e)
        for e in apis
    )
    form_txt = " ".join(
        str(f.get("action") or "") + " " + " ".join(f.get("inputs") or [])
        if isinstance(f, dict)
        else str(f)
        for f in forms
    )
    return " ".join(
        [
            str(target),
            str(title),
            " ".join(str(p) for p in pages),
            api_txt,
            form_txt,
            " ".join(str(t) for t in tech),
            " ".join(str(n) for n in notes),
            " ".join(str(j) for j in js_files),
        ]
    )


def _wordpress_in_play(cmap: Any, kickoff: Dict[str, Any]) -> bool:
    """True only with CMS evidence — not because we requested /wp-json on an SPA."""
    techs = list(kickoff.get("technologies") or [])
    if isinstance(cmap, dict):
        techs.extend(cmap.get("technologies") or [])
    elif cmap is not None:
        techs.extend(getattr(cmap, "technologies", None) or [])
    if any("wordpress" in str(t).lower() for t in techs):
        return True
    if "CMS: WordPress" in str(kickoff.get("brief") or ""):
        return True
    for h in kickoff.get("hits") or []:
        if h.get("spa_shell"):
            continue
        path = str(h.get("path") or "")
        if not _WP_RE.search(path):
            continue
        ctype = str(h.get("content_type") or "").lower()
        try:
            st = int(h.get("status") or 0)
        except (TypeError, ValueError):
            st = 0
        if "json" in ctype or st in (301, 302, 401, 403):
            return True
        snip = str(h.get("snippet") or "")
        if "wordpress" in snip.lower() or (
            "wp-json" in snip.lower() and "application/json" in ctype
        ):
            return True
    blob = _blob(cmap)
    if re.search(r"wp-content|wp-includes|content=\"WordPress", blob, re.I):
        return True
    return False


def classify_app_kind(
    cmap: Any = None,
    *,
    kickoff: Optional[Dict[str, Any]] = None,
) -> str:
    """Best-effort product shape a human would name after 30 seconds on the site."""
    kickoff = kickoff or {}
    if kickoff.get("needs_dir_brute"):
        return "empty"
    blob = _blob(cmap) + " " + str(kickoff.get("brief") or "")
    if _EMPTY_RE.search(blob[:800]) and "EMPTY/404" in str(kickoff.get("brief") or ""):
        return "empty"
    if _wordpress_in_play(cmap, kickoff):
        return "wordpress"
    pages = []
    apis = []
    forms = []
    has_login = False
    has_spa = False
    has_api = False
    has_auth = False
    if isinstance(cmap, dict):
        pages = cmap.get("pages_visited") or []
        apis = cmap.get("api_endpoints") or []
        forms = cmap.get("forms") or []
        has_login = bool(cmap.get("has_login_form"))
        has_spa = bool(cmap.get("has_spa_signals"))
        has_api = bool(cmap.get("has_api"))
        has_auth = bool(cmap.get("has_auth"))
    elif cmap is not None:
        pages = getattr(cmap, "pages_visited", None) or []
        apis = getattr(cmap, "api_endpoints", None) or []
        forms = getattr(cmap, "forms", None) or []
        has_login = bool(getattr(cmap, "has_login_form", False))
        has_spa = bool(getattr(cmap, "has_spa_signals", False))
        has_api = bool(getattr(cmap, "has_api", False))
        has_auth = bool(getattr(cmap, "has_auth", False))
    if kickoff.get("hits"):
        for h in kickoff["hits"]:
            path = str(h.get("path") or "")
            ctype = str(h.get("content_type") or "").lower()
            try:
                st = int(h.get("status") or 0)
            except (TypeError, ValueError):
                st = 0
            if _LOGIN_RE.search(path) and st in (200, 302, 401):
                has_login = True
            if "json" in ctype and st in (200, 401, 403, 405):
                has_api = True
            if h.get("product") == "appsmith" or _APPSMITH_RE.search(str(h.get("title") or "")):
                has_spa = True
    title = ""
    if kickoff.get("hits"):
        root = next((h for h in kickoff["hits"] if h.get("kind") == "root"), None)
        title = str((root or {}).get("title") or "")
    if _APPSMITH_RE.search(title) or _APPSMITH_RE.search(blob):
        has_spa = True
        has_login = True
    # Login wall beats "API-only" when we have not crawled past the sign-in page.
    if has_login and len(pages) <= 3 and not (has_api and len(pages) > 3):
        return "login_wall"
    if has_spa and not has_api:
        return "spa"
    if has_api and not pages:
        return "api"
    if has_api and has_auth:
        return "saas"
    if _ADMIN_RE.search(blob) and not has_api:
        return "admin"
    if pages and not forms and not has_api:
        return "marketing"
    return "mixed"


# Product knowledge a human applies once they *name* the app — not page params.
# Login-wall evidence still goes first; these fill SQLi/SSRF/API that the login
# form will never show.
_PRODUCT_HUNTS: Dict[str, List[Dict[str, str]]] = {
    "appsmith": [
        {
            "hunt": "api_authz",
            "specialist": "api_authz",
            "why": (
                "Appsmith workspaces/apps/pages are objects — IDOR on /api/v1 after a "
                "session (anonymousUser vs authed), not Nuclei"
            ),
            "evidence": "/api/v1",
        },
        {
            "hunt": "ssrf",
            "specialist": "ssrf",
            "why": (
                "Appsmith datasources + REST/JS queries fetch URLs the login page never "
                "shows — queue SSRF for after foothold (OOB, not metadata/localhost)"
            ),
            "evidence": "product:appsmith datasources",
        },
        {
            "hunt": "sqli",
            "specialist": "sqli",
            "why": (
                "Appsmith query editor speaks SQL/Mongo against connected DBs — not the "
                "email field on /user/login. Hunt after a session, on mapped queries"
            ),
            "evidence": "product:appsmith query editor",
        },
    ],
}


def _product_name(cmap: Any, kickoff: Dict[str, Any], blob: str) -> str:
    for h in kickoff.get("hits") or []:
        if str(h.get("product") or "").lower() == "appsmith":
            return "appsmith"
        if _APPSMITH_RE.search(str(h.get("title") or "")):
            return "appsmith"
    if _APPSMITH_RE.search(blob):
        return "appsmith"
    techs = " ".join(str(t) for t in (kickoff.get("technologies") or []))
    if _APPSMITH_RE.search(techs):
        return "appsmith"
    return ""


def _add(
    start: List[Dict[str, str]],
    *,
    hunt: str,
    specialist: str,
    why: str,
    evidence: str = "",
    first: bool = False,
) -> None:
    row = {
        "hunt": hunt,
        "specialist": specialist,
        "why": why,
        "evidence": (evidence or "")[:240],
    }
    if first:
        start.insert(0, row)
    else:
        start.append(row)


def start_here_from_observations(
    cmap: Any = None,
    *,
    kickoff: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, str]]:
    """Ranked hunts a human would pick *first*, given only what they saw."""
    kickoff = kickoff or {}
    start: List[Dict[str, str]] = []
    kind = classify_app_kind(cmap, kickoff=kickoff)
    blob = _blob(cmap) + " " + str(kickoff.get("brief") or "")
    product = _product_name(cmap, kickoff, blob)
    pages: Sequence[Any] = []
    apis: Sequence[Any] = []
    forms: Sequence[Any] = []
    param_paths: Sequence[Any] = []
    js_files: Sequence[Any] = []
    authenticated = None
    has_login = False
    has_upload = False
    has_graphql = False
    has_search = False
    has_spa = False
    has_api = False
    if isinstance(cmap, dict):
        pages = cmap.get("pages_visited") or []
        apis = cmap.get("api_endpoints") or []
        forms = cmap.get("forms") or []
        param_paths = cmap.get("param_rich_paths") or []
        js_files = cmap.get("js_files") or []
        authenticated = cmap.get("authenticated")
        has_login = bool(cmap.get("has_login_form") or cmap.get("has_auth"))
        has_upload = bool(cmap.get("has_upload"))
        has_graphql = bool(cmap.get("has_graphql"))
        has_search = bool(cmap.get("has_search"))
        has_spa = bool(cmap.get("has_spa_signals"))
        has_api = bool(cmap.get("has_api"))
    elif cmap is not None:
        pages = getattr(cmap, "pages_visited", None) or []
        apis = getattr(cmap, "api_endpoints", None) or []
        forms = getattr(cmap, "forms", None) or []
        param_paths = getattr(cmap, "param_rich_paths", None) or []
        js_files = getattr(cmap, "js_files", None) or []
        authenticated = getattr(cmap, "authenticated", None)
        has_login = bool(getattr(cmap, "has_login_form", False) or getattr(cmap, "has_auth", False))
        has_upload = bool(getattr(cmap, "has_upload", False))
        has_graphql = bool(getattr(cmap, "has_graphql", False))
        has_search = bool(getattr(cmap, "has_search", False))
        has_spa = bool(getattr(cmap, "has_spa_signals", False))
        has_api = bool(getattr(cmap, "has_api", False))

    for h in kickoff.get("hits") or []:
        path = str(h.get("path") or "")
        ctype = str(h.get("content_type") or "").lower()
        try:
            st = int(h.get("status") or 0)
        except (TypeError, ValueError):
            st = 0
        if _LOGIN_RE.search(path) and st in (200, 302, 401):
            has_login = True
        if "json" in ctype and st in (200, 401, 403, 405):
            has_api = True
        if h.get("product") == "appsmith" or _APPSMITH_RE.search(str(h.get("title") or "")):
            has_spa = True
            has_login = True
    if kind == "login_wall":
        has_login = True
    if kind == "spa":
        has_spa = True

    if kind == "empty" or kickoff.get("needs_dir_brute"):
        _add(
            start,
            hunt="path_enum",
            specialist="content_api",
            why="Root looks empty/404 — a human brute-forces directories before declaring the host clean",
            evidence=str((kickoff.get("brief") or "")[:120]),
            first=True,
        )

    if kind == "wordpress" or _wordpress_in_play(cmap, kickoff):
        _add(
            start,
            hunt="wordpress",
            specialist="injection",
            why="WordPress in-play — REST /wp-json/wp/v2/users then admin-ajax tax_query timing; WPScan is optional",
            evidence=next((str(p) for p in pages if _WP_RE.search(str(p))), "wordpress"),
            first=True,
        )

    if has_spa:
        _add(
            start,
            hunt="spa_client",
            specialist="spa_client",
            why="SPA shell — reconstruct JS/API routes before guessing vulns or treating HTML 200s as extra products",
            evidence=(js_files[0] if js_files else (pages[0] if pages else "spa")),
        )

    if has_login and authenticated is not True:
        _add(
            start,
            hunt="credential_assault",
            specialist="credential_assault",
            why="Login form, no session yet — a human tries tiny default lists, then session logic, before XSS",
            evidence=next(
                (str(p) for p in pages if _LOGIN_RE.search(str(p))),
                next(
                    (
                        str(f.get("action") or "")
                        for f in forms
                        if isinstance(f, dict)
                    ),
                    "login",
                ),
            ),
        )
        _add(
            start,
            hunt="auth_logic",
            specialist="auth_logic",
            why="After a foothold (or if defaults fail) probe session/forced-browse on mapped auth paths",
            evidence="login",
        )
        if product != "appsmith":
            login_ev = next(
                (str(p) for p in pages if _LOGIN_RE.search(str(p))),
                "login",
            )
            _add(
                start,
                hunt="login_injection",
                specialist="sqli",
                why=(
                    "Login/auth fields are an injection surface even with no query params — "
                    "error/boolean/time canaries on username then password, not creds-only"
                ),
                evidence=login_ev,
            )

    id_ev = next(
        (str(p) for p in list(param_paths) + [str(e) for e in apis] if _ID_RE.search(str(p))),
        "",
    )
    if has_api or id_ev:
        _add(
            start,
            hunt="api_authz",
            specialist="api_authz",
            why="Object IDs / first-party APIs observed — a human tests IDOR/BOLA before payload spray",
            evidence=id_ev or (apis[0].get("path") if apis and isinstance(apis[0], dict) else "api"),
        )

    settings_ev = next(
        (str(p) for p in list(pages) + [str(e) for e in apis] + [blob] if _SETTINGS_WRITE_RE.search(str(p))),
        "",
    )
    if settings_ev:
        _add(
            start,
            hunt="unauth_settings_write",
            specialist="api_authz",
            why=(
                "Settings/Save* or ASP.NET App Service APIs — paired unauth write: "
                "sibling 401 vs SaveSettings 200 void (one canary key)"
            ),
            evidence=settings_ev[:240],
            first=bool(re.search(r"settings|savesettings|getsettings", settings_ev, re.I)),
        )

    email_ev = next(
        (str(p) for p in list(pages) + [str(e) for e in apis] + [blob] if _EMAIL_CHANGE_RE.search(str(p))),
        "",
    )
    if email_ev:
        _add(
            start,
            hunt="email_change_ato",
            specialist="auth_logic",
            why=(
                "Email-change / djoser users API — unauth reset_email 204 vs set_password "
                "401 (one canary; do not complete ATO on a real mailbox)"
            ),
            evidence=email_ev[:240],
            first=True,
        )

    ws = []
    if isinstance(cmap, dict):
        ws = list(cmap.get("websockets") or [])
    elif cmap is not None:
        ws = list(getattr(cmap, "websockets", None) or [])
    socket_ev = next(
        (str(p) for p in list(pages) + ws + [blob] if _SOCKETIO_RE.search(str(p))),
        "",
    )
    if socket_ev:
        _add(
            start,
            hunt="socketio_idor",
            specialist="api_authz",
            why=(
                "Socket.IO / get_stream — anonymous url_key for fabricated siteId. "
                "Do not fetch video; do not send null crash loops"
            ),
            evidence=socket_ev[:240],
            first=True,
        )

    ml_ev = next(
        (str(p) for p in list(pages) + [str(e) for e in apis] + [blob] if _ML_PIPELINE_RE.search(str(p))),
        "",
    )
    if ml_ev:
        _add(
            start,
            hunt="ml_pipeline_rbac",
            specialist="api_authz",
            why="ML train/celery APIs — self-reg JWT often has no RBAC; do not delete production models",
            evidence=ml_ev[:240],
        )

    reflect_ev = next(
        (str(p) for p in list(param_paths) + [str(p) for p in pages] if _SEARCH_RE.search(str(p))),
        "",
    )
    if has_search or reflect_ev:
        _add(
            start,
            hunt="xss",
            specialist="xss",
            why="Search/reflect params on the page — XSS canaries on those inputs, not a generic injection dump",
            evidence=reflect_ev or "search",
        )

    ssrf_ev = next((str(p) for p in list(param_paths) + [blob] if _SSRF_RE.search(str(p))), "")
    if ssrf_ev:
        _add(
            start,
            hunt="ssrf",
            specialist="ssrf",
            why="URL-fetch / webhook / proxy fields — execute_interactsh register → plant payload_url → poll",
            evidence=ssrf_ev[:240],
        )

    if param_paths and not reflect_ev:
        _add(
            start,
            hunt="sqli",
            specialist="sqli",
            why="Non-reflect params exist — disciplined SQLi/SSTI canaries on mapped fields only",
            evidence=str(param_paths[0]),
        )
    elif param_paths:
        _add(
            start,
            hunt="sqli",
            specialist="sqli",
            why="Parameter-rich paths besides search — SQLi/cmd after XSS canaries, not instead of them",
            evidence=str(param_paths[0]),
        )

    if has_upload:
        _add(
            start,
            hunt="file_upload",
            specialist="file_upload",
            why="Upload control on the page — content-type/filename tricks, not a webshell",
            evidence=next(
                (
                    str(f.get("action") or "")
                    for f in forms
                    if isinstance(f, dict)
                    and any(re.search(r"file|upload", i or "", re.I) for i in (f.get("inputs") or []))
                ),
                "upload",
            ),
        )
    if has_graphql:
        _add(
            start,
            hunt="graphql",
            specialist="graphql_api",
            why="GraphQL path observed — introspection + object authz, not Nuclei graphql-detect only",
            evidence="graphql",
        )

    for row in _PRODUCT_HUNTS.get(product) or []:
        _add(
            start,
            hunt=row["hunt"],
            specialist=row["specialist"],
            why=row["why"],
            evidence=row.get("evidence") or product,
        )

    if kind == "marketing" and not start:
        _add(
            start,
            hunt="js_secrets",
            specialist="js_secrets",
            why="Marketing/static surface — a human reads JS and headers before inventing injection",
            evidence=(js_files[0] if js_files else (pages[0] if pages else "")),
        )

    # Dedup by specialist, keep first (human priority).
    seen: set[str] = set()
    unique: List[Dict[str, str]] = []
    for row in start:
        key = row["specialist"]
        if key in seen:
            continue
        seen.add(key)
        unique.append(row)
    return unique[:10]


def one_liner(kind: str, cmap: Any = None, kickoff: Optional[Dict[str, Any]] = None) -> str:
    kickoff = kickoff or {}
    title = ""
    target = ""
    if isinstance(cmap, dict):
        target = str(cmap.get("target") or "")
        title = str(cmap.get("title") or "")
    elif cmap is not None:
        target = str(getattr(cmap, "target", "") or "")
    if not title and kickoff.get("hits"):
        root = next((h for h in kickoff["hits"] if h.get("kind") == "root"), None)
        title = str((root or {}).get("title") or "")
    host = urlparse(target).netloc if target else ""
    labels = {
        "empty": "empty/404 root — enumerate hidden paths before hunting bugs",
        "wordpress": "WordPress site — users API and login before template spray",
        "login_wall": "login wall — session/defaults before the rest of the app exists",
        "spa": "client-rendered SPA — recover APIs from JS before guessing vulns",
        "api": "API-first surface — authz on objects, not page XSS",
        "saas": "authenticated SaaS — IDOR/tenant/session before injection",
        "admin": "admin/console surface — privilege and exposure first",
        "marketing": "marketing/static site — JS, headers, leftover admin paths",
        "mixed": "mixed web app — map features, then attack what you saw",
    }
    head = labels.get(kind, labels["mixed"])
    bit = f"{title} — " if title else ""
    where = f" ({host})" if host else ""
    return f"{bit}{head}{where}"


def format_page_assessment_for_prompt(assessment: Optional[Dict[str, Any]]) -> str:
    if not assessment:
        return (
            "No page assessment yet. Browse the app (execute_interceptor / deep_crawl) "
            "before dispatching hunters. Do not spray Nuclei."
        )
    lines = [
        "### How a human tester would start (from what this page shows)",
        f"App kind: {assessment.get('app_kind') or 'unknown'}",
        assessment.get("one_liner") or "",
    ]
    features = assessment.get("observed_features") or []
    if features:
        lines.append("Observed on the page:")
        for feat in features[:8]:
            if isinstance(feat, dict):
                lines.append(f"  - {feat.get('name')}: {feat.get('evidence') or feat.get('why')}")
            else:
                lines.append(f"  - {feat}")
    start = assessment.get("start_here") or []
    if start:
        lines.append("Start here (dispatch these, in order — not a scanner list):")
        for i, row in enumerate(start[:8], 1):
            lines.append(
                f"  {i}. [{row.get('specialist')}] {row.get('why')}"
                + (f" — {row.get('evidence')}" if row.get("evidence") else "")
            )
    skip = assessment.get("do_not_start_with")
    if skip:
        lines.append(skip)
    return "\n".join(line for line in lines if line).strip()


def _observed_features(cmap: Any, kickoff: Optional[Dict[str, Any]]) -> List[Dict[str, str]]:
    feats: List[Dict[str, str]] = []
    kickoff = kickoff or {}

    def flag(name: str, ok: bool, evidence: str = "") -> None:
        if ok:
            feats.append({"name": name, "evidence": evidence[:200]})

    if isinstance(cmap, dict):
        flag("login", bool(cmap.get("has_login_form") or cmap.get("has_auth")))
        flag("upload", bool(cmap.get("has_upload")))
        flag("search", bool(cmap.get("has_search")))
        flag("graphql", bool(cmap.get("has_graphql")))
        flag("api", bool(cmap.get("has_api")), str((cmap.get("api_endpoints") or [{}])[0:1]))
        flag("spa", bool(cmap.get("has_spa_signals")))
        flag("admin", bool(cmap.get("has_admin")))
        n_pages = len(cmap.get("pages_visited") or [])
        n_forms = len(cmap.get("forms") or [])
        if n_pages:
            feats.append({"name": "browsed_pages", "evidence": str(n_pages)})
        if n_forms:
            feats.append({"name": "forms", "evidence": str(n_forms)})
    elif cmap is not None:
        flag("login", bool(getattr(cmap, "has_login_form", False)))
        flag("upload", bool(getattr(cmap, "has_upload", False)))
        flag("search", bool(getattr(cmap, "has_search", False)))
        flag("graphql", bool(getattr(cmap, "has_graphql", False)))
        flag("api", bool(getattr(cmap, "has_api", False)))
        flag("spa", bool(getattr(cmap, "has_spa_signals", False)))
    techs = (kickoff.get("technologies") or [])[:8]
    if techs:
        feats.append({"name": "tech", "evidence": ", ".join(str(t) for t in techs)})
    return feats


def assess_page(
    cmap: Any = None,
    *,
    kickoff: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Return a serializable assessment attached to the capability map."""
    kickoff = kickoff or {}
    kind = classify_app_kind(cmap, kickoff=kickoff)
    start = start_here_from_observations(cmap, kickoff=kickoff)
    assessment = {
        "app_kind": kind,
        "one_liner": one_liner(kind, cmap, kickoff),
        "observed_features": _observed_features(cmap, kickoff),
        "start_here": start,
        "do_not_start_with": (
            "Do NOT start with Nuclei / known-CVE spray. Coverage is leftover after "
            "these hunts. Status 200 is not a finding."
        ),
    }
    assessment["brief"] = format_page_assessment_for_prompt(assessment)
    return assessment


def specialists_from_assessment(
    assessment: Optional[Dict[str, Any]],
    *,
    max_specialists: int = 6,
) -> List[str]:
    """Prefer human start_here order when dispatching auto fireteam."""
    names: List[str] = ["app_mapper"]
    for row in (assessment or {}).get("start_here") or []:
        spec = str(row.get("specialist") or "").strip()
        if spec and spec not in names and spec not in (
            "finding_judge",
            "independent_verifier",
            "risk_assessor",
        ):
            names.append(spec)
        if len(names) >= max_specialists:
            break
    return names[:max_specialists]
