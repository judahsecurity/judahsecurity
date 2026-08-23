"""
Praetorian-style application sitemap persistence.

Store crawls as durable rows: same-origin Sitemap, REST API Endpoints, and
External URLs, with per-path flags (secrets / login / SSO / screenshots / response).

Never raises into callers — ingest helpers catch and log.
"""

from __future__ import annotations

import hashlib
import logging
import re
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.sitemap_entry import (
    KIND_API,
    KIND_EXTERNAL,
    KIND_SITEMAP,
    SitemapEntry,
)

logger = logging.getLogger(__name__)

API_PATH_RE = re.compile(
    r"(/api/|/v\d+/|/graphql|/gql\b|/rest/|/json\b|/xmlrpc|/rpc/|/soap|/openapi|/swagger)",
    re.I,
)
LOGIN_RE = re.compile(
    r"(login|sign[-_]?in|sign[-_]?up|logon|passwd|password|forgot|reset.?password|"
    r"wp-login|wp-admin|accounts?/login|authn?(/|$)|session/new|users/sign)",
    re.I,
)
SSO_RE = re.compile(
    r"(sso|saml|oauth|oidc|openid|/authorize\b|/callback\b|adfs|okta|onelogin|"
    r"auth0|wsfed|cas/login)",
    re.I,
)
SECRETS_PATH_RE = re.compile(
    r"(\.env|credentials|secret|apikey|api[-_]?key|\.git/|id_rsa|backup|dump|"
    r"wp-config|phpinfo|web\.config)",
    re.I,
)
STATIC_EXT_RE = re.compile(
    r"\.(css|woff2?|ttf|eot|png|jpe?g|gif|svg|ico|webp|mp4|mp3|pdf)$",
    re.I,
)


def path_key(kind: str, host: str, method: str, path: str) -> str:
    raw = f"{kind}|{(host or '').lower()}|{(method or '').upper()}|{path or '/'}"
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


def templatize_query(query: str) -> str:
    """Collapse query values to EXPR so tokens/PII are not stored and URLs cluster."""
    if not query:
        return ""
    pairs = []
    for key, value in parse_qsl(query, keep_blank_values=True):
        if value:
            pairs.append((key, "EXPR"))
        else:
            pairs.append((key, ""))
    if not pairs:
        return "EXPR" if query else ""
    return urlencode(pairs, doseq=True)


def _normalize_host(host: str) -> str:
    h = (host or "").strip().lower()
    if h.startswith("[") and "]" in h:
        return h
    return h.split(":")[0]


def _asset_host(asset: Asset) -> str:
    live = (getattr(asset, "live_url", None) or "").strip()
    if live.startswith("http"):
        try:
            return _normalize_host(urlparse(live).netloc)
        except Exception:
            pass
    return _normalize_host(asset.value or "")


def parse_discovered_url(
    raw: str,
    *,
    default_host: str = "",
    default_scheme: str = "https",
) -> Optional[Dict[str, str]]:
    """Parse a URL or path into host/path/url/query_template."""
    text = (raw or "").strip()
    if not text or text.startswith("javascript:") or text.startswith("mailto:"):
        return None
    if text.startswith("//"):
        text = f"{default_scheme}:{text}"
    if not text.startswith(("http://", "https://")):
        if text.startswith("/") and default_host:
            text = f"{default_scheme}://{default_host}{text}"
        elif "/" not in text and "." in text:
            text = f"{default_scheme}://{text}"
        elif default_host:
            text = f"{default_scheme}://{default_host}/{text.lstrip('/')}"
        else:
            return None
    try:
        parsed = urlparse(text)
    except Exception:
        return None
    host = _normalize_host(parsed.netloc)
    if not host:
        return None
    path = parsed.path or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    qtmpl = templatize_query(parsed.query)
    display_path = path if not qtmpl else f"{path}?{qtmpl}"
    rebuilt = urlunparse(
        (parsed.scheme or default_scheme, host, path, "", qtmpl, "")
    )
    return {
        "host": host,
        "path": display_path[:2048],
        "url": rebuilt[:2048],
        "query_template": qtmpl[:1024] if qtmpl else "",
        "scheme": parsed.scheme or default_scheme,
    }


def classify_kind(host: str, path: str, asset_host: str, *, force_api: bool = False) -> str:
    if host and asset_host and host != asset_host:
        return KIND_EXTERNAL
    blob = path or ""
    if force_api or API_PATH_RE.search(blob):
        return KIND_API
    return KIND_SITEMAP


def classify_flags(path: str, url: str = "") -> Dict[str, bool]:
    blob = f"{path} {url}"
    return {
        "has_login": bool(LOGIN_RE.search(blob)),
        "has_sso": bool(SSO_RE.search(blob)),
        "has_secrets": bool(SECRETS_PATH_RE.search(blob)),
    }


def _merge_sources(existing: Optional[list], source: Optional[str]) -> list:
    out: List[str] = []
    for s in list(existing or []) + ([source] if source else []):
        if s and s not in out:
            out.append(s)
    return out[:20]


def _merge_params(existing: Optional[list], incoming: Optional[Iterable[str]]) -> list:
    out: List[str] = []
    for p in list(existing or []) + list(incoming or []):
        s = str(p).strip()
        if s and s not in out:
            out.append(s)
    return out[:80]


def find_asset_for_host(db: Session, organization_id: int, host: str) -> Optional[Asset]:
    host = _normalize_host(host)
    if not host:
        return None
    asset = (
        db.query(Asset)
        .filter(Asset.organization_id == organization_id, Asset.value == host)
        .first()
    )
    if asset:
        return asset
    if host.startswith("www."):
        asset = (
            db.query(Asset)
            .filter(Asset.organization_id == organization_id, Asset.value == host[4:])
            .first()
        )
        if asset:
            return asset
    return (
        db.query(Asset)
        .filter(Asset.organization_id == organization_id, Asset.value == f"www.{host}")
        .first()
    )


def _upsert_rows(
    db: Session,
    *,
    organization_id: int,
    asset: Asset,
    rows: Sequence[Dict[str, Any]],
) -> int:
    """Merge rows onto sitemap_entries for one asset. Caller commits."""
    if not rows:
        return 0
    keys = [r["path_key"] for r in rows if r.get("path_key")]
    existing_map: Dict[str, SitemapEntry] = {}
    if keys:
        found = (
            db.query(SitemapEntry)
            .filter(SitemapEntry.asset_id == asset.id, SitemapEntry.path_key.in_(keys))
            .all()
        )
        existing_map = {e.path_key: e for e in found}

    now = datetime.utcnow()
    created = 0
    for rec in rows:
        key = rec.get("path_key")
        if not key:
            continue
        ent = existing_map.get(key)
        if ent is None:
            ent = SitemapEntry(
                organization_id=organization_id,
                asset_id=asset.id,
                kind=rec["kind"],
                path_key=key,
                host=rec.get("host") or "",
                method=rec.get("method") or "",
                path=rec.get("path") or "/",
                url=rec.get("url") or "",
                query_template=rec.get("query_template") or None,
                has_secrets=bool(rec.get("has_secrets")),
                has_login=bool(rec.get("has_login")),
                has_sso=bool(rec.get("has_sso")),
                screenshot_count=int(rec.get("screenshot_count") or 0),
                screenshot_id=rec.get("screenshot_id"),
                http_status=rec.get("http_status"),
                response_title=(rec.get("response_title") or None),
                source=rec.get("source"),
                sources=_merge_sources([], rec.get("source")),
                parameters=_merge_params([], rec.get("parameters")),
                extra=rec.get("extra") or {},
                first_seen=now,
                last_seen=now,
            )
            db.add(ent)
            existing_map[key] = ent
            created += 1
            continue
        ent.last_seen = now
        ent.has_secrets = bool(ent.has_secrets or rec.get("has_secrets"))
        ent.has_login = bool(ent.has_login or rec.get("has_login"))
        ent.has_sso = bool(ent.has_sso or rec.get("has_sso"))
        if rec.get("http_status"):
            ent.http_status = rec["http_status"]
        if rec.get("response_title"):
            ent.response_title = rec["response_title"][:512]
        if rec.get("screenshot_id"):
            ent.screenshot_id = rec["screenshot_id"]
        if rec.get("screenshot_count"):
            ent.screenshot_count = max(int(ent.screenshot_count or 0), int(rec["screenshot_count"]))
        elif rec.get("screenshot_id"):
            ent.screenshot_count = max(int(ent.screenshot_count or 0), 1)
        if rec.get("query_template") and not ent.query_template:
            ent.query_template = rec["query_template"]
        ent.sources = _merge_sources(ent.sources, rec.get("source"))
        ent.parameters = _merge_params(ent.parameters, rec.get("parameters"))
        if rec.get("source"):
            ent.source = rec["source"]
        if rec.get("url"):
            ent.url = rec["url"]
    return created


def _record_from_parsed(
    parsed: Dict[str, str],
    *,
    asset_host: str,
    source: str,
    method: str = "",
    force_kind: Optional[str] = None,
    force_api: bool = False,
    has_secrets: bool = False,
    has_login: bool = False,
    has_sso: bool = False,
    http_status: Optional[int] = None,
    response_title: Optional[str] = None,
    screenshot_id: Optional[int] = None,
    screenshot_count: int = 0,
    parameters: Optional[List[str]] = None,
) -> Optional[Dict[str, Any]]:
    kind = force_kind or classify_kind(
        parsed["host"], parsed["path"], asset_host, force_api=force_api
    )
    flags = classify_flags(parsed["path"], parsed["url"])
    method_n = (method or "").upper().strip()
    if kind == KIND_SITEMAP and not method_n:
        method_n = "GET"
    if kind == KIND_EXTERNAL and not method_n:
        method_n = "GET"
    rec = {
        "kind": kind,
        "host": parsed["host"],
        "method": method_n,
        "path": parsed["path"] if kind != KIND_EXTERNAL else parsed["url"],
        "url": parsed["url"],
        "query_template": parsed.get("query_template") or "",
        "has_secrets": bool(has_secrets or flags["has_secrets"]),
        "has_login": bool(has_login or flags["has_login"]),
        "has_sso": bool(has_sso or flags["has_sso"]),
        "http_status": http_status,
        "response_title": response_title,
        "screenshot_id": screenshot_id,
        "screenshot_count": screenshot_count,
        "source": source,
        "parameters": list(parameters or []),
    }
    rec["path_key"] = path_key(kind, rec["host"], rec["method"], rec["path"])
    return rec


def ingest_urls_for_asset(
    db: Session,
    organization_id: int,
    asset: Asset,
    urls: Iterable[Any],
    *,
    source: str,
    methods: Optional[Dict[str, str]] = None,
    force_kind: Optional[str] = None,
    force_api: bool = False,
    has_secrets: bool = False,
    has_login: bool = False,
    has_sso: bool = False,
    http_status: Optional[int] = None,
    response_title: Optional[str] = None,
    screenshot_id: Optional[int] = None,
) -> int:
    """Upsert discovered URLs/paths onto the asset's sitemap. Caller commits."""
    asset_host = _asset_host(asset)
    methods = methods or {}
    rows: List[Dict[str, Any]] = []
    seen_keys = set()
    for item in urls:
        method = ""
        raw = item
        item_login = has_login
        item_sso = has_sso
        item_secrets = has_secrets
        item_status = http_status
        item_title = response_title
        if isinstance(item, dict):
            raw = item.get("url") or item.get("path") or item.get("value") or ""
            method = (item.get("method") or "").upper()
            item_login = bool(has_login or item.get("has_login") or item.get("login"))
            item_sso = bool(has_sso or item.get("has_sso") or item.get("sso"))
            item_secrets = bool(has_secrets or item.get("has_secrets"))
            if item.get("status") or item.get("http_status"):
                try:
                    item_status = int(item.get("status") or item.get("http_status"))
                except (TypeError, ValueError):
                    pass
            item_title = item.get("title") or item.get("response_title") or response_title
        raw_s = str(raw or "").strip()
        if not raw_s:
            continue
        parsed = parse_discovered_url(raw_s, default_host=asset_host)
        if not parsed:
            continue
        if STATIC_EXT_RE.search(parsed["path"]) and not item_secrets:
            continue
        rec = _record_from_parsed(
            parsed,
            asset_host=asset_host,
            source=source,
            method=method or methods.get(raw_s, ""),
            force_kind=force_kind,
            force_api=force_api or bool(API_PATH_RE.search(raw_s)),
            has_secrets=item_secrets,
            has_login=item_login,
            has_sso=item_sso,
            http_status=item_status,
            response_title=item_title,
            screenshot_id=screenshot_id,
        )
        if not rec or rec["path_key"] in seen_keys:
            continue
        seen_keys.add(rec["path_key"])
        rows.append(rec)
        if parsed.get("query_template"):
            rec["parameters"] = _merge_params(
                rec.get("parameters"),
                [k for k, _ in parse_qsl(parsed["query_template"], keep_blank_values=True)],
            )
    # chunk to keep IN() lists reasonable
    total = 0
    for i in range(0, len(rows), 400):
        total += _upsert_rows(
            db,
            organization_id=organization_id,
            asset=asset,
            rows=rows[i : i + 400],
        )
    try:
        from app.services.rest_inventory_service import (
            fetch_and_store_spec,
            looks_like_spec_url,
            merge_rest_endpoints,
        )

        api_rows = [r for r in rows if r.get("kind") == KIND_API]
        if api_rows:
            merge_rest_endpoints(
                asset,
                [
                    {
                        "method": r.get("method") or "GET",
                        "path": r.get("path") or "/",
                        "url": r.get("url"),
                        "parameters": r.get("parameters") or [],
                        "status": r.get("http_status"),
                    }
                    for r in api_rows
                ],
                source=source if source != "interceptor" else "vespasian",
            )
        for r in rows:
            url = r.get("url") or r.get("path") or ""
            if looks_like_spec_url(url):
                fetch_and_store_spec(asset, url if str(url).startswith("http") else r.get("url") or url, source="openapi")
    except Exception as e:
        logger.debug("rest inventory merge skipped: %s", e)
    return total


def persist_crawl_urls(
    db: Session,
    organization_id: int,
    asset: Asset,
    *,
    urls: Optional[Iterable[str]] = None,
    endpoints: Optional[Iterable[str]] = None,
    api_urls: Optional[Iterable[str]] = None,
    source: str,
) -> int:
    n = 0
    if urls:
        n += ingest_urls_for_asset(db, organization_id, asset, urls, source=source)
    if endpoints:
        n += ingest_urls_for_asset(db, organization_id, asset, endpoints, source=source)
    if api_urls:
        n += ingest_urls_for_asset(
            db, organization_id, asset, api_urls, source=source, force_api=True
        )
    return n


def persist_capability_map(
    db: Session,
    organization_id: int,
    cmap: Dict[str, Any],
    *,
    source: str = "interceptor",
) -> int:
    """Fold an Application Capability Map into sitemap_entries for the target host."""
    if not cmap or not organization_id:
        return 0
    target = str(cmap.get("target") or "").strip()
    parsed_target = parse_discovered_url(target) if target else None
    host = (parsed_target or {}).get("host") or _normalize_host(urlparse(target).netloc if target else "")
    if not host:
        return 0
    asset = find_asset_for_host(db, organization_id, host)
    if not asset:
        logger.info("sitemap: no asset for host %s (org %s); skip capability map persist", host, organization_id)
        return 0

    pages = list(cmap.get("pages_visited") or [])
    js_endpoints = list(cmap.get("js_endpoints") or [])
    third = list(cmap.get("third_party") or [])
    api_eps = list(cmap.get("api_endpoints") or [])
    forms = list(cmap.get("forms") or [])
    js_files = list(cmap.get("js_files") or [])

    n = ingest_urls_for_asset(db, organization_id, asset, pages + js_endpoints + js_files, source=source)

    api_raw: List[Dict[str, Any]] = []
    for e in api_eps:
        if isinstance(e, dict):
            path = e.get("path") or ""
            ehost = e.get("host") or host
            method = e.get("method") or "GET"
            url = path if str(path).startswith("http") else f"https://{ehost}{path if str(path).startswith('/') else '/' + str(path)}"
            api_raw.append({"url": url, "method": method})
        elif e:
            api_raw.append({"url": str(e), "method": "GET"})
    n += ingest_urls_for_asset(
        db, organization_id, asset, api_raw, source=source, force_api=True
    )

    n += ingest_urls_for_asset(
        db, organization_id, asset, third, source=source, force_kind=KIND_EXTERNAL
    )

    form_urls = []
    for f in forms:
        if not isinstance(f, dict):
            continue
        action = f.get("action") or f.get("page") or ""
        if action:
            form_urls.append(
                {
                    "url": action,
                    "method": (f.get("method") or "POST").upper(),
                    "has_login": bool(
                        classify_flags(action).get("has_login")
                        or any(
                            LOGIN_RE.search(str(i or ""))
                            for i in (f.get("inputs") or [])
                        )
                    ),
                }
            )
    if form_urls:
        n += ingest_urls_for_asset(db, organization_id, asset, form_urls, source=source)
    try:
        from app.services.rest_inventory_service import (
            fetch_and_store_spec,
            looks_like_spec_url,
            merge_rest_endpoints,
            rest_rows_from_capability_map,
        )

        merge_rest_endpoints(
            asset,
            rest_rows_from_capability_map(cmap),
            source="vespasian" if source in ("interceptor", "deep_crawl") else source,
        )
        for blob in list(cmap.get("pages_visited") or []) + list(cmap.get("js_endpoints") or []) + list(
            cmap.get("api_endpoints") or []
        ):
            text = blob.get("path") if isinstance(blob, dict) else blob
            if looks_like_spec_url(str(text or "")):
                url = str(blob.get("url") or text) if isinstance(blob, dict) else str(blob)
                if not url.startswith("http"):
                    url = (asset.live_url or f"https://{asset.value}").rstrip("/") + "/" + url.lstrip("/")
                fetch_and_store_spec(asset, url, source="openapi")
    except Exception as e:
        logger.debug("rest inventory from capability map skipped: %s", e)
    return n


def persist_capability_map_safe(
    organization_id: Optional[int],
    cmap: Optional[Dict[str, Any]],
    *,
    source: str = "interceptor",
    db: Optional[Session] = None,
) -> int:
    if not organization_id or not cmap:
        return 0
    own = db is None
    if own:
        from app.db.database import SessionLocal

        db = SessionLocal()
    try:
        n = persist_capability_map(db, int(organization_id), cmap, source=source)
        if own:
            db.commit()
        return n
    except Exception as e:
        logger.warning("sitemap capability-map persist failed: %s", e)
        if own and db is not None:
            try:
                db.rollback()
            except Exception:
                pass
        return 0
    finally:
        if own and db is not None:
            try:
                db.close()
            except Exception:
                pass


def mark_secrets_on_urls(
    db: Session,
    organization_id: int,
    urls: Iterable[str],
    *,
    source: str = "js_recon",
) -> int:
    n = 0
    by_host: Dict[str, List[str]] = {}
    for u in urls:
        parsed = parse_discovered_url(str(u))
        if not parsed:
            continue
        by_host.setdefault(parsed["host"], []).append(parsed["url"])
    for host, host_urls in by_host.items():
        asset = find_asset_for_host(db, organization_id, host)
        if not asset:
            continue
        n += ingest_urls_for_asset(
            db, organization_id, asset, host_urls, source=source, has_secrets=True
        )
    return n


def link_screenshot(
    db: Session,
    asset: Asset,
    url: str,
    *,
    screenshot_id: Optional[int],
    http_status: Optional[int] = None,
    response_title: Optional[str] = None,
    source: str = "screenshot",
) -> int:
    return ingest_urls_for_asset(
        db,
        asset.organization_id,
        asset,
        [url],
        source=source,
        http_status=http_status,
        response_title=response_title,
        screenshot_id=screenshot_id,
    )


def hydrate_from_asset_json(db: Session, asset: Asset) -> int:
    """One-shot backfill from legacy asset.endpoints / login_portals JSON."""
    existing = (
        db.query(SitemapEntry.id)
        .filter(SitemapEntry.asset_id == asset.id)
        .limit(1)
        .first()
    )
    if existing:
        return 0
    n = 0
    org_id = asset.organization_id
    endpoints = list(asset.endpoints or [])
    if endpoints:
        n += ingest_urls_for_asset(db, org_id, asset, endpoints, source="legacy_endpoints")
    portals = list(asset.login_portals or [])
    if portals:
        n += ingest_urls_for_asset(
            db, org_id, asset, portals, source="login_portal", has_login=True
        )
    js_files = list(asset.js_files or [])
    if js_files:
        n += ingest_urls_for_asset(db, org_id, asset, js_files, source="legacy_js")
    return n


def entries_for_asset(
    db: Session,
    asset_id: int,
    *,
    kind: Optional[str] = None,
    secrets: Optional[bool] = None,
    login: Optional[bool] = None,
    sso: Optional[bool] = None,
    screenshots: Optional[bool] = None,
    response: Optional[bool] = None,
    search: Optional[str] = None,
    limit: int = 5000,
) -> List[SitemapEntry]:
    q = db.query(SitemapEntry).filter(SitemapEntry.asset_id == asset_id)
    if kind:
        q = q.filter(SitemapEntry.kind == kind)
    if secrets is True:
        q = q.filter(SitemapEntry.has_secrets.is_(True))
    if login is True:
        q = q.filter(SitemapEntry.has_login.is_(True))
    if sso is True:
        q = q.filter(SitemapEntry.has_sso.is_(True))
    if screenshots is True:
        q = q.filter(SitemapEntry.screenshot_count > 0)
    if response is True:
        q = q.filter(SitemapEntry.http_status.isnot(None))
    if search:
        like = f"%{search.strip()}%"
        q = q.filter(
            (SitemapEntry.path.ilike(like))
            | (SitemapEntry.url.ilike(like))
            | (SitemapEntry.host.ilike(like))
        )
    return (
        q.order_by(SitemapEntry.kind, SitemapEntry.path)
        .limit(max(1, min(limit, 20000)))
        .all()
    )


def summarize_entries(entries: Sequence[SitemapEntry]) -> Dict[str, int]:
    return {
        "sitemap": sum(1 for e in entries if e.kind == KIND_SITEMAP),
        "api": sum(1 for e in entries if e.kind == KIND_API),
        "external": sum(1 for e in entries if e.kind == KIND_EXTERNAL),
        "secrets": sum(1 for e in entries if e.has_secrets),
        "login": sum(1 for e in entries if e.has_login),
        "sso": sum(1 for e in entries if e.has_sso),
        "screenshots": sum(1 for e in entries if (e.screenshot_count or 0) > 0),
        "with_response": sum(1 for e in entries if e.http_status is not None),
        "total": len(entries),
    }
