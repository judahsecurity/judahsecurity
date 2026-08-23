"""
REST API inventory on the asset record (Praetorian / Vespasian shape).

Existing crawls already observe XHR, Swagger/OpenAPI paths, and Katana API URLs.
This module writes that data onto ``Asset.rest_endpoints`` and ``Asset.api_specs``:

  method, path, parameters, access (No Auth / Auth Required), response
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import parse_qsl, urljoin, urlparse

from sqlalchemy.orm import Session

from app.models.asset import Asset

logger = logging.getLogger(__name__)

ACCESS_NO_AUTH = "no_auth"
ACCESS_REQUIRED = "auth_required"
ACCESS_UNKNOWN = "unknown"

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.I,
)
_SPEC_NAME_RE = re.compile(
    r"(openapi|swagger|api-docs|/api/schema)(\.(json|yaml|yml))?$",
    re.I,
)
_SPEC_PATHS = (
    "/swagger.json",
    "/swagger.yaml",
    "/openapi.json",
    "/openapi.yaml",
    "/v3/api-docs",
    "/v2/api-docs",
    "/api-docs",
    "/api/schema",
    "/api/schema/",
    "/docs/openapi.json",
    "/swagger/v1/swagger.json",
)
_STATIC_EXT = re.compile(
    r"\.(?:css|js|mjs|map|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|mp4|webm|pdf)$",
    re.I,
)
_REST_HINT = re.compile(
    r"(/api/|/graphql|/gql\b|/v\d+/|/rest/|/json|/xmlrpc|/openapi|/swagger"
    r"|/collect\b|/consent|/cookieconsent|\.json$|\.php$|/newsletter|/query)",
    re.I,
)
_MAX_ENDPOINTS = 2500
_MAX_SPEC_BYTES = 250_000


def normalize_api_path(path: str) -> str:
    """Collapse ids/UUIDs so observed URLs cluster like OpenAPI templates."""
    parts = []
    for part in (path or "/").split("/"):
        if not part:
            continue
        name, dot, ext = part.rpartition(".")
        if part.isdigit() or _UUID_RE.match(part):
            parts.append("{id}")
        elif dot and _UUID_RE.match(name):
            parts.append(f"{{id}}.{ext}")
        elif len(part) > 24 and re.match(r"^[A-Za-z0-9_-]+$", part):
            parts.append("{id}")
        else:
            parts.append(part)
    return "/" + "/".join(parts) if parts else "/"


def _infer_access(*, status: Optional[int] = None, has_auth_header: bool = False, spec_access: Optional[str] = None) -> str:
    if spec_access in (ACCESS_NO_AUTH, ACCESS_REQUIRED):
        return spec_access
    if status in (401, 403):
        return ACCESS_REQUIRED
    if has_auth_header:
        return ACCESS_REQUIRED
    if status is not None and 200 <= status < 400:
        return ACCESS_NO_AUTH
    return ACCESS_UNKNOWN


def looks_like_rest(method: str, path: str) -> bool:
    """XHR/spec rows belong in REST; static assets and HTML pages do not."""
    p = (path or "/").split("?")[0]
    if _STATIC_EXT.search(p):
        return False
    m = (method or "GET").upper()
    if m in ("POST", "PUT", "PATCH", "DELETE"):
        return True
    return bool(_REST_HINT.search(p) or "{" in p)


def _status_from_operation(operation: Dict[str, Any]) -> Optional[int]:
    responses = operation.get("responses") or {}
    if not isinstance(responses, dict):
        return None
    for code in ("200", "201", "204", "302", "301", "401", "403", "404"):
        if code in responses:
            try:
                return int(code)
            except ValueError:
                continue
    for code in responses:
        if str(code).isdigit():
            return int(code)
    return None


def _op_access_from_spec(spec: Dict[str, Any], operation: Dict[str, Any]) -> str:
    sec = operation.get("security")
    if sec is None:
        sec = spec.get("security")
    if sec == [] or sec is None or sec == [{}]:
        return ACCESS_NO_AUTH
    if isinstance(sec, list) and len(sec) == 0:
        return ACCESS_NO_AUTH
    return ACCESS_REQUIRED


def _collect_params(operation: Dict[str, Any], path_item: Dict[str, Any], path: str) -> List[str]:
    names: List[str] = []
    for blob in (path_item.get("parameters") or []) + (operation.get("parameters") or []):
        if isinstance(blob, dict) and blob.get("name"):
            names.append(str(blob["name"]))
    for m in re.finditer(r"\{([^}/]+)\}", path or ""):
        if m.group(1) not in names:
            names.append(m.group(1))
    body = operation.get("requestBody") or {}
    content = body.get("content") if isinstance(body, dict) else {}
    if isinstance(content, dict):
        for media in content.values():
            schema = (media or {}).get("schema") or {}
            props = schema.get("properties") if isinstance(schema, dict) else None
            if isinstance(props, dict):
                names.extend(str(k) for k in props.keys())
    out: List[str] = []
    for n in names:
        if n and n not in out:
            out.append(n)
    return out[:80]


def endpoints_from_openapi(spec: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Parse Swagger 2 / OpenAPI 3 paths into REST inventory rows."""
    if not isinstance(spec, dict) or not spec.get("paths"):
        return []
    base = str(spec.get("basePath") or "")
    rows: List[Dict[str, Any]] = []
    for raw_path, path_item in (spec.get("paths") or {}).items():
        if not isinstance(path_item, dict):
            continue
        path = f"{base}{raw_path}" if base and not str(raw_path).startswith(base) else str(raw_path)
        if not path.startswith("/"):
            path = "/" + path
        for method, operation in path_item.items():
            m = str(method).upper()
            if m not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
                continue
            if not isinstance(operation, dict):
                continue
            params = _collect_params(operation, path_item, path)
            access = _op_access_from_spec(spec, operation)
            status = _status_from_operation(operation)
            rows.append(
                {
                    "method": m,
                    "path": path,
                    "parameters": params,
                    "param_count": len(params),
                    "access": access,
                    "status": status,
                    "source": "openapi",
                    "summary": (operation.get("summary") or operation.get("operationId") or "")[:200],
                }
            )
    return rows


def _row_key(method: str, path: str) -> str:
    return f"{(method or 'GET').upper()} {path or '/'}"


def merge_rest_endpoints(asset: Asset, incoming: Iterable[Dict[str, Any]], *, source: str) -> int:
    """Upsert REST rows onto ``asset.rest_endpoints``. Returns newly added count."""
    existing = [e for e in (asset.rest_endpoints or []) if isinstance(e, dict)]
    by_key: Dict[str, Dict[str, Any]] = {}
    for e in existing:
        by_key[_row_key(str(e.get("method") or "GET"), str(e.get("path") or "/"))] = e

    now = datetime.utcnow().isoformat()
    added = 0
    for raw in incoming:
        if not isinstance(raw, dict):
            continue
        method = str(raw.get("method") or "GET").upper()
        path = normalize_api_path(str(raw.get("path") or raw.get("normalized_path") or "/"))
        if not path:
            continue
        if _STATIC_EXT.search(path):
            continue
        params = [str(p) for p in (raw.get("parameters") or []) if p]
        if raw.get("url") and "?" in str(raw.get("url")):
            q = urlparse(str(raw["url"])).query
            for k, _ in parse_qsl(q, keep_blank_values=True):
                if k not in params:
                    params.append(k)
        status = raw.get("status") or raw.get("http_status")
        if status is None and raw.get("status_codes"):
            try:
                status = int(raw["status_codes"][-1])
            except (TypeError, ValueError, IndexError):
                status = None
        try:
            status_i = int(status) if status is not None else None
        except (TypeError, ValueError):
            status_i = None
        access = _infer_access(
            status=status_i,
            has_auth_header=bool(raw.get("has_auth_header")),
            spec_access=raw.get("access") if raw.get("access") in (ACCESS_NO_AUTH, ACCESS_REQUIRED) else None,
        )
        key = _row_key(method, path)
        row = by_key.get(key)
        srcs = []
        if row:
            srcs = list(row.get("sources") or [])
            if source and source not in srcs:
                srcs.append(source)
            merged_params = list(row.get("parameters") or [])
            for p in params:
                if p not in merged_params:
                    merged_params.append(p)
            if status_i:
                row["status"] = status_i
            if access != ACCESS_UNKNOWN:
                row["access"] = access
            row["parameters"] = merged_params[:80]
            row["param_count"] = len(row["parameters"])
            row["sources"] = srcs[:12]
            row["source"] = source or row.get("source")
            row["last_seen"] = now
        else:
            if source:
                srcs.append(source)
            by_key[key] = {
                "method": method,
                "path": path,
                "parameters": params[:80],
                "param_count": len(params[:80]),
                "access": access,
                "status": status_i,
                "source": source,
                "sources": srcs,
                "first_seen": now,
                "last_seen": now,
                "summary": (raw.get("summary") or "")[:200],
            }
            added += 1

    asset.rest_endpoints = list(by_key.values())[:_MAX_ENDPOINTS]
    return added


def merge_api_spec(asset: Asset, spec_meta: Dict[str, Any]) -> None:
    specs = [s for s in (asset.api_specs or []) if isinstance(s, dict)]
    url = str(spec_meta.get("url") or "")
    specs = [s for s in specs if s.get("url") != url]
    specs.insert(0, spec_meta)
    asset.api_specs = specs[:8]


def parse_spec_document(text: str, content_type: str = "") -> Optional[Dict[str, Any]]:
    blob = (text or "").strip()
    if not blob:
        return None
    data = None
    ct = (content_type or "").lower()
    if "json" in ct or blob.startswith("{") or blob.startswith("["):
        try:
            data = json.loads(blob)
        except json.JSONDecodeError:
            data = None
    if data is None:
        try:
            import yaml

            data = yaml.safe_load(blob)
        except Exception:
            return None
    if isinstance(data, dict) and (data.get("paths") or data.get("openapi") or data.get("swagger")):
        return data
    return None


def store_openapi_spec(asset: Asset, *, url: str, spec: Dict[str, Any], source: str = "openapi") -> int:
    """Persist spec metadata + documented endpoints onto the asset."""
    info = spec.get("info") or {}
    endpoints = endpoints_from_openapi(spec)
    encoded = json.dumps(spec, default=str)
    meta = {
        "url": url,
        "title": (info.get("title") or "")[:200],
        "version": str(spec.get("openapi") or spec.get("swagger") or info.get("version") or ""),
        "endpoint_count": len(endpoints),
        "discovered_by": source,
        "last_captured": datetime.utcnow().isoformat(),
        "format": "openapi",
    }
    if len(encoded) <= _MAX_SPEC_BYTES:
        meta["spec"] = spec
    merge_api_spec(asset, meta)
    return merge_rest_endpoints(asset, endpoints, source=source)


def rest_rows_from_capability_map(cmap: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for e in cmap.get("api_endpoints") or []:
        if isinstance(e, dict):
            path = str(e.get("path") or "")
            if " " in path and path.split(" ", 1)[0].isalpha():
                method, path = path.split(" ", 1)
            else:
                method = e.get("method") or "GET"
            if path.startswith("http"):
                parsed = urlparse(path)
                path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
            path_only = path.split("?")[0]
            if not looks_like_rest(str(method), path_only):
                continue
            rows.append({"method": method, "path": path_only, "url": path, "source": "vespasian"})
        elif e and looks_like_rest("GET", str(e)):
            rows.append({"method": "GET", "path": str(e), "source": "vespasian"})
    for s in cmap.get("api_samples") or []:
        if not isinstance(s, dict):
            continue
        headers = s.get("headers") or {}
        has_auth = any(str(k).lower() == "authorization" for k in headers)
        url = str(s.get("url") or "")
        parsed = urlparse(url)
        path = parsed.path or "/"
        if _STATIC_EXT.search(path):
            continue
        rows.append(
            {
                "method": s.get("method") or "GET",
                "path": path,
                "url": url,
                "has_auth_header": has_auth,
                "status": s.get("status") or s.get("http_status"),
                "source": "vespasian",
            }
        )
    for form in cmap.get("forms") or []:
        if not isinstance(form, dict):
            continue
        method = str(form.get("method") or "POST").upper()
        action = str(form.get("action") or form.get("page") or "")
        if not action:
            continue
        parsed = urlparse(action) if action.startswith("http") else None
        path = (parsed.path if parsed else action) or "/"
        if not path.startswith("/"):
            path = "/" + path
        if method in ("GET",) and not looks_like_rest(method, path):
            continue
        if method not in ("POST", "PUT", "PATCH", "DELETE") and not looks_like_rest(method, path):
            continue
        params = [str(i) for i in (form.get("inputs") or []) if i]
        rows.append(
            {
                "method": method,
                "path": path.split("?")[0],
                "url": action,
                "parameters": params,
                "source": "vespasian",
            }
        )
    return rows


def rest_rows_from_urls(urls: Iterable[Any], *, method: str = "GET") -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for item in urls:
        raw_method = method
        raw = item
        status = None
        if isinstance(item, dict):
            raw = item.get("url") or item.get("path") or ""
            raw_method = item.get("method") or method
            status = item.get("status") or item.get("http_status")
        text = str(raw or "").strip()
        if not text:
            continue
        if text.startswith("http"):
            parsed = urlparse(text)
            path = parsed.path or "/"
            url = text
        else:
            path = text if text.startswith("/") else "/" + text
            url = text
        rows.append({"method": raw_method, "path": path, "url": url, "status": status})
    return rows


def looks_like_spec_url(url_or_path: str) -> bool:
    return bool(_SPEC_NAME_RE.search((url_or_path or "").split("?")[0]))


def fetch_and_store_spec(asset: Asset, spec_url: str, *, source: str = "openapi") -> int:
    """GET a discovered swagger/openapi URL and store documented endpoints on the asset."""
    try:
        import httpx
    except ImportError:
        return 0
    try:
        with httpx.Client(verify=False, timeout=12.0, follow_redirects=True) as client:
            resp = client.get(
                spec_url,
                headers={"Accept": "application/json, application/yaml, text/yaml, */*"},
            )
        if resp.status_code not in (200, 201, 206):
            return 0
        spec = parse_spec_document(resp.text, resp.headers.get("content-type", ""))
        if not spec:
            return 0
        return store_openapi_spec(asset, url=str(resp.url), spec=spec, source=source)
    except Exception as e:
        logger.debug("openapi fetch failed for %s: %s", spec_url, e)
        return 0


def discover_specs_for_asset(asset: Asset, base_url: str, *, extra_urls: Optional[Iterable[str]] = None) -> int:
    """Probe common spec paths (same list kickoff already hits) and persist if found."""
    parsed = urlparse(base_url if base_url.startswith("http") else f"https://{base_url}")
    origin = f"{parsed.scheme}://{parsed.netloc}"
    candidates = [urljoin(origin, p) for p in _SPEC_PATHS]
    for u in extra_urls or []:
        if u and str(u) not in candidates:
            candidates.append(str(u))
    n = 0
    for url in candidates:
        n += fetch_and_store_spec(asset, url, source="openapi")
        if n and len(asset.api_specs or []) >= 3:
            break
    return n


def persist_rest_inventory_safe(
    db: Optional[Session],
    organization_id: Optional[int],
    host_or_url: str,
    *,
    cmap: Optional[Dict[str, Any]] = None,
    urls: Optional[Iterable[Any]] = None,
    source: str = "vespasian",
    probe_specs: bool = False,
) -> int:
    """Resolve asset by host and write REST inventory. Never raises."""
    if not organization_id or not host_or_url:
        return 0
    own = db is None
    if own:
        from app.db.database import SessionLocal

        db = SessionLocal()
    try:
        from app.services.sitemap_service import find_asset_for_host, parse_discovered_url

        parsed = parse_discovered_url(host_or_url) or {}
        host = parsed.get("host") or urlparse(host_or_url if "://" in host_or_url else f"https://{host_or_url}").netloc
        asset = find_asset_for_host(db, int(organization_id), host)
        if not asset:
            return 0
        n = 0
        if cmap:
            n += merge_rest_endpoints(asset, rest_rows_from_capability_map(cmap), source=source)
        if urls:
            n += merge_rest_endpoints(asset, rest_rows_from_urls(urls), source=source)
            for item in urls:
                raw = item.get("url") if isinstance(item, dict) else item
                if looks_like_spec_url(str(raw or "")):
                    spec_url = str(raw)
                    if not spec_url.startswith("http"):
                        live = asset.live_url or f"https://{asset.value}"
                        spec_url = urljoin(live.rstrip("/") + "/", spec_url.lstrip("/"))
                    n += fetch_and_store_spec(asset, spec_url, source="openapi")
        if probe_specs:
            live = asset.live_url or f"https://{asset.value}"
            n += discover_specs_for_asset(asset, live)
        if own:
            db.commit()
        return n
    except Exception as e:
        logger.warning("rest inventory persist failed: %s", e)
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


def hydrate_rest_from_existing(asset: Asset, *, sitemap_api: Optional[Iterable[Any]] = None) -> int:
    """Backfill ``asset.rest_endpoints`` from Katana metadata / sitemap API rows already on the asset."""
    if any(isinstance(e, dict) for e in (asset.rest_endpoints or [])):
        return 0
    incoming: List[Dict[str, Any]] = []
    meta = asset.metadata_ or {}
    incoming.extend(rest_rows_from_urls(meta.get("katana_api_endpoints") or []))
    for node in sitemap_api or []:
        if isinstance(node, dict):
            incoming.append(
                {
                    "method": node.get("method") or "GET",
                    "path": node.get("path") or "/",
                    "url": node.get("url"),
                    "parameters": node.get("parameters") or [],
                    "status": node.get("http_status") or node.get("status"),
                    "access": node.get("access"),
                }
            )
        else:
            incoming.append(
                {
                    "method": getattr(node, "method", None) or "GET",
                    "path": getattr(node, "path", None) or "/",
                    "url": getattr(node, "url", None),
                    "parameters": list(getattr(node, "parameters", None) or []),
                    "status": getattr(node, "http_status", None),
                    "access": getattr(node, "access", None),
                }
            )
    n = merge_rest_endpoints(asset, incoming, source="katana")
    for spec in asset.api_specs or []:
        if isinstance(spec, dict) and isinstance(spec.get("spec"), dict):
            n += store_openapi_spec(
                asset,
                url=str(spec.get("url") or ""),
                spec=spec["spec"],
                source=str(spec.get("discovered_by") or "openapi"),
            )
    return n


def summarize_rest(asset: Asset) -> Dict[str, Any]:
    rows = [e for e in (asset.rest_endpoints or []) if isinstance(e, dict)]
    methods = sorted({str(e.get("method") or "GET").upper() for e in rows})
    unauth = sum(1 for e in rows if e.get("access") == ACCESS_NO_AUTH)
    last = None
    for e in rows:
        ls = e.get("last_seen")
        if ls and (last is None or str(ls) > str(last)):
            last = ls
    specs = [s for s in (asset.api_specs or []) if isinstance(s, dict)]
    sources = []
    for e in rows:
        for s in e.get("sources") or ([e.get("source")] if e.get("source") else []):
            if s and s not in sources:
                sources.append(s)
    return {
        "endpoint_count": len(rows),
        "method_count": len(methods),
        "methods": methods,
        "unauthenticated_count": unauth,
        "last_captured": last or (specs[0].get("last_captured") if specs else None),
        "discovered_by": sources[0] if sources else ("openapi" if specs else None),
        "spec_count": len(specs),
    }


def to_openapi_yaml(asset: Asset) -> Optional[str]:
    """Rebuild a minimal OpenAPI document from stored spec or inventory."""
    for spec in asset.api_specs or []:
        if isinstance(spec, dict) and spec.get("spec"):
            try:
                import yaml

                return yaml.safe_dump(spec["spec"], sort_keys=False)
            except Exception:
                return json.dumps(spec["spec"], indent=2)
    rows = [e for e in (asset.rest_endpoints or []) if isinstance(e, dict)]
    if not rows:
        return None
    paths: Dict[str, Any] = {}
    for e in rows:
        path = e.get("path") or "/"
        method = str(e.get("method") or "get").lower()
        paths.setdefault(path, {})[method] = {
            "summary": e.get("summary") or "",
            "parameters": [{"name": p, "in": "query"} for p in (e.get("parameters") or [])],
            "responses": {"200": {"description": "Observed or documented"}},
        }
    doc = {
        "openapi": "3.0.3",
        "info": {"title": f"{asset.value} API", "version": "discovered"},
        "paths": paths,
    }
    try:
        import yaml

        return yaml.safe_dump(doc, sort_keys=False)
    except Exception:
        return json.dumps(doc, indent=2)
