"""Operator-supplied OpenAPI / Swagger / Postman documents as Prowl inputs.

A spec is documentation, not traffic. This module turns one into bounded,
value-free synthetic requests for the existing operation ledger
(``runtime_mapper.ingest_operations``) and REST inventory rows for the asset.
Nothing here sends a request.

Scope is strict: an operation whose resolved origin differs from the allowed
origin is dropped and counted, never rewritten onto the allowed host.
Placeholder values are synthetic (``1``, ``test``) so no example secrets or
customer values from the document reach the agent ledger.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlencode, urljoin, urlsplit

MAX_DOCUMENT_BYTES = 2_000_000
MAX_REQUESTS = 500
MAX_BODY_FIELDS = 40
_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
_PATH_PARAM = re.compile(r"\{([^}/]{1,80})\}")
_POSTMAN_VAR = re.compile(r"\{\{\s*([A-Za-z0-9_.-]{1,80})\s*\}\}")
_ID_LIKE = re.compile(r"(^|_|-)(id|uuid|guid|key|slug)$|Id$|ID$", re.I)
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.\[\]-]{0,79}\Z")


@dataclass
class ParsedSpec:
    kind: str  # "openapi" | "postman"
    document: Dict[str, Any]
    title: str = ""
    version: str = ""


@dataclass
class SpecImport:
    kind: str
    title: str
    origin: str
    requests: List[Dict[str, Any]] = field(default_factory=list)
    rest_rows: List[Dict[str, Any]] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)
    suggested_identities: List[Dict[str, str]] = field(default_factory=list)
    owner_only_candidates: List[Dict[str, Any]] = field(default_factory=list)
    truncated: bool = False

    def summary(self) -> Dict[str, Any]:
        return {
            "format": self.kind,
            "title": self.title,
            "allowed_origin": self.origin,
            "operations": len(self.requests),
            "out_of_scope_dropped": len(self.out_of_scope),
            "out_of_scope_origins": sorted(set(self.out_of_scope))[:10],
            "suggested_identities": self.suggested_identities[:10],
            "owner_only_candidates": self.owner_only_candidates[:40],
            "truncated": self.truncated,
        }


def normalize_origin(value: str) -> str:
    """``scheme://host[:port]`` for http(s) URLs; empty when not a clean origin."""
    parts = urlsplit(str(value or "").strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return ""
    if parts.username or parts.password:
        return ""
    try:
        port = parts.port
    except ValueError:
        return ""
    default = 443 if parts.scheme == "https" else 80
    host = parts.hostname.lower()
    return f"{parts.scheme}://{host}" + (f":{port}" if port and port != default else "")


def parse_api_document(text: str) -> ParsedSpec:
    """Detect and load an OpenAPI 3, Swagger 2 or Postman v2.x document."""
    if not isinstance(text, str) or not text.strip():
        raise ValueError("API document is empty")
    if len(text.encode("utf-8", "ignore")) > MAX_DOCUMENT_BYTES:
        raise ValueError(f"API document exceeds {MAX_DOCUMENT_BYTES} bytes")
    blob = text.strip()
    data: Any = None
    if blob[:1] in "{[":
        try:
            data = json.loads(blob)
        except ValueError:
            data = None
    if data is None:
        try:
            import yaml

            data = yaml.safe_load(blob)
        except Exception as exc:  # yaml.YAMLError and friends
            raise ValueError("API document is not valid JSON or YAML") from exc
    if not isinstance(data, dict):
        raise ValueError("API document must be a JSON/YAML object")
    if data.get("openapi") or data.get("swagger"):
        if not isinstance(data.get("paths"), dict):
            raise ValueError("OpenAPI document has no paths")
        info = data.get("info") if isinstance(data.get("info"), dict) else {}
        return ParsedSpec("openapi", data, str(info.get("title") or "")[:200],
                          str(data.get("openapi") or data.get("swagger") or ""))
    info = data.get("info") if isinstance(data.get("info"), dict) else {}
    schema = str(info.get("schema") or "")
    if isinstance(data.get("item"), list) and ("postman" in schema or "_postman_id" in info):
        return ParsedSpec("postman", data, str(info.get("name") or "")[:200], schema[-20:])
    if isinstance(data.get("collection"), dict):  # Postman API envelope
        return parse_api_document(json.dumps(data["collection"]))
    raise ValueError("Unrecognized API document: expected OpenAPI/Swagger or a Postman v2 collection")


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _placeholder(name: str, schema: Optional[Dict[str, Any]] = None) -> Any:
    kind = str((schema or {}).get("type") or "")
    if kind in ("integer", "number") or _ID_LIKE.search(name or ""):
        return 1
    if kind == "boolean":
        return True
    if kind == "array":
        return ["test"]
    return "test"


def _fill_path(path: str) -> Tuple[str, List[str]]:
    names = _PATH_PARAM.findall(path)
    filled = _PATH_PARAM.sub(lambda m: str(_placeholder(m.group(1))), path)
    return filled, names


def _owner_candidate(method: str, template: str, names: Iterable[str]) -> Optional[Dict[str, Any]]:
    id_names = [n for n in names if _ID_LIKE.search(n)]
    if method != "GET" or not id_names:
        return None
    return {"method": method, "path_template": template, "object_parameters": id_names[:4]}


# ---------------------------------------------------------------------------
# OpenAPI / Swagger
# ---------------------------------------------------------------------------

def _resolve_ref(doc: Dict[str, Any], node: Any, depth: int = 0) -> Any:
    """Follow local ``#/...`` refs only, a few levels deep."""
    while isinstance(node, dict) and isinstance(node.get("$ref"), str) and depth < 6:
        ref = node["$ref"]
        if not ref.startswith("#/"):
            return {}
        cur: Any = doc
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            cur = cur.get(part) if isinstance(cur, dict) else None
            if cur is None:
                return {}
        node, depth = cur, depth + 1
    return node


def _schema_skeleton(doc: Dict[str, Any], schema: Any, depth: int = 0) -> Any:
    schema = _resolve_ref(doc, schema)
    if not isinstance(schema, dict) or depth > 3:
        return "test"
    for combo in ("allOf", "oneOf", "anyOf"):
        if isinstance(schema.get(combo), list) and schema[combo]:
            if combo == "allOf":
                merged: Dict[str, Any] = {}
                for part in schema[combo][:6]:
                    sk = _schema_skeleton(doc, part, depth + 1)
                    if isinstance(sk, dict):
                        merged.update(sk)
                return merged or "test"
            return _schema_skeleton(doc, schema[combo][0], depth + 1)
    props = schema.get("properties")
    if isinstance(props, dict) or schema.get("type") == "object":
        out: Dict[str, Any] = {}
        for name, sub in list((props or {}).items())[:MAX_BODY_FIELDS]:
            if not isinstance(name, str) or not name:
                continue
            sub = _resolve_ref(doc, sub)
            if isinstance(sub, dict) and (sub.get("readOnly") is True):
                continue
            if isinstance(sub, dict) and (sub.get("properties") or sub.get("$ref")
                                          or sub.get("allOf")) and depth < 3:
                out[name] = _schema_skeleton(doc, sub, depth + 1)
            else:
                out[name] = _placeholder(name, sub if isinstance(sub, dict) else None)
        return out
    if schema.get("type") == "array":
        return [_schema_skeleton(doc, schema.get("items"), depth + 1)]
    return _placeholder("", schema)


def _openapi_bases(doc: Dict[str, Any], origin: str) -> List[str]:
    bases: List[str] = []
    if doc.get("swagger"):
        host = str(doc.get("host") or "")
        base_path = str(doc.get("basePath") or "")
        schemes = [s for s in (doc.get("schemes") or []) if s in ("http", "https")]
        if host:
            for scheme in schemes or [urlsplit(origin).scheme or "https"]:
                bases.append(f"{scheme}://{host}{base_path}")
        else:
            bases.append(origin + base_path)
        return bases
    for server in doc.get("servers") or []:
        if not isinstance(server, dict) or not server.get("url"):
            continue
        url = str(server["url"])
        variables = server.get("variables") if isinstance(server.get("variables"), dict) else {}

        def _sub(match: re.Match) -> str:
            var = variables.get(match.group(1)) or {}
            return str(var.get("default") or "") if isinstance(var, dict) else ""

        url = _PATH_PARAM.sub(_sub, url)
        bases.append(urljoin(origin + "/", url) if not url.startswith(("http://", "https://")) else url)
    return bases or [origin]


def _security_identities(doc: Dict[str, Any]) -> List[Dict[str, str]]:
    schemes = (doc.get("components") or {}).get("securitySchemes") \
        if isinstance(doc.get("components"), dict) else None
    if schemes is None:
        schemes = doc.get("securityDefinitions")
    out = []
    for name, raw in (schemes or {}).items() if isinstance(schemes, dict) else []:
        raw = _resolve_ref(doc, raw)
        if not isinstance(raw, dict):
            continue
        kind = str(raw.get("type") or "")
        detail = str(raw.get("scheme") or raw.get("in") or raw.get("flow") or "")
        out.append({"scheme": str(name)[:80], "type": kind[:40], "detail": detail[:40],
                    "suggestion": "Register two named test identities of this kind "
                                  "(owner and other) before authorization checks"})
    return out


def import_openapi(doc: Dict[str, Any], origin: str) -> SpecImport:
    origin = normalize_origin(origin)
    if not origin:
        raise ValueError("A clean http(s) origin is required to import a spec")
    info = doc.get("info") if isinstance(doc.get("info"), dict) else {}
    result = SpecImport("openapi", str(info.get("title") or "")[:200], origin)
    bases = _openapi_bases(doc, origin)
    in_scope = [b for b in bases if normalize_origin(b) == origin]
    result.out_of_scope.extend(normalize_origin(b) or b[:80] for b in bases if b not in in_scope)
    if not in_scope:
        result.suggested_identities = _security_identities(doc)
        return result
    base = in_scope[0].rstrip("/")
    base_path = urlsplit(base).path
    global_security = doc.get("security")

    for raw_path, path_item in (doc.get("paths") or {}).items():
        path_item = _resolve_ref(doc, path_item)
        if not isinstance(path_item, dict) or not isinstance(raw_path, str):
            continue
        shared = [p for p in (path_item.get("parameters") or []) if isinstance(p, (dict,))]
        for method_raw, operation in path_item.items():
            method = str(method_raw).upper()
            if method not in _METHODS or not isinstance(operation, dict):
                continue
            if len(result.requests) >= MAX_REQUESTS:
                result.truncated = True
                break
            template = base_path + "/" + raw_path.lstrip("/")
            path, path_names = _fill_path(template)
            query: Dict[str, Any] = {}
            headers: Dict[str, str] = {}
            form: Dict[str, Any] = {}
            body: Any = None
            for param in shared + list(operation.get("parameters") or []):
                param = _resolve_ref(doc, param)
                if not isinstance(param, dict) or not isinstance(param.get("name"), str):
                    continue
                name, where = param["name"], param.get("in")
                schema = param.get("schema") if isinstance(param.get("schema"), dict) else param
                if where == "query" and _NAME.fullmatch(name):
                    query[name] = _placeholder(name, schema)
                elif where == "path" and name not in path_names:
                    path_names.append(name)
                elif where == "formData" and _NAME.fullmatch(name):
                    form[name] = _placeholder(name, schema)
                elif where == "body":  # Swagger 2
                    body = _schema_skeleton(doc, param.get("schema"))
            content_type = ""
            request_body = _resolve_ref(doc, operation.get("requestBody"))
            content = request_body.get("content") if isinstance(request_body, dict) else None
            if isinstance(content, dict) and content:
                preferred = next((ct for ct in content if "json" in ct), None) \
                    or next((ct for ct in content if "x-www-form-urlencoded" in ct), None) \
                    or next(iter(content))
                media = content.get(preferred) or {}
                skeleton = _schema_skeleton(doc, (media or {}).get("schema"))
                content_type = str(preferred)
                if "x-www-form-urlencoded" in content_type and isinstance(skeleton, dict):
                    form = {k: v for k, v in skeleton.items() if _NAME.fullmatch(k)}
                elif "json" in content_type:
                    body = skeleton
            if form and not content_type:
                content_type = "application/x-www-form-urlencoded"
            elif body is not None and not content_type:
                content_type = "application/json"
            if content_type:
                headers["Content-Type"] = content_type
            if "x-www-form-urlencoded" in content_type:
                body = urlencode(form)
            url = origin + path + ("?" + urlencode(query, doseq=True) if query else "")
            result.requests.append({"url": url, "method": method, "headers": headers,
                                    "body": body if body is not None else ""})
            security = operation.get("security", global_security)
            requires_auth = bool(security) and security != [{}]
            result.rest_rows.append({
                "method": method, "path": template,
                "parameters": sorted(set(query) | set(form) | set(path_names)
                                     | (set(body) if isinstance(body, dict) else set()))[:80],
                "access": "auth_required" if requires_auth else "no_auth",
                "summary": str(operation.get("summary") or operation.get("operationId") or "")[:200],
            })
            candidate = _owner_candidate(method, template, path_names)
            if candidate:
                candidate["requires_auth"] = requires_auth
                result.owner_only_candidates.append(candidate)
    result.suggested_identities = _security_identities(doc)
    return result


# ---------------------------------------------------------------------------
# Postman v2.x
# ---------------------------------------------------------------------------

def _postman_vars(collection: Dict[str, Any], extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for var in collection.get("variable") or []:
        if isinstance(var, dict) and isinstance(var.get("key"), str):
            out[var["key"]] = str(var.get("value") or "")
    out.update(extra or {})
    return out


def _expand(value: str, variables: Dict[str, str], depth: int = 0) -> str:
    if depth > 4:
        return value
    expanded = _POSTMAN_VAR.sub(lambda m: variables.get(m.group(1), "{{%s}}" % m.group(1)), value)
    return _expand(expanded, variables, depth + 1) if expanded != value else expanded


def _walk_items(items: Any, depth: int = 0) -> Iterable[Dict[str, Any]]:
    if depth > 8 or not isinstance(items, list):
        return
    for item in items:
        if not isinstance(item, dict):
            continue
        if isinstance(item.get("item"), list):
            yield from _walk_items(item["item"], depth + 1)
        elif isinstance(item.get("request"), (dict, str)):
            yield item


def _postman_url(raw: Any, variables: Dict[str, str]) -> Tuple[str, Dict[str, Any]]:
    """Return (url_without_query, query) after variable expansion."""
    query: Dict[str, Any] = {}
    if isinstance(raw, str):
        text = _expand(raw, variables)
    elif isinstance(raw, dict):
        text = _expand(str(raw.get("raw") or ""), variables)
        if not text:
            host = raw.get("host")
            host = ".".join(host) if isinstance(host, list) else str(host or "")
            path = raw.get("path")
            path = "/".join(str(p) for p in path) if isinstance(path, list) else str(path or "")
            text = _expand(f"{raw.get('protocol') or 'https'}://{host}/{path}", variables)
        for q in raw.get("query") or []:
            if isinstance(q, dict) and isinstance(q.get("key"), str) and not q.get("disabled"):
                query[q["key"]] = "test"
    else:
        return "", {}
    if "?" in text:
        text, _, qs = text.partition("?")
        for pair in qs.split("&"):
            key = pair.split("=", 1)[0]
            if key:
                query.setdefault(_expand(key, variables), "test")
    return text, query


def _postman_path_names(url: str) -> Tuple[str, List[str]]:
    """``:id`` segments and unresolved ``{{var}}`` become placeholders."""
    parts = urlsplit(url)
    names: List[str] = []
    segments = []
    for seg in parts.path.split("/"):
        if seg.startswith(":") and len(seg) > 1:
            names.append(seg[1:])
            segments.append("{%s}" % seg[1:])
        else:
            m = _POSTMAN_VAR.fullmatch(seg)
            if m:
                names.append(m.group(1))
                segments.append("{%s}" % m.group(1))
            else:
                segments.append(seg)
    return "/".join(segments) or "/", names


def _postman_auth(collection: Dict[str, Any]) -> List[Dict[str, str]]:
    seen: Dict[str, Dict[str, str]] = {}

    def note(auth: Any) -> None:
        if isinstance(auth, dict) and auth.get("type") and auth["type"] != "noauth":
            kind = str(auth["type"])[:40]
            seen.setdefault(kind, {"scheme": kind, "type": kind, "detail": "",
                                   "suggestion": "Register two named test identities of this kind "
                                                 "(owner and other) before authorization checks"})

    note(collection.get("auth"))
    for item in _walk_items(collection.get("item")):
        request = item.get("request")
        if isinstance(request, dict):
            note(request.get("auth"))
    return list(seen.values())


def import_postman(collection: Dict[str, Any], origin: str,
                   variables: Optional[Dict[str, str]] = None) -> SpecImport:
    origin = normalize_origin(origin)
    if not origin:
        raise ValueError("A clean http(s) origin is required to import a collection")
    info = collection.get("info") if isinstance(collection.get("info"), dict) else {}
    result = SpecImport("postman", str(info.get("name") or "")[:200], origin)
    env = _postman_vars(collection, variables)
    # A bare {{baseUrl}} with no value is assumed to be the allowed origin.
    for key in ("baseUrl", "base_url", "host", "url"):
        env.setdefault(key, origin)
    seen = set()
    for item in _walk_items(collection.get("item")):
        if len(result.requests) >= MAX_REQUESTS:
            result.truncated = True
            break
        request = item["request"]
        if isinstance(request, str):
            request = {"url": request, "method": "GET"}
        method = str(request.get("method") or "GET").upper()
        if method not in _METHODS:
            continue
        url, query = _postman_url(request.get("url"), env)
        if not url:
            continue
        if not url.startswith(("http://", "https://")):
            url = urljoin(origin + "/", url.lstrip("/"))
        if normalize_origin(url) != origin:
            result.out_of_scope.append(normalize_origin(url) or url[:80])
            continue
        template, path_names = _postman_path_names(url)
        path, _ = _fill_path(template)
        headers: Dict[str, str] = {}
        body: Any = ""
        raw_body = request.get("body") if isinstance(request.get("body"), dict) else {}
        mode = raw_body.get("mode")
        body_names: List[str] = []
        if mode == "raw":
            text = _expand(str(raw_body.get("raw") or ""), env)
            lang = ((raw_body.get("options") or {}).get("raw") or {}).get("language") \
                if isinstance(raw_body.get("options"), dict) else ""
            try:
                parsed = json.loads(_POSTMAN_VAR.sub("1", text)) if text.strip() else None
            except ValueError:
                parsed = None
            if isinstance(parsed, dict):
                body = {k: _placeholder(k, {"type": "integer" if isinstance(v, int)
                                            and not isinstance(v, bool) else ""})
                        if not isinstance(v, (dict, list)) else v
                        for k, v in list(parsed.items())[:MAX_BODY_FIELDS] if isinstance(k, str)}
                body_names = list(body)
                headers["Content-Type"] = "application/json"
            elif lang == "json":
                headers["Content-Type"] = "application/json"
        elif mode in ("urlencoded", "formdata"):
            form = {}
            for entry in raw_body.get(mode) or []:
                if (isinstance(entry, dict) and isinstance(entry.get("key"), str)
                        and not entry.get("disabled") and entry.get("type") != "file"
                        and _NAME.fullmatch(entry["key"])):
                    form[entry["key"]] = _placeholder(entry["key"])
            if form:
                body = urlencode(form)
                body_names = list(form)
                headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif mode == "graphql":
            gql = raw_body.get("graphql") if isinstance(raw_body.get("graphql"), dict) else {}
            query_doc = str(gql.get("query") or "")[:8000]
            try:
                variables_doc = json.loads(str(gql.get("variables") or "{}"))
            except ValueError:
                variables_doc = {}
            body = {"query": query_doc,
                    "variables": {k: "test" for k in (variables_doc or {})}
                    if isinstance(variables_doc, dict) else {}}
            headers["Content-Type"] = "application/json"
        key = (method, template, tuple(sorted(query)), tuple(sorted(body_names)))
        if key in seen:
            continue
        seen.add(key)
        full = origin + path + ("?" + urlencode(query) if query else "")
        result.requests.append({"url": full, "method": method, "headers": headers, "body": body})
        auth = request.get("auth") if isinstance(request.get("auth"), dict) else collection.get("auth")
        requires_auth = isinstance(auth, dict) and auth.get("type") not in (None, "noauth")
        result.rest_rows.append({
            "method": method, "path": template,
            "parameters": sorted(set(query) | set(body_names) | set(path_names))[:80],
            "access": "auth_required" if requires_auth else "unknown",
            "summary": str(item.get("name") or "")[:200],
        })
        candidate = _owner_candidate(method, template, path_names)
        if candidate:
            candidate["requires_auth"] = requires_auth
            result.owner_only_candidates.append(candidate)
    result.suggested_identities = _postman_auth(collection)
    return result


def import_api_document(text_or_parsed: Any, origin: str,
                        variables: Optional[Dict[str, str]] = None) -> SpecImport:
    parsed = text_or_parsed if isinstance(text_or_parsed, ParsedSpec) \
        else parse_api_document(text_or_parsed)
    if parsed.kind == "openapi":
        return import_openapi(parsed.document, origin)
    return import_postman(parsed.document, origin, variables)


# ---------------------------------------------------------------------------
# Asset persistence and lookup
# ---------------------------------------------------------------------------

def default_origin_for_asset(asset: Any) -> str:
    value = str(getattr(asset, "value", "") or "").strip()
    if value.startswith(("http://", "https://")):
        return normalize_origin(value)
    if value and "/" not in value and " " not in value:
        return normalize_origin(f"https://{value}")
    return ""


def persist_import_to_asset(asset: Any, parsed: ParsedSpec, imported: SpecImport, *,
                            name: str = "") -> int:
    """Store the document and its REST rows on the asset. Caller commits."""
    from datetime import datetime

    from app.services.rest_inventory_service import (
        _MAX_SPEC_BYTES, merge_api_spec, merge_rest_endpoints,
    )

    label = (name or parsed.title or parsed.kind)[:120]
    meta: Dict[str, Any] = {
        "url": f"upload://{parsed.kind}/{label}",
        "title": parsed.title,
        "version": parsed.version,
        "endpoint_count": len(imported.rest_rows),
        "discovered_by": "operator_upload",
        "last_captured": datetime.utcnow().isoformat(),
        "format": parsed.kind,
        "allowed_origin": imported.origin,
    }
    if len(json.dumps(parsed.document, default=str)) <= _MAX_SPEC_BYTES:
        meta["spec"] = parsed.document
    merge_api_spec(asset, meta)
    return merge_rest_endpoints(asset, imported.rest_rows, source=f"{parsed.kind}_upload")


def stored_documents(asset: Any) -> List[ParsedSpec]:
    """Stored spec bodies on an asset (uploaded or crawled), newest first."""
    out: List[ParsedSpec] = []
    for meta in getattr(asset, "api_specs", None) or []:
        if not isinstance(meta, dict) or not isinstance(meta.get("spec"), dict):
            continue
        try:
            out.append(parse_api_document(json.dumps(meta["spec"])))
        except ValueError:
            continue
    return out
