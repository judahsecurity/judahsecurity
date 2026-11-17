"""Value-free parameter inventory for specialist assignment and coverage.

Only names, locations, paths, and evidence references enter the agent map.
Request values, cookies, headers, and bodies are never copied into this ledger.
"""

from __future__ import annotations

import json
import re
from urllib.parse import parse_qsl, urljoin, urlsplit

from app.services.agent.static_assets import is_static_asset

MAX_PARAMETERS = 4000
_NAME = re.compile(r"[A-Za-z_/][A-Za-z0-9_./*\[\]-]{0,79}\Z")
_JSON_POINTER = re.compile(r"/[A-Za-z0-9_.\[\]/~*-]{1,119}\Z")
_POSITIVE_INTEGER = re.compile(r"[1-9][0-9]{0,8}\Z")
_PROTECTED = re.compile(r"csrf|xsrf|nonce|session|token|secret|api[_-]?key|authorization|jwt|bearer", re.I)
_XSS_HINT = re.compile(r"q|query|search|term|name|title|message|comment|content|text|html|redirect|url", re.I)
_SQL_HINT = re.compile(r"id|key|category|filter|sort|page|limit|offset|search|query|email|user|order", re.I)
_LOCATIONS = {"query", "form", "body_json", "body_form", "body_xml", "cookie", "header", "path"}
# RFC 6265 cookie-name token and RFC 7230 header-name token (names only, never values).
_COOKIE_NAME = re.compile(r"[A-Za-z0-9!#$%&'*+.^_`|~-]{1,80}\Z")
_HEADER_NAME = re.compile(r"[A-Za-z0-9-]{1,64}\Z")
_PATH_NAME = re.compile(r"path\[[1-9][0-9]?\]\Z")
# Cookies that carry sessions, credentials, or anti-forgery state. They stay in
# the inventory so the surface is visible, but never become injection work.
_CREDENTIAL_COOKIE = re.compile(
    r"sess|sid\Z|\Asid|token|auth|jwt|csrf|xsrf|forgery|verification|login|remember|"
    r"secret|identity|credential|bearer|saml|oidc|oauth|\A__(?:host|secure)-",
    re.I,
)
# Client-side analytics/consent/CDN cookies the application server does not read.
_CLIENT_ONLY_COOKIE = re.compile(
    r"\A(?:_ga|_gid|_gat|__utm|_fbp|_fbc|_gcl|_hj|_clck|_clsk|_uet|__cf|cf_|"
    r"optanon|cookieconsent|cookielawinfo|ai_user|ai_session|_pk_|mp_|amplitude|intercom-)",
    re.I,
)
# Request headers that applications commonly log, geolocate, or look up in SQL.
HEADER_CANDIDATES = ("User-Agent", "Referer", "X-Forwarded-For", "Accept-Language")
_CREDENTIAL_HEADER = re.compile(
    r"\A(?:cookie|authorization|proxy-authorization|host|content-length|content-type|"
    r"transfer-encoding|connection|x-forwarded-host|forwarded)\Z|token|auth|csrf|xsrf|"
    r"secret|api[_-]?key|signature|session",
    re.I,
)
# Path segments that look like database identifiers.
_ID_SEGMENT = re.compile(
    r"[0-9]{1,12}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.I,
)
_SOURCE_RANK = {
    "javascript_static": 0, "service": 0,
    "page_url": 1, "browser_link": 1, "api_endpoint": 1,
    "observed_form": 2, "form_action": 2,
    "browser_request": 3, "application_operation": 3,
    "captured_api": 4, "browser_traffic": 5,
    "header_candidate": 0, "path_segment": 1, "set_cookie": 2,
    "captured_cookie": 3, "browser_cookie": 3,
}


def is_credential_cookie(name: str) -> bool:
    """Whether a cookie name looks like session, credential, or CSRF state."""
    return bool(_CREDENTIAL_COOKIE.search(str(name or "")))


def cookie_names(*values: object) -> list[str]:
    """Names from Cookie / Set-Cookie header values; values are discarded."""
    names: list[str] = []
    for value in values:
        items = value if isinstance(value, list) else [value]
        for item in items:
            if not isinstance(item, str) or not item:
                continue
            # A Cookie header is "a=1; b=2". A Set-Cookie header is "a=1; Path=/";
            # several may be folded with newlines or commas before the next name.
            for line in re.split(r"[\r\n]+|,(?=\s*[A-Za-z0-9!#$%&'*+.^_`|~-]+=)", item):
                attrs = {"path", "domain", "expires", "max-age", "secure",
                         "httponly", "samesite", "priority", "partitioned"}
                for pair in line.split(";"):
                    name, sep, _ = pair.strip().partition("=")
                    name = name.strip()
                    if (sep and _COOKIE_NAME.fullmatch(name)
                            and name.lower() not in attrs and name not in names):
                        names.append(name)
    return names[:40]


def _testable(location: str, name: str) -> bool:
    if location == "cookie":
        return not (is_credential_cookie(name) or _CLIENT_ONLY_COOKIE.search(name))
    if location == "header":
        return not _CREDENTIAL_HEADER.search(name)
    if location == "path":
        return True
    return not bool(_PROTECTED.search(name))


def _origin(value: str) -> str:
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
        return ""
    try:
        port = parts.port
    except ValueError:
        return ""
    default = 443 if parts.scheme == "https" else 80
    return f"{parts.scheme}://{parts.hostname.lower()}" + (f":{port}" if port and port != default else "")


def _base(cmap: dict) -> str:
    for candidate in (cmap.get("scope"), cmap.get("target")):
        if isinstance(candidate, str) and _origin(candidate):
            return _origin(candidate)
    return ""


def _resolved(raw: str, base: str) -> tuple[str, str]:
    if not isinstance(raw, str) or not raw or not base:
        return "", ""
    full = urljoin(base + "/", raw)
    parts = urlsplit(full)
    if _origin(full) != base:
        return "", ""
    return parts.path or "/", parts.query


def collect_parameter_inventory(cmap: dict) -> list[dict]:
    """Merge observed forms, URLs, API samples, and service metadata."""
    base = _base(cmap)
    if not base:
        return []
    rows: dict[tuple[str, str, str, str, str], dict] = {}
    request_scoped: dict[tuple[str, str, str], str] = {}
    path_templates: set[tuple[str, str, str, str]] = set()

    def add(*, method: str, url: str, name: str, location: str,
            source: str, value_type: str = "", identity: str = "",
            artifact_id: str = "") -> None:
        if not isinstance(name, str) or location not in _LOCATIONS:
            return
        matcher = {
            "cookie": _COOKIE_NAME, "header": _HEADER_NAME, "path": _PATH_NAME,
        }.get(location) or (_JSON_POINTER if location == "body_json" and name.startswith("/") else _NAME)
        if not matcher.fullmatch(name):
            return
        path, _ = _resolved(url, base)
        if is_static_asset(path):
            return
        if not path:
            return
        if location in {"cookie", "header"}:
            # Cookies and generic headers ride on every request to the host.
            # Test each name once, on the first page where it was observed.
            scope_key = (location, name.lower(), str(identity or "anonymous")[:80])
            path = request_scoped.setdefault(scope_key, path)
        method = str(method or "GET").upper()
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            return
        key = (method, path, location, name, str(identity or "anonymous")[:80])
        row = {
            "method": method, "host": urlsplit(base).netloc, "path": path,
            "name": name, "location": location, "source": str(source)[:40],
            "value_type": str(value_type or "")[:40],
            "identity": key[4], "artifact_id": str(artifact_id or "")[:80],
            "testable": _testable(location, name),
        }
        prior = rows.get(key)
        if prior is None:
            if len(rows) < MAX_PARAMETERS:
                rows[key] = row
        else:
            if value_type and not prior.get("value_type"):
                prior["value_type"] = row["value_type"]
            if (artifact_id and source == "browser_traffic"
                    and (prior.get("source") != "browser_traffic"
                         or prior.get("artifact_id") != artifact_id)):
                row["value_type"] = row["value_type"] or prior.get("value_type", "")
                rows[key] = row
            elif ((artifact_id and not prior.get("artifact_id"))
                  or (not prior.get("artifact_id") and
                      _SOURCE_RANK.get(source, 0) > _SOURCE_RANK.get(prior["source"], 0))):
                row["value_type"] = row["value_type"] or prior.get("value_type", "")
                rows[key] = row

    def path_segments(url: str, method: str, identity: str = "") -> None:
        """Identifier-like path segments (/item/42) are injection points too."""
        path, _ = _resolved(url, base)
        if not path or is_static_asset(path):
            return
        segments = path.split("/")
        template = "/".join("*" if _ID_SEGMENT.fullmatch(seg) else seg for seg in segments)
        for index, segment in enumerate(segments[:12]):
            if not segment or not _ID_SEGMENT.fullmatch(segment):
                continue
            # /item/42 and /item/43 are one input; keep the first concrete URL.
            key = (str(method or "GET").upper(), template, str(index), str(identity or "anonymous"))
            if key in path_templates:
                continue
            path_templates.add(key)
            add(method=method, url=url, name=f"path[{index}]", location="path",
                source="path_segment", identity=identity,
                value_type="positive_integer" if _POSITIVE_INTEGER.fullmatch(segment) else "identifier")

    def query(url: str, method: str, source: str, identity: str = "",
              artifact_id: str = "") -> None:
        path_segments(url, method, identity)
        path, raw_query = _resolved(url, base)
        if not path:
            return
        try:
            pairs = parse_qsl(raw_query, keep_blank_values=True, max_num_fields=100)
        except ValueError:
            return
        for name, value in pairs[:40]:
            add(method=method, url=url, name=name, location="query",
                source=source, identity=identity, artifact_id=artifact_id,
                value_type="positive_integer" if _POSITIVE_INTEGER.fullmatch(value) else "")

    for page in (cmap.get("pages_visited") or [])[:120]:
        if isinstance(page, str):
            query(page, "GET", "page_url")

    for link in (cmap.get("discovered_links") or [])[:500]:
        if not isinstance(link, dict):
            continue
        url = str(link.get("url") or "")
        link_identity = str(link.get("identity") or "")
        query(url, "GET", "browser_link", identity=link_identity)
        for name in (link.get("query_keys") or [])[:20]:
            add(method="GET", url=url, name=name, location="query",
                source="browser_link", identity=link_identity)

    for form in (cmap.get("forms") or [])[:80]:
        if not isinstance(form, dict):
            continue
        method = str(form.get("method") or "GET").upper()
        action = str(form.get("action") or form.get("page") or cmap.get("target") or "")
        if not action:
            continue
        form_identity = str(form.get("identity") or "")
        query(action, method, "form_action", identity=form_identity)
        for field in (form.get("fields") or form.get("inputs") or [])[:60]:
            name = field.get("name") if isinstance(field, dict) else field
            value_type = field.get("control_type", "") if isinstance(field, dict) else ""
            add(method=method, url=action, name=name,
                # Use the same location as a later browser traffic capture so
                # the observed form and its replayable request are one input.
                location="query" if method == "GET" else "body_form",
                source="observed_form", value_type=value_type,
                identity=form_identity)

    for endpoint in (cmap.get("api_endpoints") or [])[:300]:
        if not isinstance(endpoint, dict):
            continue
        path = str(endpoint.get("path") or "")
        host = str(endpoint.get("host") or urlsplit(base).netloc)
        url = path if path.startswith(("http://", "https://")) else f"{urlsplit(base).scheme}://{host}/{path.lstrip('/')}"
        query(url, str(endpoint.get("method") or "GET"), "api_endpoint")
        for name in (endpoint.get("query_keys") or [])[:40]:
            add(method=str(endpoint.get("method") or "GET"), url=url,
                name=name, location="query", source="api_endpoint")

    for sample in (cmap.get("api_samples") or [])[:80]:
        if not isinstance(sample, dict):
            continue
        method = str(sample.get("method") or "GET")
        url = str(sample.get("url") or "")
        sample_identity = str(sample.get("identity") or "")
        query(url, method, "captured_api", identity=sample_identity,
              artifact_id=sample.get("artifact_id", ""))
        body = sample.get("body")
        headers = sample.get("headers") if isinstance(sample.get("headers"), dict) else {}
        response_headers = next((sample.get(key) for key in ("response_headers", "resp_headers")
                                 if isinstance(sample.get(key), dict)), {})
        request_cookie = [v for k, v in headers.items() if str(k).lower() == "cookie"]
        set_cookie = [v for k, v in response_headers.items() if str(k).lower() == "set-cookie"]
        for name in cookie_names(request_cookie, set_cookie, sample.get("set_cookie") or ""):
            add(method=method, url=url, name=name, location="cookie",
                source="captured_cookie" if name in cookie_names(request_cookie) else "set_cookie",
                identity=sample_identity)
        for header in list(headers)[:40]:
            header = str(header)
            # Application-specific request headers (X-Tenant-Id, X-Branch, ...)
            # are server-read inputs; standard and credential headers are not.
            if header.lower().startswith("x-") and header.lower() not in {
                "x-requested-with", "x-forwarded-proto", "x-forwarded-port",
            }:
                add(method=method, url=url, name=header, location="header",
                    source="captured_api", identity=sample_identity,
                    artifact_id=sample.get("artifact_id", ""))
        request_type = str(sample.get("request_content_type") or next(
            (value for key, value in headers.items() if str(key).lower() == "content-type"), ""
        )).lower()
        if method.upper() in {"POST", "PUT", "PATCH"} and any(
            mime in request_type for mime in ("application/xml", "text/xml", "+xml")
        ):
            add(method=method, url=url, name="document", location="body_xml",
                source="captured_api", identity=sample_identity,
                artifact_id=sample.get("artifact_id", ""))
        if isinstance(body, str) and len(body) <= 16_000:
            try:
                body = json.loads(body)
            except ValueError:
                if "application/x-www-form-urlencoded" in request_type:
                    try:
                        for name, _ in parse_qsl(body, keep_blank_values=True, max_num_fields=100)[:40]:
                            add(method=method, url=url, name=name, location="body_form",
                                source="captured_api", identity=sample_identity,
                                artifact_id=sample.get("artifact_id", ""))
                    except ValueError:
                        pass
                body = None
        if isinstance(body, (dict, list)):
            emitted = 0

            def walk_json(value: object, pointer: str = "", depth: int = 0) -> None:
                """Use the JSON pointer accepted by captured POST replay."""
                nonlocal emitted
                if depth > 5 or emitted >= 40:
                    return
                if isinstance(value, dict):
                    for key, child in list(value.items())[:40]:
                        if isinstance(key, str) and key:
                            escaped = key.replace("~", "~0").replace("/", "~1")
                            walk_json(child, f"{pointer}/{escaped}", depth + 1)
                elif isinstance(value, list):
                    # Exact observed indexes can be replayed even when an
                    # array has more than one element; a wildcard cannot.
                    for index, child in enumerate(value[:3]):
                        walk_json(child, f"{pointer}/{index}", depth + 1)
                elif pointer:
                    add(method=method, url=url, name=pointer, location="body_json",
                        source="captured_api", identity=sample_identity,
                        value_type=("positive_integer" if isinstance(value, int)
                                    and not isinstance(value, bool) and 0 < value <= 999_999_999
                                    else ""), artifact_id=sample.get("artifact_id", ""))
                    emitted += 1

            walk_json(body)

    for cookie in (cmap.get("cookie_inputs") or [])[:60]:
        if isinstance(cookie, dict):
            add(method="GET", url=base + str(cookie.get("path") or "/"),
                name=cookie.get("name"), location="cookie",
                source=str(cookie.get("source") or "browser_cookie"),
                identity=cookie.get("identity", ""))

    for raw in (cmap.get("parameter_inventory") or [])[:MAX_PARAMETERS]:
        if not isinstance(raw, dict):
            continue
        url = str(raw.get("url") or "") or base + str(raw.get("path") or "")
        add(method=raw.get("method", "GET"), url=url, name=raw.get("name"),
            location=raw.get("location", "query"), source=raw.get("source", "service"),
            value_type=raw.get("value_type", ""), identity=raw.get("identity", ""),
            artifact_id=raw.get("artifact_id", ""))

    if cmap.get("pages_visited"):
        # A reachable application reads standard request headers on its entry
        # page (logging, analytics, geo/language lookup). Offer each once.
        entry, _ = _resolved(str(cmap.get("target") or base), base)
        for header in HEADER_CANDIDATES:
            add(method="GET", url=base + (entry or "/"), name=header,
                location="header", source="header_candidate")

    return sorted(rows.values(), key=lambda row: (
        row["host"], row["path"], row["method"], row["location"], row["name"], row["identity"],
    ))


def inventory_with_operations(cmap: dict, operations: list[dict]) -> dict:
    """Add value-free central-ledger input names to the scoped worklist."""
    base = _base(cmap)
    if not base:
        return cmap
    discovered = []
    for operation in operations[:1000]:
        if not isinstance(operation, dict):
            continue
        url = str(operation.get("url") or "")
        if _origin(url) != base:
            continue
        method = str(operation.get("method") or "GET").upper()
        content_type = str(operation.get("request_content_type")
                           or operation.get("content_type") or "").lower()
        identities = operation.get("identities") or ["anonymous"]
        for parameter in (operation.get("parameters") or [])[:100]:
            if not isinstance(parameter, str):
                continue
            kind, separator, name = parameter.partition(":")
            if not separator or not _NAME.fullmatch(name):
                continue
            if kind == "query":
                location = "query"
            elif kind == "body" and "json" in content_type:
                location = "body_json"
            elif kind == "body" and "application/x-www-form-urlencoded" in content_type:
                location = "body_form"
            elif kind == "variable" and "json" in content_type:
                location, name = "body_json", f"variables.{name}"
            else:
                continue
            for identity in identities[:10]:
                discovered.append({
                    "url": url, "method": method, "name": name,
                    "location": location, "identity": identity,
                    "source": "application_operation",
                })
    if not discovered:
        return cmap
    merged = dict(cmap)
    merged["parameter_inventory"] = collect_parameter_inventory({
        **cmap, "parameter_inventory": [
            *(cmap.get("parameter_inventory") or []), *discovered,
        ][:MAX_PARAMETERS],
    })
    return merged


def parameters_for_specialist(cmap: dict, specialist: str) -> list[dict]:
    rows = [row for row in collect_parameter_inventory(cmap) if row["testable"]]
    if specialist not in {"xss", "sqli", "injection", "server_injection"}:
        return rows

    def rank(row: dict) -> tuple:
        return (parameter_priority(row, specialist), row["path"], row["name"])

    return sorted(rows, key=rank)


def parameter_priority(row: dict, specialist: str) -> int:
    """Order likely sinks first without removing lower-signal observed inputs."""
    name = str(row.get("name") or "")
    value_type = str(row.get("value_type") or "")
    location = str(row.get("location") or "")
    if specialist == "sqli" and re.search(r"category|filter|search|query", name, re.I):
        return 0
    if specialist == "sqli" and location == "cookie":
        # Non-session cookies (language, country, branch, currency, cart) are
        # server-read state that developers rarely parameterize.
        return 1
    if specialist == "sqli" and location == "path":
        return 1
    if location == "header":
        return 3
    if specialist == "xss":
        favored = bool(_XSS_HINT.search(name)) or value_type in {"search", "text", "textarea"}
    elif specialist == "sqli":
        favored = bool(_SQL_HINT.search(name)) or value_type in {"positive_integer", "number"}
    else:
        favored = bool(_XSS_HINT.search(name) or _SQL_HINT.search(name))
    observed = row.get("source") in {"observed_form", "captured_api", "browser_traffic"}
    return 1 if favored and observed else 2 if favored else 3
