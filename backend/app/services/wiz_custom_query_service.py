"""Run user-defined, read-only Wiz GraphQL queries and store what they return.

Wiz can export any table in its UI as a Python script. :func:`parse_python_script`
pulls the ``QUERY`` and ``VARIABLES`` out of such a script without executing it,
and :func:`sync_custom_query` pages through the query with the connection's
credentials and upserts every returned node as a :class:`WizCustomQueryRecord`.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import ipaddress
import json
import logging
import re
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetStatus, AssetType
from app.models.wiz_custom_query import WizCustomQuery, WizCustomQueryRecord
from app.models.wiz_integration import WizIntegration
from app.services.wiz_service import WizApiError, WizClient, _client_for

logger = logging.getLogger(__name__)

DISCOVERY_SOURCE = "wiz"
MAX_QUERY_LENGTH = 100_000
PREVIEW_ROWS = 5

APPLICATION_ENDPOINTS_QUERY = """
query ApplicationEndpointsTable($first: Int, $after: String, $filterBy: ApplicationEndpointFilters, $orderBy: ApplicationEndpointOrder) {
  applicationEndpoints(first: $first, after: $after, filterBy: $filterBy, orderBy: $orderBy) {
    nodes {
      id
      name
      host
      port
      protocols
      cloudPlatform
      cloudAccount { cloudProvider id externalId }
      firstSeen
      updatedAt
      portStatus
      httpResults {
        statusCode
        statusText
        pageTitle
        authenticationMethod
        authenticationServiceProvider
        contentType
        screenshotUrl
      }
      exposureLevel
      scanSources
      issueAnalytics {
        informationalSeverityCount
        lowSeverityCount
        mediumSeverityCount
        highSeverityCount
        criticalSeverityCount
        issueCount
      }
      hostedTechnologies { id technology { id name } }
      resources { providerUniqueId id name type }
      domain { id name }
      owningApplicationServices { id displayName }
    }
    pageInfo { endCursor hasNextPage }
  }
}
""".strip()

TEMPLATES: List[Dict[str, Any]] = [
    {
        "key": "application_endpoints",
        "name": "Application endpoints",
        "description": (
            "Externally reachable hosts and ports Wiz discovered, with HTTP results, exposure "
            "level, hosted technologies and related issue counts. Imported as assets."
        ),
        "query": APPLICATION_ENDPOINTS_QUERY,
        "variables": {"filterBy": {}, "orderBy": {"field": "RELATED_ISSUE_SEVERITY", "direction": "DESC"}},
        "connection_path": "applicationEndpoints",
        "asset_host_field": "host",
    },
]


class WizQueryError(ValueError):
    """A user-correctable problem with a custom query definition."""


# ── Parsing and validation ──────────────────────────────────────────────────


def parse_python_script(script: str) -> Dict[str, Any]:
    """Extract QUERY and VARIABLES from a Wiz "Copy as Python" script.

    The script is parsed, never executed: only literal assignments are read.
    """
    try:
        tree = ast.parse(script or "")
    except SyntaxError as exc:
        raise WizQueryError(f"Could not parse the script as Python (line {exc.lineno}).") from exc
    found: Dict[str, Any] = {}
    for node in tree.body:
        targets: List[ast.expr] = []
        value: Optional[ast.expr] = None
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        for target in targets:
            if isinstance(target, ast.Name) and target.id in ("QUERY", "VARIABLES"):
                try:
                    found[target.id] = ast.literal_eval(value)
                except (ValueError, TypeError, SyntaxError) as exc:
                    raise WizQueryError(f"{target.id} must be a literal value in the script.") from exc
    query = found.get("QUERY")
    if not isinstance(query, str) or not query.strip():
        raise WizQueryError("No QUERY string was found in the script.")
    variables = found.get("VARIABLES") or {}
    if not isinstance(variables, dict):
        raise WizQueryError("VARIABLES must be a dictionary.")
    return {"query": query.strip(), "variables": variables}


def _top_level_words(query: str) -> List[str]:
    """Words outside any braces/parens, ignoring comments and string literals."""
    text = re.sub(r'"""[\s\S]*?"""', " ", query)
    text = re.sub(r'"(?:\\.|[^"\\])*"', " ", text)
    text = re.sub(r"#[^\n]*", " ", text)
    words: List[str] = []
    depth = 0
    for match in re.finditer(r"[{}()]|[_A-Za-z][_0-9A-Za-z]*", text):
        token = match.group(0)
        if token in "{(":
            depth += 1
        elif token in "})":
            depth = max(0, depth - 1)
        elif depth == 0:
            words.append(token)
    return words


def validate_query(query: str) -> str:
    """Accept only read operations; the Wiz integration must never write to Wiz."""
    query = (query or "").strip()
    if not query:
        raise WizQueryError("The GraphQL query is empty.")
    if len(query) > MAX_QUERY_LENGTH:
        raise WizQueryError("The GraphQL query is too long.")
    words = _top_level_words(query)
    if "mutation" in words or "subscription" in words:
        raise WizQueryError(
            "Only read queries are allowed. This is a GraphQL mutation, which changes data in Wiz "
            "instead of returning findings (for example, UpdateUserPreferences only hides UI help "
            "banners). Capture the request that loads the table rows instead."
        )
    if "{" not in query:
        raise WizQueryError("The GraphQL query has no selection set.")
    return query


def _declares(query: str, name: str) -> bool:
    return re.search(rf"\${name}\s*:", query) is not None


def page_variables(
    query: str, variables: Optional[Dict[str, Any]], page_size: int, cursor: Optional[str]
) -> Dict[str, Any]:
    """Variables for one page. A cursor copied from the browser is always replaced."""
    result = copy.deepcopy(variables or {})
    if _declares(query, "first"):
        result["first"] = page_size
    if _declares(query, "after"):
        result["after"] = cursor
    elif cursor is not None:
        raise WizQueryError("The query paginates but does not declare an $after variable.")
    return result


def _dig(value: Any, path: str) -> Any:
    for key in [part for part in (path or "").split(".") if part]:
        if isinstance(value, dict):
            value = value.get(key)
        elif isinstance(value, list) and key.isdigit() and int(key) < len(value):
            value = value[int(key)]
        else:
            return None
    return value


def find_connection(data: Dict[str, Any], path: Optional[str] = None) -> Tuple[str, Dict[str, Any]]:
    """Locate the paginated connection ({nodes|edges, pageInfo}) in a response."""
    if path:
        connection = _dig(data, path)
        if not isinstance(connection, dict):
            raise WizQueryError(f"The response has no object at '{path}'.")
        return path, connection
    queue: List[Tuple[str, Any]] = [("", data)]
    while queue:
        prefix, value = queue.pop(0)
        if isinstance(value, dict):
            if isinstance(value.get("nodes"), list) or isinstance(value.get("edges"), list):
                if prefix:
                    return prefix, value
            for key, child in value.items():
                if isinstance(child, dict):
                    queue.append((f"{prefix}.{key}" if prefix else key, child))
    raise WizQueryError(
        "Could not find a list of results (an object with 'nodes' and 'pageInfo') in the response."
    )


def _connection_nodes(connection: Dict[str, Any]) -> List[Dict[str, Any]]:
    if isinstance(connection.get("nodes"), list):
        items = connection["nodes"]
    else:
        items = [edge.get("node") for edge in connection.get("edges") or [] if isinstance(edge, dict)]
    return [item for item in items if isinstance(item, dict)]


async def run_query(
    client: WizClient,
    query: str,
    variables: Optional[Dict[str, Any]],
    *,
    connection_path: Optional[str] = None,
    page_size: int = 100,
    max_pages: int = 50,
    limit: Optional[int] = None,
) -> Dict[str, Any]:
    """Page through a read query. Returns nodes, the resolved path and page count."""
    query = validate_query(query)
    nodes: List[Dict[str, Any]] = []
    cursor: Optional[str] = None
    path = connection_path or None
    pages = 0
    truncated = False
    size = max(1, min(page_size, limit or page_size))
    for _ in range(max(1, max_pages)):
        data = await client.graphql(query, page_variables(query, variables, size, cursor))
        path, connection = find_connection(data, path)
        nodes.extend(_connection_nodes(connection))
        pages += 1
        if limit and len(nodes) >= limit:
            return {"nodes": nodes[:limit], "connection_path": path, "pages": pages, "truncated": False}
        page_info = connection.get("pageInfo") or {}
        if not page_info.get("hasNextPage"):
            break
        cursor = page_info.get("endCursor")
        if not cursor or not _declares(query, "after"):
            break
    else:
        truncated = True
    return {"nodes": nodes, "connection_path": path, "pages": pages, "truncated": truncated}


def _field_paths(rows: Iterable[Dict[str, Any]], prefix: str = "", depth: int = 0) -> List[str]:
    paths: List[str] = []
    for row in rows:
        for key, value in row.items():
            path = f"{prefix}{key}"
            if path not in paths:
                paths.append(path)
            if isinstance(value, dict) and depth < 2:
                for child in _field_paths([value], f"{path}.", depth + 1):
                    if child not in paths:
                        paths.append(child)
    return paths


async def preview(
    integration: WizIntegration,
    query: str,
    variables: Optional[Dict[str, Any]],
    connection_path: Optional[str] = None,
) -> Dict[str, Any]:
    result = await run_query(
        _client_for(integration),
        query,
        variables,
        connection_path=connection_path,
        page_size=PREVIEW_ROWS,
        max_pages=1,
        limit=PREVIEW_ROWS,
    )
    rows = result["nodes"]
    return {
        "ok": True,
        "message": f"Query returned {len(rows)} sample row(s) from '{result['connection_path']}'.",
        "connection_path": result["connection_path"],
        "rows": rows,
        "fields": _field_paths(rows),
    }


# ── Persistence ─────────────────────────────────────────────────────────────


def _external_id(node: Dict[str, Any]) -> str:
    node_id = node.get("id")
    if node_id not in (None, ""):
        return str(node_id)[:500]
    digest = hashlib.sha256(json.dumps(node, sort_keys=True, default=str).encode()).hexdigest()
    return f"sha256:{digest}"


def _host_and_type(raw: Any) -> Optional[Tuple[str, AssetType, Optional[str]]]:
    """Normalize a hostname/URL/IP into (asset value, asset type, url)."""
    if raw in (None, "") or isinstance(raw, (dict, list)):
        return None
    text = str(raw).strip()
    url = text if "://" in text else None
    host = (urlparse(text if url else f"//{text}").hostname or "").strip().rstrip(".").lower()
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
        return host, AssetType.IP_ADDRESS, url
    except ValueError:
        pass
    if not re.fullmatch(r"[a-z0-9_*-]+(\.[a-z0-9_-]+)+", host):
        return None
    asset_type = AssetType.DOMAIN if host.count(".") == 1 else AssetType.SUBDOMAIN
    return host, asset_type, url


def _upsert_host_asset(
    db: Session, cq: WizCustomQuery, node: Dict[str, Any], stats: Dict[str, int]
) -> Optional[Asset]:
    parsed = _host_and_type(_dig(node, cq.asset_host_field or ""))
    if not parsed:
        return None
    value, asset_type, url = parsed
    asset = db.query(Asset).filter(
        Asset.organization_id == cq.organization_id, Asset.value == value
    ).first()
    source = {"query_id": cq.id, "query_name": cq.name, "record_id": _external_id(node)}
    if asset:
        metadata = dict(asset.metadata_ or {})
        pulls = dict(metadata.get("wiz_custom_queries") or {})
        pulls[str(cq.id)] = source
        metadata["wiz_custom_queries"] = pulls
        asset.metadata_ = metadata
        asset.last_seen = datetime.utcnow()
        tags = list(asset.tags or [])
        if "source:wiz" not in tags:
            tags.append("source:wiz")
            asset.tags = tags
        stats["assets_updated"] += 1
        return asset
    asset = Asset(
        name=value[:255],
        asset_type=asset_type,
        value=value[:500],
        organization_id=cq.organization_id,
        status=AssetStatus.DISCOVERED,
        discovery_source=DISCOVERY_SOURCE,
        association_reason=f"Returned by the Wiz custom query '{cq.name}'"[:1000],
        association_confidence=90,
        tags=["source:wiz"],
        metadata_={"wiz_custom_queries": {str(cq.id): source}},
        live_url=url[:500] if url else None,
        is_public=True,
    )
    db.add(asset)
    db.flush()
    stats["assets_created"] += 1
    return asset


def _new_stats() -> Dict[str, int]:
    return {
        "rows_seen": 0,
        "records_created": 0,
        "records_updated": 0,
        "records_gone": 0,
        "assets_created": 0,
        "assets_updated": 0,
        "pages": 0,
    }


async def sync_custom_query(
    db: Session,
    cq: WizCustomQuery,
    *,
    integration: Optional[WizIntegration] = None,
    client: Optional[WizClient] = None,
) -> Dict[str, Any]:
    stats = _new_stats()
    try:
        client = client or _client_for(integration or cq.integration)
        result = await run_query(
            client,
            cq.query,
            cq.variables or {},
            connection_path=cq.connection_path,
            page_size=cq.page_size or 100,
            max_pages=cq.max_pages or 50,
        )
        now = datetime.utcnow()
        stats["pages"] = result["pages"]
        existing = {
            record.external_id: record
            for record in db.query(WizCustomQueryRecord).filter(WizCustomQueryRecord.query_id == cq.id)
        }
        seen = set()
        for node in result["nodes"]:
            external_id = _external_id(node)
            if external_id in seen:
                continue
            seen.add(external_id)
            stats["rows_seen"] += 1
            record = existing.get(external_id)
            if record is None:
                record = WizCustomQueryRecord(
                    organization_id=cq.organization_id,
                    query_id=cq.id,
                    external_id=external_id,
                    first_seen_at=now,
                )
                db.add(record)
                existing[external_id] = record
                stats["records_created"] += 1
            else:
                stats["records_updated"] += 1
            record.data = node
            record.is_present = True
            record.last_seen_at = now
            if cq.asset_host_field:
                asset = _upsert_host_asset(db, cq, node, stats)
                if asset is not None:
                    record.asset_id = asset.id
        # A truncated run did not see every row, so absence proves nothing.
        if not result["truncated"]:
            for external_id, record in existing.items():
                if external_id not in seen and record.is_present:
                    record.is_present = False
                    stats["records_gone"] += 1
        if not cq.connection_path:
            cq.connection_path = result["connection_path"]
        cq.last_run_at = now
        cq.last_run_ok = True
        cq.last_error = (
            f"Stopped after {cq.max_pages} page(s); raise the page limit to fetch everything."
            if result["truncated"]
            else None
        )
        cq.last_run_stats = stats
        db.commit()
        return {
            "ok": True,
            "message": (
                f"'{cq.name}': {stats['rows_seen']} row(s), {stats['records_created']} new, "
                f"{stats['records_gone']} no longer returned, {stats['assets_created']} new asset(s)."
            ),
            **stats,
        }
    except (WizApiError, WizQueryError) as exc:
        return _record_failure(db, cq, stats, str(exc))
    except Exception as exc:  # noqa: BLE001
        logger.exception("Wiz custom query %s failed", cq.id)
        return _record_failure(db, cq, stats, f"Unexpected error: {exc}")


def _record_failure(db: Session, cq: WizCustomQuery, stats: Dict[str, int], message: str) -> Dict[str, Any]:
    db.rollback()
    cq.last_run_at = datetime.utcnow()
    cq.last_run_ok = False
    cq.last_error = message[:1000]
    cq.last_run_stats = stats
    db.commit()
    return {"ok": False, "message": f"'{cq.name}' failed: {message}", **stats}


async def sync_integration_queries(db: Session, integration: WizIntegration) -> List[Dict[str, Any]]:
    """Run every active custom query for a connection, sharing one OAuth token."""
    queries = (
        db.query(WizCustomQuery)
        .filter(WizCustomQuery.integration_id == integration.id, WizCustomQuery.is_active == True)  # noqa: E712
        .order_by(WizCustomQuery.id)
        .all()
    )
    if not queries:
        return []
    try:
        client = _client_for(integration)
    except WizApiError as exc:
        return [_record_failure(db, cq, _new_stats(), str(exc)) for cq in queries]
    return [await sync_custom_query(db, cq, client=client) for cq in queries]
