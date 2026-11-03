"""Normalize ffuf and sqlmap output into bounded, in-scope assessment leads.

These scanners are lead generators, not oracles. ffuf discovers paths and
sqlmap flags injectable parameters; both become parameter-inventory rows that
``seed_parameter_coverage_cells`` turns into coverage cells. A scanner's own
verdict never becomes a finding — confirmation still runs through the typed
scoped probes and the independent verifier. Everything here is pure: parse
text or JSON, drop out-of-scope and malformed rows, and bound the count.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

MAX_SCANNER_ROWS = 60

# Statuses ffuf returns that indicate real, reachable content worth probing.
# 404 and other misses are dropped.
_FFUF_KEEP_STATUS = frozenset({
    200, 201, 202, 203, 204, 206,
    301, 302, 303, 307, 308,
    401, 403, 405, 500,
})

# sqlmap prints one block per injectable parameter:
#   Parameter: id (GET)
#       Type: boolean-based blind
# The place in parentheses maps to an input location.
_SQLMAP_PARAM = re.compile(
    r"^\s*Parameter:\s*(?P<name>[^\s(]{1,128})\s*\((?P<place>GET|POST|URI|COOKIE|JSON)\)",
    re.MULTILINE,
)
_SQLMAP_URL = re.compile(r"\bURL:\s*(?P<url>https?://[^\s]{1,2048})", re.IGNORECASE)
_PLACE_LOCATION = {
    "GET": ("query", "GET"),
    "URI": ("query", "GET"),
    "POST": ("body_form", "POST"),
    "JSON": ("body_json", "POST"),
    # COOKIE injections are recorded but excluded from automatic injection work,
    # so they are not emitted as probe leads here.
}


def _in_scope(url: str, allowed_hosts: set[str]) -> bool:
    try:
        host = (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return False
    return bool(host) and host in allowed_hosts


def _normalize_hosts(allowed_hosts) -> set[str]:
    out = set()
    for host in allowed_hosts or ():
        if isinstance(host, str) and host:
            out.add(host.lower().rstrip("."))
    return out


def ffuf_rows(output: str, *, allowed_hosts) -> list[dict]:
    """Discovered in-scope paths from ffuf JSON output → endpoint inventory rows.

    ffuf's ``-of json`` payload is an object with a ``results`` array; each
    result carries a ``url`` and ``status``. Non-JSON or miss statuses yield
    nothing.
    """
    hosts = _normalize_hosts(allowed_hosts)
    if not hosts:
        return []
    try:
        document = json.loads(output)
    except (ValueError, TypeError):
        return []
    results = document.get("results") if isinstance(document, dict) else None
    if not isinstance(results, list):
        return []
    rows: dict[tuple, dict] = {}
    for entry in results:
        if not isinstance(entry, dict):
            continue
        url = entry.get("url")
        status = entry.get("status")
        if (not isinstance(url, str) or not isinstance(status, int)
                or status not in _FFUF_KEEP_STATUS or not _in_scope(url, hosts)):
            continue
        parts = urlsplit(url)
        path = parts.path or "/"
        if parts.query or parts.fragment or len(path) > 512:
            continue
        key = (parts.hostname, path)
        if key in rows:
            continue
        rows[key] = {
            "method": "GET", "url": f"{parts.scheme}://{parts.netloc}{path}",
            "name": "endpoint", "location": "query",
            "source": "ffuf_discovery",
        }
        if len(rows) >= MAX_SCANNER_ROWS:
            break
    return list(rows.values())


def sqlmap_rows(output: str, *, allowed_hosts) -> list[dict]:
    """Injectable parameters from sqlmap's report → sql-injection lead rows.

    A flagged parameter is a lead: it seeds a ``sql_injection`` coverage cell
    that the scoped SQLi probes and the independent verifier must still confirm
    before anything is published.
    """
    hosts = _normalize_hosts(allowed_hosts)
    if not hosts or not isinstance(output, str):
        return []
    url_match = _SQLMAP_URL.search(output)
    target_url = url_match.group("url") if url_match else ""
    if target_url and not _in_scope(target_url, hosts):
        return []
    parts = urlsplit(target_url) if target_url else None
    rows: dict[tuple, dict] = {}
    for match in _SQLMAP_PARAM.finditer(output):
        place = match.group("place").upper()
        if place not in _PLACE_LOCATION:
            continue
        location, method = _PLACE_LOCATION[place]
        name = match.group("name")
        key = (name, location, method)
        if key in rows:
            continue
        row = {
            "method": method, "name": name, "location": location,
            "source": "sqlmap_lead",
        }
        if parts and parts.hostname and parts.hostname.lower().rstrip(".") in hosts:
            row["url"] = f"{parts.scheme}://{parts.netloc}{parts.path or '/'}"
        else:
            # Without a verified in-scope URL we cannot anchor the row's path.
            continue
        rows[key] = row
        if len(rows) >= MAX_SCANNER_ROWS:
            break
    return list(rows.values())


def scanner_rows(tool: str, output: str, *, allowed_hosts) -> list[dict]:
    """Dispatch to the ffuf or sqlmap normalizer by tool name."""
    name = (tool or "").lower()
    if "ffuf" in name:
        return ffuf_rows(output, allowed_hosts=allowed_hosts)
    if "sqlmap" in name:
        return sqlmap_rows(output, allowed_hosts=allowed_hosts)
    return []
