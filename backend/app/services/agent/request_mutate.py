"""Captured-request mutate queue — pick one sample, change one field, send.

Specialists prove unknown bugs (SSRF/IDOR/authz) by mutating live HTTP, not
by describing Nuclei templates.
"""

from __future__ import annotations

import json
from copy import deepcopy
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

LOCATIONS = ("query", "header", "body_json", "body_form", "path", "method")


def samples_from_map(cmap: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not isinstance(cmap, dict):
        return []
    rows = list(cmap.get("api_samples") or [])
    # Also lift OpenAPI-ish endpoints into synthetic GET samples.
    for ep in cmap.get("api_endpoints") or []:
        if not isinstance(ep, dict):
            continue
        host = str(ep.get("host") or "")
        path = str(ep.get("path") or "")
        method = str(ep.get("method") or "GET")
        if not path:
            continue
        if path.startswith("http"):
            url = path
        elif host:
            url = f"https://{host}{path if path.startswith('/') else '/' + path}"
        else:
            target = str(cmap.get("target") or "").rstrip("/")
            url = f"{target}{path if path.startswith('/') else '/' + path}" if target else path
        rows.append({"method": method, "url": url, "headers": {}, "synthetic": True})
    return rows[:80]


def normalize_sample(
    sample: Dict[str, Any],
    *,
    fallback_origin: str = "",
) -> Dict[str, Any]:
    method = str(sample.get("method") or "GET").upper()
    url = str(sample.get("url") or sample.get("path") or "").strip()
    if url.startswith("/") and fallback_origin:
        url = fallback_origin.rstrip("/") + url
    if url and not url.startswith(("http://", "https://")) and fallback_origin:
        url = fallback_origin.rstrip("/") + "/" + url.lstrip("/")
    headers = dict(sample.get("headers") or {})
    body = sample.get("body") or sample.get("postData") or sample.get("post_data")
    if body is not None and not isinstance(body, str):
        try:
            body = json.dumps(body)
        except Exception:
            body = str(body)
    return {
        "method": method,
        "url": url,
        "headers": {str(k): str(v) for k, v in headers.items()},
        "body": body,
    }


def summarize_samples(
    samples: List[Dict[str, Any]],
    *,
    fallback_origin: str = "",
    limit: int = 40,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for i, raw in enumerate(samples[:limit]):
        if not isinstance(raw, dict):
            continue
        norm = normalize_sample(raw, fallback_origin=fallback_origin)
        keys: List[str] = []
        parsed = urlparse(norm["url"])
        keys.extend(k for k, _ in parse_qsl(parsed.query, keep_blank_values=True))
        body = norm.get("body") or ""
        if body:
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    keys.extend(str(k) for k in list(data.keys())[:12])
            except Exception:
                pass
        out.append({
            "index": i,
            "method": norm["method"],
            "url": norm["url"][:300],
            "fields": keys[:16],
            "has_body": bool(body),
        })
    return out


def apply_one_mutation(
    sample: Dict[str, Any],
    *,
    location: str,
    field: str,
    value: str,
    fallback_origin: str = "",
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Return (baseline, mutant). Mutant differs in exactly one location/field."""
    loc = (location or "query").strip().lower()
    if loc not in LOCATIONS:
        raise ValueError(f"location must be one of {LOCATIONS}")
    field = str(field or "").strip()
    if loc != "method" and not field:
        raise ValueError("field is required unless location=method")

    baseline = normalize_sample(sample, fallback_origin=fallback_origin)
    if not baseline["url"]:
        raise ValueError("sample has no url")
    mutant = deepcopy(baseline)

    if loc == "method":
        mutant["method"] = (value or field or "GET").upper()
    elif loc == "header":
        hdrs = dict(mutant["headers"])
        hdrs[field] = value
        mutant["headers"] = hdrs
    elif loc == "query":
        mutant["url"] = _set_query(mutant["url"], field, value)
    elif loc == "path":
        parsed = urlparse(mutant["url"])
        path = parsed.path or "/"
        if field in path:
            path = path.replace(field, value, 1)
        else:
            path = path.rstrip("/") + "/" + value.lstrip("/")
        mutant["url"] = urlunparse(parsed._replace(path=path))
    elif loc == "body_json":
        mutant["body"] = _set_json_field(mutant.get("body") or "{}", field, value)
        ctype = {k.lower(): k for k in mutant["headers"]}
        if "content-type" not in ctype:
            mutant["headers"]["Content-Type"] = "application/json"
    elif loc == "body_form":
        mutant["body"] = _set_form_field(mutant.get("body") or "", field, value)
        ctype = {k.lower(): k for k in mutant["headers"]}
        if "content-type" not in ctype:
            mutant["headers"]["Content-Type"] = "application/x-www-form-urlencoded"

    return baseline, mutant


def _set_query(url: str, field: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True) if k != field]
    pairs.append((field, value))
    return urlunparse(parsed._replace(query=urlencode(pairs)))


def _set_json_field(body: str, field: str, value: str) -> str:
    data: Any
    try:
        data = json.loads(body) if body else {}
    except Exception:
        data = {}
    if not isinstance(data, dict):
        data = {"_": data}
    # dotted path: a.b.c
    parts = [p for p in field.split(".") if p]
    cur = data
    for p in parts[:-1]:
        nxt = cur.get(p)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[p] = nxt
        cur = nxt
    cur[parts[-1] if parts else field] = _maybe_json_value(value)
    return json.dumps(data)


def _set_form_field(body: str, field: str, value: str) -> str:
    pairs = [(k, v) for k, v in parse_qsl(body, keep_blank_values=True) if k != field]
    pairs.append((field, value))
    return urlencode(pairs)


def _maybe_json_value(value: str) -> Any:
    text = str(value)
    if text.lower() in ("true", "false"):
        return text.lower() == "true"
    try:
        if text.isdigit() or (text.startswith("-") and text[1:].isdigit()):
            return int(text)
    except Exception:
        pass
    return text
