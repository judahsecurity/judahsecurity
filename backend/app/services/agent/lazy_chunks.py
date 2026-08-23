"""Recover webpack/Vite/Next lazy chunks from a first-party bundle, then fetch them.

Port of the lazy_chunk_downloader skill (scripts/fetch_lazy_chunks.js):
webpack 5 ``.u`` / ``.miniCssF`` template + hash-map expansion, Vite mapDeps,
quoted fallbacks (including Next.js ``[accountId]`` chunks). In-scope HTTP only.
404s are expected — hash maps list ids that were never emitted.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Set
from urllib.parse import urljoin, urlparse

import httpx

MAX_CHUNKS = 60
MAX_DISCOVER = 200
MAX_BYTES = 16_000_000

_WEBPACK_FN = re.compile(
    r"\.(?:u|miniCssF)\s*=\s*(?:function\s*)?\(?\s*([\w$]+)\s*\)?\s*(?:=>|\{)"
)
_MAP_PAIR = re.compile(
    r"""(?:"([^"]+)"|'([^']+)'|([\w$]+))\s*:\s*(?:"([^"]*)"|'([^']*)'|([\w$.]+))"""
)
_VITE_DEPS = re.compile(r"__vite__\w*[Dd]eps\s*=?\s*\(?\s*\[([^\]]*)\]")
_PUBLIC_PATH = re.compile(r"""\.p\s*=\s*['"`]([^'"`]*)['"`]""")
_QUOTED_ASSET = re.compile(
    r"""['"`]((?:\.{0,2}/)?(?:[\w.\[\]-]+/)*[\w.\[\]-]*\.(?:chunk\.)?(?:js|css))['"`]"""
)
_NEXT_CHUNK = re.compile(r"""(/_next/static/(?:chunks|css)/[^'"\s]+\.(?:js|css))""")
_PRIORITY = re.compile(r"app|admin|action|page|main|index|runtime|execute|chunk", re.I)


def _host(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def in_scope(url: str, origin_host: str) -> bool:
    h = _host(url)
    origin_host = (origin_host or "").lower().lstrip(".")
    if not h or not origin_host:
        return False
    return h == origin_host or h.endswith("." + origin_host)


def _match_balanced(src: str, open_idx: int, open_ch: str, close_ch: str) -> Optional[str]:
    depth = 0
    for i in range(open_idx, len(src)):
        c = src[i]
        if c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return src[open_idx : i + 1]
    return None


def expand_template(param: str, expr: str) -> List[str]:
    """Expand a webpack ``.u`` body over every chunkId in its hash/name maps."""
    parts: List[Dict[str, Any]] = []
    i = 0
    n = len(expr)
    while i < n:
        c = expr[i]
        if c in "\"'`":
            j = i + 1
            s: List[str] = []
            while j < n and expr[j] != c:
                if expr[j] == "\\" and j + 1 < n:
                    s.append(expr[j + 1])
                    j += 2
                else:
                    s.append(expr[j])
                    j += 1
            parts.append({"lit": "".join(s)})
            i = j + 1
        elif c == "{":
            obj = _match_balanced(expr, i, "{", "}")
            if not obj:
                i += 1
                continue
            mapping: Dict[str, str] = {}
            for m in _MAP_PAIR.finditer(obj):
                key = m.group(1) or m.group(2) or m.group(3)
                val = m.group(4) if m.group(4) is not None else (m.group(5) if m.group(5) is not None else m.group(6))
                if key is not None and val is not None:
                    mapping[str(key)] = str(val)
            i += len(obj)
            if re.match(r"^[\s()]*\[", expr[i:]):
                idx = expr.find("]", i)
                if idx != -1:
                    i = idx + 1
            default = False
            dm = re.match(r"^[\s)]*\|\|[\s]*[\w$]+", expr[i:])
            if dm:
                default = True
                i += len(dm.group(0))
            parts.append({"map": mapping, "def": default})
        elif re.match(r"[A-Za-z0-9_$]", c):
            j = i
            while j < n and re.match(r"[A-Za-z0-9_$]", expr[j]):
                j += 1
            word = expr[i:j]
            if word == param:
                parts.append({"param": True})
            i = j
        else:
            i += 1

    ids: Set[str] = set()
    for p in parts:
        if p.get("map"):
            ids.update(p["map"].keys())
    if not ids:
        return []

    files: List[str] = []
    for chunk_id in ids:
        name = ""
        ok = True
        for p in parts:
            if "lit" in p:
                name += p["lit"]
            elif p.get("param"):
                name += chunk_id
            elif p.get("map") is not None:
                mp = p["map"]
                if chunk_id in mp:
                    name += mp[chunk_id]
                elif p.get("def"):
                    name += chunk_id
                else:
                    ok = False
                    break
        if ok and re.search(r"[^/]\.(js|css)$", name, re.I):
            files.append(name)
    return files


def find_webpack_templates(src: str) -> List[str]:
    out: List[str] = []
    for m in _WEBPACK_FN.finditer(src or ""):
        param = m.group(1)
        last = src[m.start() + len(m.group(0)) - 1]
        if last == "{":
            body = _match_balanced(src, m.start() + len(m.group(0)) - 1, "{", "}") or ""
            body = body[1:-1]
            body = re.sub(r"^\s*return\b", "", body)
        else:
            tail = src[m.start() + len(m.group(0)) - 1 :]
            depth = 0
            end = 0
            for i, ch in enumerate(tail[:6000]):
                if ch in "({[":
                    depth += 1
                elif ch in ")}]":
                    if depth == 0:
                        end = i
                        break
                    depth -= 1
                elif ch in ";," and depth == 0:
                    end = i
                    break
                end = i + 1
            body = tail[:end]
        out.extend(expand_template(param, body))
    return out


def find_fallbacks(src: str) -> List[str]:
    out: List[str] = []
    for m in _VITE_DEPS.finditer(src or ""):
        for q in re.findall(r"""['"`]([^'"`]+\.(?:js|css))['"`]""", m.group(1)):
            out.append(q)
    for m in _NEXT_CHUNK.finditer(src or ""):
        out.append(m.group(1))
    for m in _QUOTED_ASSET.finditer(src or ""):
        p = m.group(1)
        if re.search(r"(?:chunk|assets|static/(?:js|css)|chunks)\b", p, re.I) or re.search(
            r"\.chunk\.(js|css)$", p, re.I
        ):
            out.append(p)
    return out


def _rank(paths: Iterable[str]) -> List[str]:
    pri: List[str] = []
    rest: List[str] = []
    seen: Set[str] = set()
    for p in paths:
        if not p or p in seen or p.startswith("."):
            continue
        seen.add(p)
        (pri if _PRIORITY.search(p) else rest).append(p)
    return pri + rest


def discover_chunk_paths(body: str) -> Dict[str, Any]:
    public_paths: List[str] = []
    seen_p: Set[str] = set()
    for m in _PUBLIC_PATH.finditer(body or ""):
        v = m.group(1)
        if v and v not in seen_p:
            seen_p.add(v)
            public_paths.append(v)
    chunks = _rank(find_webpack_templates(body or "") + find_fallbacks(body or ""))
    chunks = [c for c in chunks if "node_modules" not in c][:MAX_DISCOVER]
    return {
        "public_paths": public_paths[:6],
        "chunk_paths": chunks[:MAX_CHUNKS],
        "count": min(len(chunks), MAX_CHUNKS),
        "discovered_total": len(chunks),
    }


def resolve_chunk_urls(
    *,
    base_url: str,
    public_paths: Iterable[str],
    chunk_paths: Iterable[str],
) -> List[str]:
    origin = base_url if "://" in (base_url or "") else f"https://{base_url}"
    parsed = urlparse(origin)
    origin_root = f"{parsed.scheme}://{parsed.netloc}"
    prefixes = [origin]
    for p in public_paths:
        if str(p).startswith("http"):
            prefixes.append(str(p))
        else:
            prefixes.append(urljoin(origin_root + "/", str(p).lstrip("/") + "/"))
    out: List[str] = []
    seen: Set[str] = set()
    for path in chunk_paths:
        if str(path).startswith("http"):
            url = str(path)
        else:
            url = urljoin(prefixes[0].rstrip("/") + "/", str(path).lstrip("/"))
        if url in seen:
            continue
        seen.add(url)
        out.append(url)
    return out[:MAX_CHUNKS]


async def fetch_lazy_chunks(
    *,
    bundle_url: str,
    base_url: str = "",
    dry_run: bool = False,
    timeout: float = 60.0,
) -> Dict[str, Any]:
    bundle_url = (bundle_url or "").strip()
    if not bundle_url.startswith("http"):
        return {"ok": False, "error": "bundle_url must be https://..."}
    origin_host = _host(base_url or bundle_url)
    async with httpx.AsyncClient(follow_redirects=True, verify=False, timeout=timeout) as client:
        try:
            resp = await client.get(bundle_url)
        except Exception as exc:
            return {"ok": False, "error": f"failed to fetch bundle: {exc}"}
        body = (resp.text or "")[:MAX_BYTES]
    discovered = discover_chunk_paths(body)
    urls = resolve_chunk_urls(
        base_url=base_url or bundle_url,
        public_paths=discovered["public_paths"],
        chunk_paths=discovered["chunk_paths"],
    )
    urls = [u for u in urls if in_scope(u, origin_host)]
    result: Dict[str, Any] = {
        "ok": True,
        "bundle_url": bundle_url,
        "public_paths": discovered["public_paths"],
        "discovered": discovered["discovered_total"],
        "in_scope_urls": urls,
        "dry_run": dry_run,
        "fetched": [],
        "failed": [],
        "next": "extract_js_endpoints on fetched URLs, then ingest_urls_into_map",
    }
    if dry_run:
        return result
    async with httpx.AsyncClient(follow_redirects=True, verify=False, timeout=timeout) as client:
        for url in urls:
            try:
                r = await client.get(url)
                if r.status_code == 200 and len(r.content or b"") > 32:
                    result["fetched"].append({"url": url, "bytes": len(r.content), "status": 200})
                else:
                    result["failed"].append({"url": url, "status": r.status_code})
            except Exception as exc:
                result["failed"].append({"url": url, "error": str(exc)[:160]})
    result["fetched_ok"] = len(result["fetched"])
    result["failed_count"] = len(result["failed"])
    return result
