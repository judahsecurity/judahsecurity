"""
Interceptor Recon Driver
========================

Interaction-first recon via Hacker-Valley-Media/Interceptor.

Site Spider skill model: **katana running inside a real Chrome tab** — drive
Chrome like a user (scroll, menus, tabs/buttons) so JS lazy-loads through
WAF-trusted fetches; mine those chunks for endpoints. Interaction is primary;
BFS link-following is secondary; ``--robots`` / ``--sitemap`` are opt-in only.

Preference:
  1. Native ``interceptor spider`` when supported (Windows skill / newer builds —
     max-pages/depth/robots/sitemap/max-clicks).
  2. Verb-loop fallback (``open`` / ``act`` / ``net log``) on older installs.
  3. Server Playwright deep_crawl is handled by interceptor_service, not here.

Standalone / worker::

    python -m app.services.interceptor_recon https://app.target.com --max-pages 25
    python -m app.services.interceptor_worker --kind mac
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import shutil
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

# Reuse the endpoint/sourcemap patterns from deep_crawl so both engines extract
# surface identically.
try:
    from app.services.deep_crawl_service import _ENDPOINT_PATTERN, _SOURCEMAP_PATTERN
except Exception:  # pragma: no cover - allow standalone use without full app
    import re

    _ENDPOINT_PATTERN = re.compile(
        r"""(?xi)(?:["'`])((?:https?://[^\s"'`<>]+)|(?:/[A-Za-z0-9_\-/.?=&%#]{3,200}))(?:["'`])"""
    )
    _SOURCEMAP_PATTERN = re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*([^\s]+)", re.IGNORECASE)

import re

_URL_RE = re.compile(r"https?://[^\s\"'`<>\\]+", re.IGNORECASE)
# "GET /api/foo", "POST https://..." style lines in net log output.
_METHOD_URL_RE = re.compile(
    r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|WS)\b\s+([^\s\"'`<>]+)", re.IGNORECASE
)

_COVERAGE_RE = re.compile(r"\b(EXHAUSTIVE|PARTIAL)\b", re.IGNORECASE)
_PAGE_LINE_RE = re.compile(
    r"(?:visited|page|url|open(?:ed)?)\s*[:=]?\s*(https?://[^\s\"'`<>]+)",
    re.IGNORECASE,
)

DEFAULT_MAX_PAGES = 15
HARD_MAX_PAGES = 80  # Interceptor Windows skill deep-SPA guidance
DEFAULT_CLICKS_PER_PAGE = 10
DEFAULT_SPIDER_DEPTH = 3
CMD_TIMEOUT = int(os.environ.get("INTERCEPTOR_CMD_TIMEOUT", "45") or "45")
SPIDER_TIMEOUT = int(os.environ.get("INTERCEPTOR_SPIDER_TIMEOUT_SEC", "1800") or "1800")

_DESTRUCTIVE_TEXT = re.compile(
    r"(log\s?out|sign\s?out|delete|remove|destroy|deactivate|pay|purchase|"
    r"checkout|buy|order|confirm|submit|save|unsubscribe|cancel\s?subscription|"
    r"reset|wipe)",
    re.IGNORECASE,
)

# bin_path -> supports native `spider`
_SPIDER_SUPPORT: Dict[str, bool] = {}


def resolve_bin() -> Optional[str]:
    """Locate the interceptor binary (INTERCEPTOR_BIN or PATH)."""
    cand = os.environ.get("INTERCEPTOR_BIN", "").strip() or "interceptor"
    if os.path.isabs(cand):
        return cand if os.path.exists(cand) and os.access(cand, os.X_OK) else None
    return shutil.which(cand)


def _apex(host: str) -> str:
    parts = (host or "").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else (host or "")


def _in_scope(host: str, scope_apex: str) -> bool:
    if not host or not scope_apex:
        return False
    host = host.lower()
    return host == scope_apex or host.endswith("." + scope_apex)


@dataclass
class ReconResult:
    """Normalised recon surface — the shared contract with deep_crawl."""
    target: str = ""
    scope: str = ""
    engine: str = "interceptor"  # interceptor_spider | interceptor_verbs | interceptor
    coverage: Optional[str] = None  # EXHAUSTIVE | PARTIAL (native spider)
    pages_visited: List[str] = field(default_factory=list)
    js_files: Set[str] = field(default_factory=set)
    source_maps: Set[str] = field(default_factory=set)
    api_calls: Dict[str, Set[str]] = field(default_factory=dict)  # host -> {"METHOD path"}
    third_party: Set[str] = field(default_factory=set)
    websockets: Set[str] = field(default_factory=set)
    sse: Set[str] = field(default_factory=set)
    endpoints_from_js: Set[str] = field(default_factory=set)
    auth_headers: List[str] = field(default_factory=list)  # names only (CSRF/auth surface)
    errors: List[str] = field(default_factory=list)

    def record_call(self, method: str, url: str) -> None:
        if not url or url.startswith(("data:", "blob:", "channel:")):
            return
        try:
            host = urlparse(url).netloc
        except Exception:
            return
        if not host:
            return
        if _in_scope(host, self.scope):
            path = urlparse(url).path or "/"
            q = urlparse(url).query
            key = f"{method.upper()} {path}" + (f"?{q[:120]}" if q else "")
            self.api_calls.setdefault(host, set()).add(key)
            if url.split("?")[0].endswith(".js"):
                self.js_files.add(url.split("?")[0])
        else:
            self.third_party.add(host)


class InterceptorCLI:
    """Thin async wrapper around the ``interceptor`` binary."""

    def __init__(self, bin_path: str, context: Optional[str] = None):
        self.bin = bin_path
        self.context = context

    async def run(self, *args: str, timeout: int = CMD_TIMEOUT) -> str:
        argv = [self.bin]
        if self.context:
            argv += ["--context", self.context]
        argv += [a for a in args if a is not None]
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return (out or b"").decode("utf-8", errors="replace")
        except asyncio.TimeoutError:
            return f"__timeout__ after {timeout}s: {' '.join(args)}"
        except FileNotFoundError:
            raise
        except Exception as e:  # pragma: no cover - defensive
            return f"__error__ {e}: {' '.join(args)}"

    async def reachable(self) -> bool:
        """True if the daemon + extension respond (status reports a context)."""
        out = await self.run("status", timeout=15)
        low = out.lower()
        if "not reachable" in low or "__error__" in low or "__timeout__" in low:
            return False
        # A working install reports a mode: line (browser-only / full).
        return "mode:" in low or "daemon:" in low or "context" in low


async def supports_spider(cli: InterceptorCLI) -> bool:
    """True when this Interceptor binary exposes a native ``spider`` verb."""
    cached = _SPIDER_SUPPORT.get(cli.bin)
    if cached is not None:
        return cached

    force = (os.environ.get("INTERCEPTOR_FORCE_SPIDER") or "").strip().lower()
    if force in ("1", "true", "yes"):
        _SPIDER_SUPPORT[cli.bin] = True
        return True
    if force in ("0", "false", "no"):
        _SPIDER_SUPPORT[cli.bin] = False
        return False

    for probe in (
        ("help", "spider"),
        ("spider", "--help"),
        ("manifest",),
    ):
        out = await cli.run(*probe, timeout=20)
        low = out.lower()
        if "__timeout__" in low or "__error__" in low:
            continue
        if "unknown" in low and "spider" in low:
            continue
        if "not found" in low or "no such" in low:
            continue
        # Positive signals from Windows skill / help text
        if any(
            tok in low
            for tok in (
                "max-pages",
                "max-clicks",
                "include-subdomains",
                "site spider",
                "usage: interceptor spider",
                "usage:\n  interceptor spider",
                '"spider"',
            )
        ):
            _SPIDER_SUPPORT[cli.bin] = True
            return True
        if probe[0] == "help" and "spider" in low and "usage" in low:
            _SPIDER_SUPPORT[cli.bin] = True
            return True

    _SPIDER_SUPPORT[cli.bin] = False
    return False


def _build_spider_argv(url: str, opts: Dict[str, Any], max_pages: int) -> List[str]:
    """Flags aligned with the Interceptor Windows Site Spider skill."""
    argv = ["spider", url, "--max-pages", str(max_pages)]

    depth = opts.get("depth", DEFAULT_SPIDER_DEPTH)
    try:
        depth_i = int(depth)
    except (TypeError, ValueError):
        depth_i = DEFAULT_SPIDER_DEPTH
    if depth_i > 0:
        argv += ["--depth", str(depth_i)]

    max_clicks = opts.get("max_clicks") or opts.get("clicks_per_page") or DEFAULT_CLICKS_PER_PAGE
    try:
        argv += ["--max-clicks", str(int(max_clicks))]
    except (TypeError, ValueError):
        pass

    if opts.get("include_subdomains") or opts.get("include-subdomains"):
        argv.append("--include-subdomains")
    if opts.get("include_thirdparty") or opts.get("include-thirdparty"):
        argv.append("--include-thirdparty")
    if opts.get("robots"):
        argv.append("--robots")
    if opts.get("sitemap"):
        argv.append("--sitemap")
    if opts.get("no_scroll") or opts.get("no-scroll") or opts.get("interact") is False:
        argv.append("--no-scroll")
    if opts.get("no_sourcemaps") or opts.get("no-sourcemaps"):
        argv.append("--no-sourcemaps")

    probe = opts.get("probe_text") or opts.get("probe-text")
    if probe:
        argv += ["--probe-text", str(probe)]

    return argv


def _parse_spider_output(out: str, result: ReconResult) -> None:
    """Best-effort parse of spider stdout into the normalised recon contract."""
    if not out:
        return
    cov = _COVERAGE_RE.search(out)
    if cov:
        result.coverage = cov.group(1).upper()

    # Prefer JSON blob if present
    stripped = out.strip()
    if stripped.startswith("{") or "\n{" in stripped:
        try:
            start = stripped.find("{")
            end = stripped.rfind("}") + 1
            if start >= 0 and end > start:
                data = json.loads(stripped[start:end])
                if isinstance(data, dict):
                    for p in data.get("pages") or data.get("pages_visited") or data.get("urls") or []:
                        if isinstance(p, str) and p.startswith("http"):
                            if p not in result.pages_visited:
                                result.pages_visited.append(p.split("#")[0])
                    for j in data.get("js") or data.get("js_files") or []:
                        if isinstance(j, str):
                            result.js_files.add(j.split("?")[0])
                    for s in data.get("source_maps") or data.get("sourcemaps") or []:
                        if isinstance(s, str):
                            result.source_maps.add(s)
                    apis = data.get("api_calls") or data.get("apis") or {}
                    if isinstance(apis, dict):
                        for host, keys in apis.items():
                            for key in keys or []:
                                parts = str(key).split(" ", 1)
                                method = parts[0] if len(parts) == 2 else "GET"
                                path = parts[1] if len(parts) == 2 else parts[0]
                                result.record_call(method, f"https://{host}{path}" if path.startswith("/") else path)
                    if data.get("coverage"):
                        result.coverage = str(data["coverage"]).upper()
        except (json.JSONDecodeError, TypeError, ValueError):
            pass

    for m in _PAGE_LINE_RE.finditer(out):
        u = m.group(1).split("#")[0]
        if u not in result.pages_visited:
            result.pages_visited.append(u)

    for method, u in _METHOD_URL_RE.findall(out):
        result.record_call(method, _abs(result.target, u))

    for u in _URL_RE.findall(out):
        clean = u.rstrip(").,;]\"'")
        result.record_call("GET", clean)
        if clean.split("?")[0].endswith(".js"):
            result.js_files.add(clean.split("?")[0])
        if clean.endswith(".map") or "sourcemap" in clean.lower():
            result.source_maps.add(clean)
        if clean.startswith("ws://") or clean.startswith("wss://"):
            result.websockets.add(clean[:400])

    # Seed pages with target if spider only printed coverage / asset URLs
    if not result.pages_visited and result.target:
        result.pages_visited.append(result.target)

    # Path-looking tokens from JS-style quotes → endpoints_from_js
    for m in _ENDPOINT_PATTERN.finditer(out):
        tok = m.group(1) if m.lastindex else m.group(0)
        if tok and tok.startswith("/") and len(tok) >= 3:
            result.endpoints_from_js.add(tok[:300])


async def _run_native_spider(
    cli: InterceptorCLI,
    url: str,
    opts: Dict[str, Any],
    result: ReconResult,
    max_pages: int,
) -> bool:
    """Run native spider; return True if we got usable pages."""
    argv = _build_spider_argv(url, opts, max_pages)
    # ~60s interaction budget per page (skill) + overhead; clamp to SPIDER_TIMEOUT
    timeout = min(SPIDER_TIMEOUT, max(300, max_pages * 75))
    logger.info("interceptor native spider: %s (timeout=%ss)", " ".join(argv), timeout)
    out = await cli.run(*argv, timeout=timeout)
    if "__timeout__" in out:
        result.errors.append(f"spider timeout after {timeout}s — parsing partial output")
    if "__error__" in out[:80].lower() and "unknown" in out.lower():
        result.errors.append("spider verb rejected by this Interceptor build")
        return False

    _parse_spider_output(out, result)
    result.engine = "interceptor_spider"

    # Drain passive nets after spider if the session is still live
    try:
        await _drain(cli, result)
        await _mine_headers(cli, result)
    except Exception as e:
        result.errors.append(f"post-spider drain: {str(e)[:120]}")

    return bool(result.pages_visited)


async def run_recon(url: str, opts: Optional[Dict[str, Any]] = None) -> ReconResult:
    """Drive Interceptor: prefer native spider, else verb-loop crawl + capture."""
    opts = opts or {}
    if not url.startswith("http"):
        url = f"https://{url}"
    scope = str(opts.get("scope") or "").strip().lower() or _apex(urlparse(url).netloc)
    max_pages = min(int(opts.get("max_pages", DEFAULT_MAX_PAGES) or DEFAULT_MAX_PAGES), HARD_MAX_PAGES)
    interact = bool(opts.get("interact", True))
    clicks = int(opts.get("clicks_per_page", DEFAULT_CLICKS_PER_PAGE) or DEFAULT_CLICKS_PER_PAGE)
    prefer_spider = opts.get("prefer_spider", True)
    if isinstance(prefer_spider, str):
        prefer_spider = prefer_spider.lower() not in ("0", "false", "no")

    result = ReconResult(target=url, scope=scope, engine="interceptor")

    bin_path = resolve_bin()
    if not bin_path:
        result.errors.append("interceptor binary not found (set INTERCEPTOR_BIN or add to PATH)")
        return result

    cli = InterceptorCLI(bin_path, context=opts.get("context"))
    if not await cli.reachable():
        result.errors.append(
            "interceptor daemon/extension not reachable — load the unpacked extension "
            "and enable Developer mode, then verify with `interceptor open <url>`"
        )
        return result

    await cli.run("net", "monitor", "on", "--reload")

    if prefer_spider and await supports_spider(cli):
        ok = await _run_native_spider(cli, url, opts, result, max_pages)
        if ok:
            return result
        result.errors.append("native spider produced no pages; falling back to verb-loop crawl")
        # Reset surface for verb-loop (keep errors)
        result.engine = "interceptor"
        result.pages_visited = []
        result.js_files = set()
        result.source_maps = set()
        result.api_calls = {}
        result.third_party = set()
        result.websockets = set()
        result.sse = set()
        result.endpoints_from_js = set()
        result.coverage = None

    # Verb-loop fallback (older Interceptor without spider)
    result.engine = "interceptor_verbs"
    queue: List[str] = [url]
    seen: Set[str] = set()

    while queue and len(result.pages_visited) < max_pages:
        page_url = queue.pop(0).split("#")[0]
        if page_url in seen:
            continue
        seen.add(page_url)

        open_out = await cli.run("open", page_url, "--reuse", "--full")
        if "__timeout__" in open_out or "__error__" in open_out:
            result.errors.append(f"open {page_url[:100]}: {open_out[:120]}")
            continue
        result.pages_visited.append(page_url)
        await cli.run("wait-stable", timeout=20)

        if interact:
            await _drive(cli, result, clicks)

        await _drain(cli, result)

        tree = await cli.run("tree", "--filter", "all")
        for link in _extract_links(tree):
            absu = urljoin(page_url, link).split("#")[0]
            if absu.startswith("http") and _in_scope(urlparse(absu).netloc, scope):
                if absu not in seen and absu not in queue and len(queue) < HARD_MAX_PAGES * 4:
                    queue.append(absu)

    await _mine_headers(cli, result)
    return result


async def _drive(cli: InterceptorCLI, result: ReconResult, clicks: int) -> None:
    """Scroll + click a bounded set of safe controls to trigger lazy loads."""
    for _ in range(4):
        await cli.run("scroll", "down", timeout=15)
        await asyncio.sleep(0.2)
    await cli.run("scroll", "top", timeout=15)

    tree = await cli.run("tree")
    refs = _extract_clickable_refs(tree)
    done = 0
    for ref, label in refs:
        if done >= clicks:
            break
        if label and _DESTRUCTIVE_TEXT.search(label):
            continue
        await cli.run("act", ref, "--no-read", timeout=20)
        done += 1
        await asyncio.sleep(0.2)
        # Traffic from each interaction is captured passively; drain periodically.
        if done % 4 == 0:
            await _drain(cli, result)


async def _drain(cli: InterceptorCLI, result: ReconResult) -> None:
    """Pull net log / headers / sse / page-comm and fold into the result."""
    net = await cli.run("net", "log", "--limit", "200")
    for method, u in _METHOD_URL_RE.findall(net):
        result.record_call(method, _abs(result.target, u))
    for u in _URL_RE.findall(net):
        result.record_call("GET", u)

    sse = await cli.run("sse", "log")
    for u in _URL_RE.findall(sse):
        result.sse.add(u[:400])

    pagecomm = await cli.run("net", "page-comm", "log")
    for u in _URL_RE.findall(pagecomm):
        if u.startswith("ws://") or u.startswith("wss://"):
            result.websockets.add(u[:400])


async def _mine_headers(cli: InterceptorCLI, result: ReconResult) -> None:
    """Record captured request-header *names* (CSRF/auth token surface)."""
    headers = await cli.run("net", "headers")
    names: Set[str] = set()
    for line in headers.splitlines():
        m = re.match(r"\s*([A-Za-z][A-Za-z0-9\-]{1,40})\s*[:=]", line)
        if m:
            name = m.group(1).strip()
            if name.lower() in (
                "authorization", "cookie", "x-csrf-token", "x-xsrf-token",
                "x-api-key", "x-auth-token", "x-requested-with", "x-csrf",
            ):
                names.add(name)
    result.auth_headers = sorted(names)


def _abs(base: str, u: str) -> str:
    if u.startswith("http") or u.startswith("ws"):
        return u
    try:
        return urljoin(base, u)
    except Exception:
        return u


def _extract_links(tree_text: str) -> List[str]:
    """Pull href-like tokens from an interceptor tree/text dump."""
    links: List[str] = []
    for m in re.finditer(r'href\s*[:=]\s*["\']?([^\s"\'<>]+)', tree_text or ""):
        links.append(m.group(1))
    links.extend(_URL_RE.findall(tree_text or ""))
    # Dedup, cap.
    out, seen = [], set()
    for l in links:
        if l not in seen:
            seen.add(l)
            out.append(l)
    return out[:300]


_REF_RE = re.compile(r"\b(e\d+(?:_\d+)?)\b")
_LABEL_RE = re.compile(r'"([^"]{1,60})"|\'([^\']{1,60})\'')


def _extract_clickable_refs(tree_text: str) -> List[tuple]:
    """Return [(ref, label)] for tree lines like 'e5 button "Search"'.

    Line-based so the label (the first quoted string on the same line) is
    captured reliably — the destructive-control filter depends on it.
    """
    out: List[tuple] = []
    seen: Set[str] = set()
    for line in (tree_text or "").splitlines():
        rm = _REF_RE.search(line)
        if not rm:
            continue
        ref = rm.group(1)
        if ref in seen:
            continue
        seen.add(ref)
        lm = _LABEL_RE.search(line)
        label = (lm.group(1) or lm.group(2) or "").strip() if lm else ""
        out.append((ref, label))
        if len(out) >= 60:
            break
    return out


def to_normalized_dict(result: ReconResult) -> Dict[str, Any]:
    """JSON-safe normalised contract shared by the bridge + ingest endpoint."""
    return {
        "target": result.target,
        "scope": result.scope,
        "engine": result.engine,
        "coverage": result.coverage,
        "pages_visited": result.pages_visited,
        "js_files": sorted(result.js_files),
        "source_maps": sorted(result.source_maps),
        "api_calls": {h: sorted(v) for h, v in result.api_calls.items()},
        "third_party": sorted(result.third_party),
        "websockets": sorted(result.websockets),
        "sse": sorted(result.sse),
        "endpoints_from_js": sorted(result.endpoints_from_js),
        "auth_headers": result.auth_headers,
        "errors": result.errors[:10],
    }


def format_output(result: ReconResult) -> str:
    """Human/agent-readable rendering (mirrors deep_crawl's envelope)."""
    d = to_normalized_dict(result)
    mode = d["engine"]
    lines = [
        f"Interceptor recon complete (engine={mode}).",
        f"Target: {d['target']}  (scope: {d['scope']})",
        f"Pages visited: {len(d['pages_visited'])}"
        + (f"  coverage={d['coverage']}" if d.get("coverage") else ""),
    ]
    for p in d["pages_visited"][:25]:
        lines.append(f"  - {p}")

    total_api = sum(len(v) for v in d["api_calls"].values())
    if d["api_calls"]:
        lines.append(f"\nFirst-party API / XHR endpoints ({total_api} across {len(d['api_calls'])} hosts):")
        for host in sorted(d["api_calls"]):
            lines.append(f"  [{host}]")
            for key in d["api_calls"][host][:80]:
                lines.append(f"    {key}")
    if d["websockets"]:
        lines.append(f"\nWebSocket channels ({len(d['websockets'])}):")
        lines += [f"    {w}" for w in d["websockets"][:20]]
    if d["sse"]:
        lines.append(f"\nSSE streams ({len(d['sse'])}):")
        lines += [f"    {s}" for s in d["sse"][:20]]
    if d["js_files"]:
        lines.append(f"\nJavaScript files ({len(d['js_files'])}):")
        lines += [f"    {j}" for j in d["js_files"][:60]]
    if d["source_maps"]:
        lines.append(f"\nSource maps ({len(d['source_maps'])}):")
        lines += [f"    {s}" for s in d["source_maps"][:20]]
    if d["endpoints_from_js"]:
        lines.append(f"\nEndpoints from JS ({len(d['endpoints_from_js'])}):")
        lines += [f"    {e}" for e in d["endpoints_from_js"][:120]]
    if d["auth_headers"]:
        lines.append(f"\nAuth/CSRF header surface: {', '.join(d['auth_headers'])}")
    if d["third_party"]:
        lines.append(f"\nThird-party hosts ({len(d['third_party'])}):")
        lines += [f"    {t}" for t in d["third_party"][:30]]
    if d["errors"]:
        lines.append("\nNotes/errors:")
        lines += [f"    {e}" for e in d["errors"]]

    lines.append(
        "\nNext steps: feed JS URLs to scan_js_urls_for_secrets, probe endpoints with "
        "arjun/schemathesis/curl, pull source maps, and record surfaces with create_finding."
    )
    return "\n".join(lines)


def _post_to_bridge(payload: Dict[str, Any], post_url: str, token: str, org: Optional[int]) -> None:
    """POST normalised recon to the ASM bridge ingest endpoint."""
    import urllib.request

    body = json.dumps({"organization_id": org, "recon": payload}).encode("utf-8")
    req = urllib.request.Request(post_url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 - operator-controlled URL
        sys.stderr.write(f"[bridge] {resp.status} {resp.reason}\n")


def _main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="interceptor_recon",
        description="Interaction-first recon (native spider when available, else verb-loop).",
    )
    parser.add_argument("url", help="seed URL to crawl (uses your logged-in browser session)")
    parser.add_argument("--max-pages", type=int, default=DEFAULT_MAX_PAGES)
    parser.add_argument("--depth", type=int, default=DEFAULT_SPIDER_DEPTH, help="native spider depth")
    parser.add_argument("--max-clicks", type=int, default=None, help="native spider max clicks / page")
    parser.add_argument("--scope", default=None, help="apex to constrain crawl")
    parser.add_argument("--no-interact", action="store_true", help="don't click / --no-scroll")
    parser.add_argument("--include-subdomains", action="store_true")
    parser.add_argument("--include-thirdparty", action="store_true")
    parser.add_argument("--robots", action="store_true", help="seed from robots.txt")
    parser.add_argument("--sitemap", action="store_true", help="seed from sitemap.xml")
    parser.add_argument("--probe-text", default=None, help="type into text inputs (chat UIs)")
    parser.add_argument("--no-spider", action="store_true", help="force verb-loop even if spider exists")
    parser.add_argument("--context", default=None, help="interceptor --context id (multi-profile)")
    parser.add_argument("--json", dest="json_out", default=None, help="write normalised JSON here")
    parser.add_argument("--post", default=None, help="ASM bridge ingest URL to POST results to")
    parser.add_argument("--token", default=os.environ.get("ASM_TOKEN", ""), help="bearer token for --post")
    parser.add_argument("--org", type=int, default=None, help="organization_id for --post")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    opts = {
        "max_pages": args.max_pages,
        "depth": args.depth,
        "max_clicks": args.max_clicks,
        "scope": args.scope,
        "interact": not args.no_interact,
        "include_subdomains": args.include_subdomains,
        "include_thirdparty": args.include_thirdparty,
        "robots": args.robots,
        "sitemap": args.sitemap,
        "probe_text": args.probe_text,
        "prefer_spider": not args.no_spider,
        "context": args.context,
    }
    result = asyncio.run(run_recon(args.url, opts))
    payload = to_normalized_dict(result)

    print(format_output(result))

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        sys.stderr.write(f"[json] wrote {args.json_out}\n")

    if args.post:
        try:
            _post_to_bridge(payload, args.post, args.token, args.org)
        except Exception as e:
            sys.stderr.write(f"[bridge] POST failed: {e}\n")
            return 2

    return 0 if result.pages_visited else 1


if __name__ == "__main__":
    raise SystemExit(_main())
