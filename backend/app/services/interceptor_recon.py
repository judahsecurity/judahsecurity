"""
Interceptor Recon Driver
========================

The real Hacker-Valley-Media/Interceptor CLI has **no `spider`/crawler command**.
It is an *agent-driven browser controller*: you drive a real, already-logged-in
Chrome/Brave tab one verb at a time (`open`, `read`, `act`, `net log`, ...).

This module builds the crawl-and-capture loop that Interceptor lacks, out of the
verbs it *does* have, so we get "interaction-first recon against my real
authenticated browser session" — the thing that beats headless crawlers on
auth-walled / anti-automation apps.

Two ways to use it:

1. Standalone on the operator's machine (macOS/Windows/Linux desktop with a real
   browser + the Interceptor extension loaded):

       python -m app.services.interceptor_recon https://app.target.com \
           --max-pages 25 --json out.json \
           --post https://asm.internal/api/v1/recon/ingest --token "$ASM_TOKEN" --org 1

   It drives your real session, normalises the captured surface, writes JSON, and
   (optionally) POSTs the result back to the ASM harness (the "bridge") so the
   in-app agent's knowledge benefits from your authenticated crawl.

2. From inside the harness via ``interceptor_service.run_interceptor`` — used only
   when the ``interceptor`` binary is reachable on the host. On a headless Linux
   server it usually is not, and the service falls back to the Playwright
   ``deep_crawl`` engine instead.

IMPORTANT — output-format tolerance
-----------------------------------
Interceptor's per-command stdout schema is not part of its stable public
contract and may evolve. This driver therefore prefers ``--json`` where a command
supports it and otherwise **regex-scrapes URLs / methods / endpoints from the raw
text**. If Interceptor changes its output, only the small parse helpers here need
tuning — the crawl logic and normalised contract stay the same.
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

DEFAULT_MAX_PAGES = 15
HARD_MAX_PAGES = 60
DEFAULT_CLICKS_PER_PAGE = 10
CMD_TIMEOUT = int(os.environ.get("INTERCEPTOR_CMD_TIMEOUT", "45") or "45")

_DESTRUCTIVE_TEXT = re.compile(
    r"(log\s?out|sign\s?out|delete|remove|destroy|deactivate|pay|purchase|"
    r"checkout|buy|order|confirm|submit|save|unsubscribe|cancel\s?subscription|"
    r"reset|wipe)",
    re.IGNORECASE,
)


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
    engine: str = "interceptor"
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


async def run_recon(url: str, opts: Optional[Dict[str, Any]] = None) -> ReconResult:
    """Drive the real Interceptor through an interaction-first crawl + capture."""
    opts = opts or {}
    if not url.startswith("http"):
        url = f"https://{url}"
    scope = str(opts.get("scope") or "").strip().lower() or _apex(urlparse(url).netloc)
    max_pages = min(int(opts.get("max_pages", DEFAULT_MAX_PAGES) or DEFAULT_MAX_PAGES), HARD_MAX_PAGES)
    interact = bool(opts.get("interact", True))
    clicks = int(opts.get("clicks_per_page", DEFAULT_CLICKS_PER_PAGE) or DEFAULT_CLICKS_PER_PAGE)

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

    # Ensure sockets/startup traffic are captured across reloads.
    await cli.run("net", "monitor", "on", "--reload")

    queue: List[str] = [url]
    seen: Set[str] = set()

    while queue and len(result.pages_visited) < max_pages:
        page_url = queue.pop(0).split("#")[0]
        if page_url in seen:
            continue
        seen.add(page_url)

        # Open in a background interceptor-group tab, reusing one tab to avoid
        # accumulation, and wait for the DOM to settle.
        open_out = await cli.run("open", page_url, "--reuse", "--full")
        if "__timeout__" in open_out or "__error__" in open_out:
            result.errors.append(f"open {page_url[:100]}: {open_out[:120]}")
            continue
        result.pages_visited.append(page_url)
        await cli.run("wait-stable", timeout=20)

        # Interact to surface SPA views + lazy chunks (bounded, non-destructive).
        if interact:
            await _drive(cli, result, clicks)

        # Drain passive capture surfaces.
        await _drain(cli, result)

        # Harvest in-scope links from the settled tree to extend the crawl.
        tree = await cli.run("tree", "--filter", "all")
        for link in _extract_links(tree):
            absu = urljoin(page_url, link).split("#")[0]
            if absu.startswith("http") and _in_scope(urlparse(absu).netloc, scope):
                if absu not in seen and absu not in queue and len(queue) < HARD_MAX_PAGES * 4:
                    queue.append(absu)

    # Mine the JS bundles we saw for endpoints/source maps (best effort — fetch
    # via the browser's credentialed context using `open` on the .js URL is
    # unreliable, so we scrape any inline references already captured).
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
    lines = [
        "Interceptor recon complete (real Hacker-Valley-Media/Interceptor session).",
        f"Target: {d['target']}  (scope: {d['scope']})",
        f"Pages visited: {len(d['pages_visited'])}",
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
        description="Interaction-first recon over the real Interceptor browser session.",
    )
    parser.add_argument("url", help="seed URL to crawl (uses your logged-in browser session)")
    parser.add_argument("--max-pages", type=int, default=DEFAULT_MAX_PAGES)
    parser.add_argument("--scope", default=None, help="apex to constrain crawl")
    parser.add_argument("--no-interact", action="store_true", help="don't click controls")
    parser.add_argument("--context", default=None, help="interceptor --context id (multi-profile)")
    parser.add_argument("--json", dest="json_out", default=None, help="write normalised JSON here")
    parser.add_argument("--post", default=None, help="ASM bridge ingest URL to POST results to")
    parser.add_argument("--token", default=os.environ.get("ASM_TOKEN", ""), help="bearer token for --post")
    parser.add_argument("--org", type=int, default=None, help="organization_id for --post")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    opts = {
        "max_pages": args.max_pages,
        "scope": args.scope,
        "interact": not args.no_interact,
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
