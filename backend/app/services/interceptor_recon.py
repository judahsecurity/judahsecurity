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

DEFAULT_MAX_PAGES = 25  # assessment-grade; skill allows up to ~80 for deep SPA
HARD_MAX_PAGES = 80  # Interceptor Windows skill deep-SPA guidance
DEFAULT_CLICKS_PER_PAGE = 14
DEFAULT_SPIDER_DEPTH = 3
HARD_MAX_DEPTH = 6
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


async def _emit_progress(thought: str) -> None:
    """Push thinking heartbeats so the agent UI stays alive mid-crawl."""
    try:
        from app.services.agent.orchestrator import _status_callback_var

        cb = _status_callback_var.get(None)
        if not cb:
            return
        msg = {"type": "thinking", "phase": "informational", "thought": thought[:500]}
        maybe = cb(msg)
        if asyncio.iscoroutine(maybe):
            await maybe
    except Exception:
        pass


def _func_score(url: str) -> int:
    try:
        from app.services.deep_crawl_service import _functionality_score

        return int(_functionality_score(url))
    except Exception:
        return 0


def _enqueue_priority(
    queue: List[tuple],
    seen: Set[str],
    url: str,
    depth: int,
    max_depth: int,
    max_queue: int,
) -> None:
    if depth > max_depth:
        return
    norm = url.split("#")[0]
    if not norm.startswith("http") or norm in seen:
        return
    if any(norm == item[2] for item in queue):
        return
    if len(queue) >= max_queue:
        return
    score = _func_score(norm)
    if score < -50:
        return
    queue.append((-score, depth, norm))
    queue.sort(key=lambda t: (t[0], t[1]))


@dataclass
class ReconResult:
    """Normalised recon surface — the shared contract with deep_crawl."""
    target: str = ""
    scope: str = ""
    engine: str = "interceptor"  # interceptor_spider | interceptor_verbs | interceptor
    coverage: Optional[str] = None  # EXHAUSTIVE | PARTIAL (native spider)
    pages_visited: List[str] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    js_files: Set[str] = field(default_factory=set)
    source_maps: Set[str] = field(default_factory=set)
    api_calls: Dict[str, Set[str]] = field(default_factory=dict)  # host -> {"METHOD path"}
    third_party: Set[str] = field(default_factory=set)
    websockets: Set[str] = field(default_factory=set)
    sse: Set[str] = field(default_factory=set)
    endpoints_from_js: Set[str] = field(default_factory=set)
    auth_headers: List[str] = field(default_factory=list)  # names only (CSRF/auth surface)
    login_plan: Optional[str] = None  # name of a replayed recorded login, if any
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
            text = (out or b"").decode("utf-8", errors="replace")
            if proc.returncode:
                return f"__error__ exit {proc.returncode}: {text}"
            return text
        except asyncio.TimeoutError:
            return f"__timeout__ after {timeout}s: {' '.join(args)}"
        except FileNotFoundError:
            raise
        except Exception as e:  # pragma: no cover - defensive
            return f"__error__ {e}: {' '.join(args)}"

    @staticmethod
    def status_is_reachable(out: str) -> bool:
        """True only when verbose status proves browser command delivery."""
        low = out.lower()
        if "not reachable" in low or "__error__" in low or "__timeout__" in low:
            return False
        # Current Interceptor builds always expose an explicit extension row in
        # verbose status. A mode line alone only proves that the CLI is installed;
        # it does not prove that browser commands can be served.
        if re.search(r"^extension:\s+reachable\b", low, re.MULTILINE):
            return True
        if re.search(r"^extension:\s+", low, re.MULTILINE):
            return False
        # Compatibility with older builds that predate the extension row.
        return "context" in low and "reachable" in low

    async def reachable(self) -> bool:
        """True if the daemon + extension can serve browser commands."""
        out = await self.run("status", "--verbose", timeout=15)
        return self.status_is_reachable(out)


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
        await _collect_loaded_scripts(cli, result)
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
    try:
        max_depth = int(opts.get("depth", DEFAULT_SPIDER_DEPTH) or DEFAULT_SPIDER_DEPTH)
    except (TypeError, ValueError):
        max_depth = DEFAULT_SPIDER_DEPTH
    max_depth = max(1, min(max_depth, HARD_MAX_DEPTH))
    interact = bool(opts.get("interact", True))
    clicks = int(
        opts.get("max_clicks")
        or opts.get("clicks_per_page", DEFAULT_CLICKS_PER_PAGE)
        or DEFAULT_CLICKS_PER_PAGE
    )
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
    if opts.get("login_plan"):
        await replay_login_plan(cli, str(opts["login_plan"]), result)
    await _emit_progress(
        f"interceptor: starting pentester crawl depth={max_depth} "
        f"max_pages={max_pages} interact={interact}"
    )

    if prefer_spider and await supports_spider(cli):
        ok = await _run_native_spider(cli, url, opts, result, max_pages)
        if ok:
            await _emit_progress(
                f"interceptor spider done — {len(result.pages_visited)} pages, "
                f"{sum(len(v) for v in result.api_calls.values())} API calls"
            )
            return result
        result.errors.append("native spider produced no pages; falling back to verb-loop crawl")
        result.engine = "interceptor"
        result.pages_visited = []
        result.forms = []
        result.js_files = set()
        result.source_maps = set()
        result.api_calls = {}
        result.third_party = set()
        result.websockets = set()
        result.sse = set()
        result.endpoints_from_js = set()
        result.coverage = None

    # Verb-loop fallback — functionality-first priority queue (interaction primary).
    result.engine = "interceptor_verbs"
    queue: List[tuple] = [(-_func_score(url), 0, url)]
    seen: Set[str] = set()

    while queue and len(result.pages_visited) < max_pages:
        _score, depth, page_url = queue.pop(0)
        page_url = page_url.split("#")[0]
        if page_url in seen:
            continue
        seen.add(page_url)

        open_out = await cli.run("open", page_url, "--reuse", "--full")
        if "__timeout__" in open_out or "__error__" in open_out:
            result.errors.append(f"open {page_url[:100]}: {open_out[:120]}")
            continue
        result.pages_visited.append(page_url)
        page_score = _func_score(page_url)
        await _emit_progress(
            f"interceptor: page {len(result.pages_visited)}/{max_pages} "
            f"depth={depth}/{max_depth} score={page_score} — {page_url[:140]}"
        )
        await cli.run("wait-stable", timeout=20)

        click_budget = clicks + (6 if page_score >= 40 else 0)
        if interact:
            await _drive(cli, result, click_budget)

        await _drain(cli, result)
        try:
            await _collect_loaded_scripts(cli, result)
        except Exception as e:
            result.errors.append(f"script enumeration {page_url[:80]}: {str(e)[:100]}")

        tree = await cli.run("tree", "--filter", "all")
        _harvest_forms(tree, page_url, result)
        child_depth = depth + 1
        for link in _extract_links(tree):
            absu = urljoin(page_url, link).split("#")[0]
            if absu.startswith("http") and _in_scope(urlparse(absu).netloc, scope):
                _enqueue_priority(
                    queue, seen, absu, child_depth, max_depth, HARD_MAX_PAGES * 4
                )

    await _mine_headers(cli, result)
    await _emit_progress(
        f"interceptor verb-loop done — {len(result.pages_visited)} pages, "
        f"{len(result.forms)} forms"
    )
    return result


async def _drive(cli: InterceptorCLI, result: ReconResult, clicks: int) -> None:
    """Scroll + click a bounded set of safe controls to trigger lazy loads."""
    for _ in range(4):
        await cli.run("scroll", "down", timeout=15)
        await asyncio.sleep(0.2)
    await cli.run("scroll", "top", timeout=15)

    tree = await cli.run("tree")
    refs = _extract_clickable_refs(tree)
    # Prefer functionality-shaped labels (login, demo, product, nav) first.
    def _label_rank(item: tuple) -> int:
        label = (item[1] or "").lower()
        if re.search(r"log\s?in|sign\s?in|demo|product|pricing|contact|account|dashboard|api|docs", label):
            return 0
        if re.search(r"menu|nav|tab|more|learn|feature", label):
            return 1
        return 2

    refs.sort(key=_label_rank)
    done = 0
    for ref, label in refs:
        if done >= clicks:
            break
        if label and _DESTRUCTIVE_TEXT.search(label):
            continue
        await cli.run("act", ref, "--no-read", timeout=20)
        done += 1
        await asyncio.sleep(0.2)
        if done % 4 == 0:
            await _drain(cli, result)


def _harvest_forms(tree_text: str, page_url: str, result: ReconResult) -> None:
    """Best-effort form signals from the accessibility/DOM tree dump."""
    if not tree_text or len(result.forms) >= 60:
        return
    low = tree_text.lower()
    has_form = bool(re.search(r"\bform\b|role[=:]?\s*form", low))
    has_password = "password" in low
    has_email = bool(re.search(r"\b(email|e-mail|username|user)\b", low))
    has_search = bool(re.search(r"\b(search|query)\b", low))
    if not (has_form or has_password or (has_email and "input" in low) or has_search):
        return
    inputs: List[str] = []
    if has_password:
        inputs.extend(["password", "username" if has_email else "email"])
    elif has_email:
        inputs.append("email")
    if has_search:
        inputs.append("q")
    for m in re.finditer(r'name\s*[:=]\s*["\']?([A-Za-z0-9_\-]{1,40})', tree_text):
        n = m.group(1)
        if n not in inputs and len(inputs) < 12:
            inputs.append(n)
    kind = "login" if has_password else ("search" if has_search else "form")
    result.forms.append(
        {
            "page": page_url,
            "method": "POST" if has_password else "GET",
            "kind": kind,
            "inputs": inputs[:12],
        }
    )


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


# ``net log`` only records fetch/XHR, never ``<script>`` loads, so bundles and
# lazy chunks must be read from the page itself. Resource timing also catches
# chunks injected after interaction; ``document.scripts`` catches cached ones.
_LOADED_SCRIPTS_JS = (
    "JSON.stringify([...new Set(["
    "...performance.getEntriesByType('resource')"
    ".filter(e=>e.initiatorType==='script'||/\\.m?js(\\?|$)/.test(e.name))"
    ".map(e=>e.name),"
    "...[...document.scripts].map(s=>s.src).filter(Boolean)"
    "])])"
)
_CSP_BLOCK_RE = re.compile(r"content security policy|unsafe-eval|evalerror", re.I)


def _parse_script_urls(out: str) -> List[str]:
    """Return URLs from the first JSON string array in an ``eval`` dump."""
    text = out or ""
    start = text.find("[")
    while start >= 0:
        end = text.find("]", start)
        if end < 0:
            break
        try:
            data = json.loads(text[start : end + 1])
        except (json.JSONDecodeError, ValueError):
            start = text.find("[", start + 1)
            continue
        if isinstance(data, list):
            return [u for u in data if isinstance(u, str) and u.startswith("http")]
        break
    return []


def _add_loaded_scripts(urls: List[str], result: ReconResult) -> int:
    added = 0
    for raw in urls:
        url = raw.split("#")[0].split("?")[0]
        host = urlparse(url).netloc
        if not host or not re.search(r"\.m?js$", url, re.I):
            continue
        if not _in_scope(host, result.scope):
            result.third_party.add(host)
            continue
        if url not in result.js_files:
            result.js_files.add(url)
            added += 1
    return added


async def _collect_loaded_scripts(cli: InterceptorCLI, result: ReconResult) -> int:
    """Add first-party scripts the current tab loaded; return how many were new.

    Tries the isolated world first. A strict CSP without ``'unsafe-eval'`` blocks
    that, so retry once in the page's own world (``--main``), which is exempt.
    The expression only reads timing entries and script ``src`` attributes.
    """
    out = await cli.run("eval", _LOADED_SCRIPTS_JS, timeout=20)
    urls = _parse_script_urls(out)
    if not urls and (_CSP_BLOCK_RE.search(out or "") or "__error__" in (out or "")):
        out = await cli.run("eval", _LOADED_SCRIPTS_JS, "--main", timeout=20)
        urls = _parse_script_urls(out)
    return _add_loaded_scripts(urls, result)


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
        "forms": list(result.forms)[:60],
        "js_files": sorted(result.js_files),
        "source_maps": sorted(result.source_maps),
        "api_calls": {h: sorted(v) for h, v in result.api_calls.items()},
        "third_party": sorted(result.third_party),
        "websockets": sorted(result.websockets),
        "sse": sorted(result.sse),
        "endpoints_from_js": sorted(result.endpoints_from_js),
        "auth_headers": result.auth_headers,
        "login_plan": result.login_plan,
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
        f"Forms observed: {len(d.get('forms') or [])}",
    ]
    if d.get("login_plan"):
        lines.append(f"Authenticated via recorded login plan: {d['login_plan']}")
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


# ---------------------------------------------------------------------------
# Recorded login replay
# ---------------------------------------------------------------------------
# An analyst records a login once (``interceptor monitor start`` ... ``stop``),
# exports it with ``interceptor monitor export <sid> --plan`` and saves it on the
# worker host as ``$INTERCEPTOR_LOGIN_PLAN_DIR/<name>.plan``. Jobs reference the
# plan by name only, so credentials in the plan never transit the ASM API or DB.
_PLAN_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
# Navigation and form input only — no eval, overrides, header/cookie rules,
# CDP network control, native macOS input, or other bridges.
_PLAN_VERBS = {
    "open", "navigate", "act", "click", "type", "select", "keys", "focus",
    "hover", "scroll", "wait", "wait-stable", "find", "read", "tree", "back", "forward",
}
_PLAN_URL_VERBS = {"open", "navigate"}
_PLAN_PREFIXES = {"interceptor", "$intc", '"$intc"', "${intc}"}
MAX_PLAN_STEPS = 40


def login_plan_dir() -> str:
    return os.environ.get("INTERCEPTOR_LOGIN_PLAN_DIR") or os.path.expanduser("~/.interceptor-plans")


def parse_login_plan(text: str, scope: str) -> List[List[str]]:
    """Validate an exported plan; return argv steps or raise ``ValueError``."""
    import shlex

    steps: List[List[str]] = []
    for lineno, line in enumerate((text or "").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            argv = shlex.split(line)
        except ValueError as exc:
            raise ValueError(f"line {lineno}: {exc}") from exc
        if argv and argv[0].lower() in _PLAN_PREFIXES:
            argv = argv[1:]
        if not argv:
            continue
        verb = argv[0].lower()
        if verb not in _PLAN_VERBS:
            raise ValueError(f"line {lineno}: '{argv[0]}' is not allowed in a login plan")
        if any(a in ("--any-tab", "--os", "--main") for a in argv[1:]):
            raise ValueError(f"line {lineno}: flag not allowed in a login plan")
        if verb in _PLAN_URL_VERBS:
            urls = [a for a in argv[1:] if not a.startswith("-")]
            if not urls:
                raise ValueError(f"line {lineno}: {verb} needs a URL")
            parsed = urlparse(urls[0])
            if parsed.scheme not in ("http", "https") or not _in_scope(parsed.hostname or "", scope):
                raise ValueError(f"line {lineno}: {urls[0][:80]} is outside scope {scope}")
        steps.append(argv)
        if len(steps) > MAX_PLAN_STEPS:
            raise ValueError(f"plan exceeds {MAX_PLAN_STEPS} steps")
    if not steps or steps[0][0].lower() not in _PLAN_URL_VERBS:
        raise ValueError("plan must start with an in-scope open/navigate")
    return steps


async def replay_login_plan(cli: InterceptorCLI, name: str, result: ReconResult) -> bool:
    """Replay a recorded login before the crawl. Failure is noted, never fatal."""
    if not _PLAN_NAME_RE.match(name or ""):
        result.errors.append("login plan: invalid name")
        return False
    path = os.path.join(login_plan_dir(), f"{name}.plan")
    try:
        with open(path, encoding="utf-8") as fh:
            steps = parse_login_plan(fh.read(), result.scope)
    except FileNotFoundError:
        result.errors.append(f"login plan '{name}' not found on this worker")
        return False
    except ValueError as exc:
        result.errors.append(f"login plan '{name}' rejected: {exc}")
        return False
    for index, argv in enumerate(steps, 1):
        out = await cli.run(*argv, timeout=45)
        if "__timeout__" in out or "__error__" in out[:80]:
            # Never echo step output: it may contain typed credentials.
            result.errors.append(f"login plan '{name}' stopped at step {index}/{len(steps)} ({argv[0]})")
            return False
    await cli.run("wait-stable", timeout=20)
    result.login_plan = name
    await _emit_progress(f"interceptor: replayed login plan '{name}' ({len(steps)} steps)")
    return True


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
    parser.add_argument("--login-plan", default=None,
                        help="replay $INTERCEPTOR_LOGIN_PLAN_DIR/<name>.plan before crawling")
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
        "login_plan": args.login_plan,
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
