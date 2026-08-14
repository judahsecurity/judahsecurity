"""
Deep Crawl Service — Interceptor-style interaction-first web recon.

Inspired by Hacker-Valley-Media/Interceptor. Where CDN/WAF-fronted apps and
single-page apps hide most of their attack surface behind JavaScript that only
loads in response to user interaction, a plain HTTP crawler (katana, gau,
waybackurls) sees only the initial HTML. This service instead drives a real
Chromium tab the way a human would — scroll, expand menus/`<details>`, click
tabs and safe buttons, then follow in-page links — so the site's own JS loads
its lazy chunks, preloads, and SPA route bundles through normal fetches.

While that happens we *passively* capture the full client-side traffic using
only standard Web APIs (no CDP/debugger footprint):

    fetch() · XMLHttpRequest · EventSource (SSE) · WebSocket ·
    navigator.sendBeacon · BroadcastChannel

plus Playwright's own request/response/websocket events. Every JS bundle that
loads is recorded, fetched with the browser's credentialed context, and mined
for API endpoints, routes, params, and source maps that scanners miss.

The result is a structured map of the *real* attack surface:
    - first-party API endpoints (method + URL + params), grouped by host
    - third-party / out-of-scope calls
    - WebSocket + SSE channels
    - JS files and source maps
    - forms and their inputs

This is read-only reconnaissance: it never submits forms or clicks
state-mutating controls (logout/delete/pay/submit are filtered out).

Runs on headless Linux/Ubuntu servers (Playwright + Chromium are baked into the
Docker images). To look like a *normal user* rather than a bot, the crawl:
    - masks the common headless/automation fingerprints (navigator.webdriver,
      missing plugins/languages, headless UA, WebGL vendor, permissions quirks)
    - sends realistic client hints, Accept-Language, locale, timezone, and a
      real desktop Chrome User-Agent
    - moves the mouse, scrolls in irregular steps, and pauses like a human

It can also crawl *as a logged-in user*. Pass any of these (JSON args):
    cookies        list[dict]  — Playwright cookie objects (name/value/domain/…)
    storage_state  dict|str    — Playwright storage_state object or a file path
    headers        dict        — extra HTTP headers (e.g. Authorization: Bearer …)
    basic_auth     dict        — {"username": ..., "password": ...} (HTTP Basic)
    local_storage  dict        — {origin: {key: value}} seeded before navigation
    user_agent     str         — override the default desktop Chrome UA
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import re
import shutil
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)


async def _emit_crawl_progress(thought: str) -> None:
    """Push a thinking heartbeat so the agent UI does not idle-timeout mid-crawl."""
    try:
        from app.services.agent.orchestrator import _status_callback_var

        cb = _status_callback_var.get(None)
        if not cb:
            return
        msg = {
            "type": "thinking",
            "phase": "informational",
            "thought": thought[:500],
        }
        maybe = cb(msg)
        if asyncio.iscoroutine(maybe):
            await maybe
    except Exception:
        pass

# Common launch flags — safe under both root (scanner, user 0:0) and non-root
# (backend appuser) containers.
_LAUNCH_ARGS = [
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-dev-shm-usage",
    "--headless=new",
    "--disable-blink-features=AutomationControlled",
    "--disable-features=IsolateOrigins,site-per-process",
    "--window-size=1920,1080",
    "--start-maximized",
    "--lang=en-US",
]

# System Chromium candidates, tried when Playwright's managed browser is absent
# (e.g. a cloud build where `playwright install` was skipped/failed). The apt
# `chromium` package is installed in both Docker images, so one of these exists.
_SYSTEM_CHROMIUM_CANDIDATES = [
    os.environ.get("CHROME_BIN", ""),
    os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE", ""),
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
]


def _find_system_chromium() -> Optional[str]:
    """Return the path to a system-installed Chromium/Chrome, if any."""
    for cand in _SYSTEM_CHROMIUM_CANDIDATES:
        if cand and os.path.exists(cand) and os.access(cand, os.X_OK):
            return cand
    for name in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
        found = shutil.which(name)
        if found:
            return found
    return None


async def _launch_chromium(pw):
    """
    Launch Chromium, resilient to a missing Playwright-managed browser.

    Cloud builds sometimes skip `playwright install` (the Dockerfile guards it
    with `|| true`). When the managed browser isn't there, fall back to the
    system Chromium the images always apt-install. Raises RuntimeError with an
    actionable message if neither is available.
    """
    try:
        return await pw.chromium.launch(headless=True, args=_LAUNCH_ARGS)
    except Exception as managed_err:
        sys_chrome = _find_system_chromium()
        if not sys_chrome:
            raise RuntimeError(
                "No usable Chromium. Playwright's managed browser failed to launch "
                f"({str(managed_err)[:160]}) and no system Chromium was found. In the "
                "image, ensure either `playwright install chromium` succeeded or the "
                "`chromium` apt package is present (set CHROME_BIN to override)."
            )
        logger.warning(
            "Playwright-managed Chromium unavailable (%s); using system Chromium at %s",
            str(managed_err)[:120], sys_chrome,
        )
        return await pw.chromium.launch(
            headless=True, args=_LAUNCH_ARGS, executable_path=sys_chrome,
        )

# Bounds — keep a single crawl cheap and predictable for agent sessions.
DEFAULT_MAX_PAGES = 10
HARD_MAX_PAGES = 20
DEFAULT_MAX_CLICKS = 12
PAGE_TIMEOUT_MS = 20000
SETTLE_MS = 800
MAX_JS_FETCH = 25
MAX_JS_BYTES = 2_000_000
MAX_CAPTURED_CALLS = 4000
# Hard wall-clock for one deep_crawl (agent must not block for an hour).
CRAWL_BUDGET_SEC = int(os.environ.get("DEEP_CRAWL_BUDGET_SEC", "600") or "600")

# Text on a control that means "do not click" — avoids state changes / logout.
_DESTRUCTIVE_TEXT = re.compile(
    r"(log\s?out|sign\s?out|delete|remove|destroy|deactivate|"
    r"pay|purchase|checkout|buy|order|confirm|submit|save|"
    r"unsubscribe|cancel\s?subscription|reset|wipe)",
    re.IGNORECASE,
)

# Endpoint extraction (kept consistent with js_recon_service).
_ENDPOINT_PATTERN = re.compile(
    r"""(?xi)
    (?:["'`])
    (
        (?:https?://[^\s"'`<>]+)
        |
        (?:/[A-Za-z0-9_\-/.?=&%#]{3,200})
    )
    (?:["'`])
    """
)
_SOURCEMAP_PATTERN = re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*([^\s]+)", re.IGNORECASE)

# Default desktop Chrome identity — kept in sync with the client hints below so
# the UA string and Sec-CH-UA headers tell the same story (mismatches are a
# classic bot tell).
_CHROME_MAJOR = "124"
_DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    f"(KHTML, like Gecko) Chrome/{_CHROME_MAJOR}.0.0.0 Safari/537.36"
)
_DEFAULT_HEADERS = {
    "Accept-Language": "en-US,en;q=0.9",
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,image/apng,*/*;q=0.8"
    ),
    "sec-ch-ua": f'"Chromium";v="{_CHROME_MAJOR}", "Google Chrome";v="{_CHROME_MAJOR}", "Not-A.Brand";v="99"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "Upgrade-Insecure-Requests": "1",
}

# Runs before any page script (document_start, MAIN world). Neutralises the
# fingerprints that headless Chromium leaks so anti-automation checks that gate
# content behind "is this a real browser?" let the crawl through.
_STEALTH = r"""
(() => {
  try {
    // navigator.webdriver -> undefined (the #1 headless tell)
    Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
  } catch (e) {}
  try {
    // Real browsers report languages
    Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
  } catch (e) {}
  try {
    // Non-empty plugins/mimeTypes array shape
    const fake = [1, 2, 3, 4, 5];
    Object.defineProperty(navigator, 'plugins', { get: () => fake });
  } catch (e) {}
  try {
    // window.chrome runtime object present in real Chrome
    if (!window.chrome) { window.chrome = {}; }
    if (!window.chrome.runtime) { window.chrome.runtime = {}; }
  } catch (e) {}
  try {
    // Notification permission query shouldn't reveal automation
    const orig = navigator.permissions && navigator.permissions.query;
    if (orig) {
      navigator.permissions.query = (p) =>
        p && p.name === 'notifications'
          ? Promise.resolve({ state: Notification.permission })
          : orig(p);
    }
  } catch (e) {}
  try {
    // Spoof a plausible GPU vendor/renderer instead of "Google SwiftShader"
    const getParam = WebGLRenderingContext.prototype.getParameter;
    WebGLRenderingContext.prototype.getParameter = function (p) {
      if (p === 37445) return 'Intel Inc.';                 // UNMASKED_VENDOR_WEBGL
      if (p === 37446) return 'Intel Iris OpenGL Engine';   // UNMASKED_RENDERER_WEBGL
      return getParam.call(this, p);
    };
  } catch (e) {}
  try {
    // hardwareConcurrency / deviceMemory in a normal desktop range
    Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8 });
    Object.defineProperty(navigator, 'deviceMemory', { get: () => 8 });
  } catch (e) {}
})();
"""

# Injected into every frame before any page script runs. Instruments the
# standard client-side networking primitives and records each call into a
# window-scoped ring buffer we drain after interaction.
_INSTRUMENTATION = r"""
(() => {
  if (window.__interceptor_installed) return;
  window.__interceptor_installed = true;
  window.__interceptor_calls = [];
  const MAX = 4000;
  const rec = (o) => {
    try {
      if (window.__interceptor_calls.length < MAX) {
        o.ts = Date.now();
        window.__interceptor_calls.push(o);
      }
    } catch (e) {}
  };
  // fetch()
  try {
    const _fetch = window.fetch;
    window.fetch = function (input, init) {
      try {
        const url = (typeof input === 'string') ? input : (input && input.url) || '';
        const method = (init && init.method) || (input && input.method) || 'GET';
        rec({ kind: 'fetch', method: String(method).toUpperCase(), url: String(url) });
      } catch (e) {}
      return _fetch.apply(this, arguments);
    };
  } catch (e) {}
  // XMLHttpRequest
  try {
    const _open = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (method, url) {
      try { rec({ kind: 'xhr', method: String(method || 'GET').toUpperCase(), url: String(url || '') }); } catch (e) {}
      return _open.apply(this, arguments);
    };
  } catch (e) {}
  // navigator.sendBeacon
  try {
    const _beacon = navigator.sendBeacon;
    if (_beacon) {
      navigator.sendBeacon = function (url, data) {
        try { rec({ kind: 'beacon', method: 'POST', url: String(url || '') }); } catch (e) {}
        return _beacon.apply(this, arguments);
      };
    }
  } catch (e) {}
  // EventSource (SSE)
  try {
    const _ES = window.EventSource;
    if (_ES) {
      window.EventSource = function (url, cfg) {
        try { rec({ kind: 'sse', method: 'GET', url: String(url || '') }); } catch (e) {}
        return new _ES(url, cfg);
      };
      window.EventSource.prototype = _ES.prototype;
    }
  } catch (e) {}
  // WebSocket
  try {
    const _WS = window.WebSocket;
    if (_WS) {
      window.WebSocket = function (url, protocols) {
        try { rec({ kind: 'websocket', method: 'WS', url: String(url || '') }); } catch (e) {}
        return new _WS(url, protocols);
      };
      window.WebSocket.prototype = _WS.prototype;
    }
  } catch (e) {}
  // BroadcastChannel
  try {
    const _BC = window.BroadcastChannel;
    if (_BC) {
      window.BroadcastChannel = function (name) {
        try { rec({ kind: 'broadcast', method: '-', url: 'channel:' + String(name || '') }); } catch (e) {}
        return new _BC(name);
      };
    }
  } catch (e) {}
})();
"""


@dataclass
class CrawlResult:
    target: str = ""
    scope: str = ""
    authenticated: Optional[bool] = None
    pages_visited: List[str] = field(default_factory=list)
    js_files: Set[str] = field(default_factory=set)
    source_maps: Set[str] = field(default_factory=set)
    # host -> {"METHOD path" : True}
    api_calls: Dict[str, Set[str]] = field(default_factory=dict)
    third_party: Set[str] = field(default_factory=set)
    websockets: Set[str] = field(default_factory=set)
    sse: Set[str] = field(default_factory=set)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    endpoints_from_js: Set[str] = field(default_factory=set)
    errors: List[str] = field(default_factory=list)
    # Playwright storage_state for authenticated handoff (cookies + origins)
    storage_state: Optional[Dict[str, Any]] = None
    # Sample first-party XHR for replay (method/url/headers/postData)
    api_samples: List[Dict[str, Any]] = field(default_factory=list)


def _check_playwright() -> bool:
    try:
        from playwright.async_api import async_playwright  # noqa: F401
        return True
    except ImportError:
        return False


def _managed_browser_present() -> bool:
    """True if a Playwright-managed Chromium appears installed on disk."""
    base = os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "").strip()
    candidates = [base] if base else []
    candidates.append(os.path.expanduser("~/.cache/ms-playwright"))
    for path in candidates:
        try:
            if path and os.path.isdir(path):
                if any(name.startswith("chromium") for name in os.listdir(path)):
                    return True
        except Exception:
            continue
    return False


def _apex(host: str) -> str:
    """Best-effort registrable apex (last two labels)."""
    parts = (host or "").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host or ""


def _in_scope(host: str, scope_apex: str) -> bool:
    if not host or not scope_apex:
        return False
    host = host.lower()
    return host == scope_apex or host.endswith("." + scope_apex)


def _resolve_secret(value: Any) -> Optional[str]:
    """
    Resolve a credential that may be a literal, an env reference, or a secret.

    So credentials don't have to sit inline in the agent's tool args / trace:
        "env:NAME"    -> os.environ["NAME"]
        "secret:NAME" -> contents of $SECRETS_DIR/NAME (or /run/secrets/NAME —
                         Docker/K8s mounted secrets)
        "file:/path"  -> contents of that file
        anything else -> returned as-is (a literal value)

    Returns None if a reference is given but can't be resolved.
    """
    if value is None:
        return None
    s = str(value)
    if s.startswith("env:"):
        return os.environ.get(s[4:].strip()) or None
    if s.startswith("secret:"):
        name = s[7:].strip()
        base = os.environ.get("SECRETS_DIR", "").strip() or "/run/secrets"
        path = os.path.join(base, name)
        try:
            return open(path, encoding="utf-8").read().strip() if os.path.isfile(path) else None
        except Exception:
            return None
    if s.startswith("file:"):
        path = s[5:].strip()
        try:
            return open(path, encoding="utf-8").read().strip() if os.path.isfile(path) else None
        except Exception:
            return None
    return s


def _load_storage_state(value: Any) -> Optional[Any]:
    """storage_state may be a dict, a JSON string, or a path to a JSON file."""
    if not value:
        return None
    if isinstance(value, dict):
        return value
    s = str(value).strip()
    if not s:
        return None
    # Inline JSON?
    if s.startswith("{"):
        try:
            return json.loads(s)
        except (json.JSONDecodeError, TypeError):
            return None
    # Otherwise treat as a file path Playwright can read directly.
    try:
        return s if os.path.isfile(s) else None
    except Exception:
        return None


def _build_context_kwargs(opts: Dict[str, Any]) -> Dict[str, Any]:
    """Assemble new_context() kwargs for a realistic, optionally authed session."""
    ua = str(opts.get("user_agent") or "").strip() or _DEFAULT_UA

    extra_headers = dict(_DEFAULT_HEADERS)
    caller_headers = opts.get("headers")
    if isinstance(caller_headers, dict):
        # Caller headers (e.g. Authorization) win over defaults. Values may be
        # env:/secret:/file: references so tokens don't sit inline in the trace.
        for k, v in caller_headers.items():
            if k and v is not None:
                resolved = _resolve_secret(v)
                if resolved is not None:
                    extra_headers[str(k)] = str(resolved)

    kwargs: Dict[str, Any] = {
        "viewport": {"width": 1366, "height": 768},
        "screen": {"width": 1920, "height": 1080},
        "device_scale_factor": 1,
        "is_mobile": False,
        "has_touch": False,
        "locale": str(opts.get("locale") or "en-US"),
        "timezone_id": str(opts.get("timezone") or "America/New_York"),
        "ignore_https_errors": True,
        "user_agent": ua,
        "extra_http_headers": extra_headers,
    }

    basic = opts.get("basic_auth")
    if isinstance(basic, dict) and basic.get("username"):
        kwargs["http_credentials"] = {
            "username": str(_resolve_secret(basic.get("username")) or ""),
            "password": str(_resolve_secret(basic.get("password")) or ""),
        }

    storage = _load_storage_state(opts.get("storage_state"))
    if storage is not None:
        kwargs["storage_state"] = storage

    return kwargs


def _parse_args(args: Any) -> Dict[str, Any]:
    """Accept a bare URL string or a JSON object."""
    if isinstance(args, dict):
        return args
    s = str(args or "").strip()
    if not s:
        return {}
    if s.startswith("{"):
        try:
            return json.loads(s)
        except (json.JSONDecodeError, TypeError):
            return {"url": s}
    return {"url": s}


async def run_deep_crawl(args: Any) -> Dict[str, Any]:
    """
    Interaction-first crawl with passive client-side traffic capture.

    Args (bare URL string, or JSON object):
        url        (str, required) — seed URL/host to crawl
        max_pages  (int)  — in-scope pages to visit (default 10, cap 20)
        interact   (bool) — click safe tabs/menus/buttons (default True)
        scope      (str)  — apex to constrain crawl (default: derived from url)
        capture_js (bool) — fetch + mine JS bundles for endpoints (default True)
        timeout_ms (int)  — per-page navigation timeout (default 20000)
        budget_sec (int)  — hard wall-clock for the whole crawl (default 600)

    Authenticated / normal-user session (all optional):
        cookies       (list[dict]) — Playwright cookie objects
        storage_state (dict|str)   — Playwright storage_state (object or file path)
        headers       (dict)       — extra HTTP headers (e.g. Authorization)
        basic_auth    (dict)       — {"username", "password"} for HTTP Basic
        local_storage (dict)       — {origin: {key: value}} seeded pre-navigation
        user_agent    (str)        — override the desktop Chrome UA
        locale        (str)        — default "en-US"
        timezone      (str)        — default "America/New_York"

    Self-service login (optional) — the crawler logs itself in, no cookies needed:
        login (dict) with:
            url                 (str, required)  — login page URL
            username            (str, required)  — literal or env:/secret:/file: ref
            password            (str, required)  — literal or env:/secret:/file: ref
            username_env        (str, optional)  — env var name to read username from
            password_env        (str, optional)  — env var name to read password from
            username_selector   (str, optional)  — auto-detected if omitted
            password_selector   (str, optional)  — auto-detected if omitted
            submit_selector     (str, optional)  — auto-detected / Enter if omitted
            extra_fields        (dict, optional)  — {selector: value} (tenant/otp/…)
            success_url         (str, optional)  — substring expected in URL after login
            success_selector    (str, optional)  — element expected after login

    Credential references (keep secrets out of the agent trace) — usable for
    login username/password, extra_fields values, basic_auth, and header values:
        "env:NAME"    read from environment variable NAME
        "secret:NAME" read from $SECRETS_DIR/NAME (default /run/secrets/NAME)
        "file:/path"  read from a file

    Returns the ASM tool envelope: {success, output, error, exit_code}.
    """
    if not _check_playwright():
        return {
            "success": False,
            "output": "Playwright not installed. Run: pip install playwright && playwright install chromium",
            "error": "playwright_not_available",
            "exit_code": -1,
        }
    if not _find_system_chromium() and not _managed_browser_present():
        logger.warning(
            "No system Chromium detected and Playwright browser dir looks empty; "
            "launch will attempt the managed browser and surface a clear error if missing."
        )

    opts = _parse_args(args)
    seed = str(opts.get("url") or opts.get("target") or "").strip()
    if not seed:
        return {
            "success": False,
            "output": "No target. Pass a URL, e.g. execute_deep_crawl(args=\"https://target.com\").",
            "error": "no_target",
            "exit_code": 1,
        }
    if not seed.startswith("http"):
        seed = f"https://{seed}"

    max_pages = min(int(opts.get("max_pages", DEFAULT_MAX_PAGES) or DEFAULT_MAX_PAGES), HARD_MAX_PAGES)
    interact = bool(opts.get("interact", True))
    capture_js = bool(opts.get("capture_js", True))
    timeout_ms = int(opts.get("timeout_ms", PAGE_TIMEOUT_MS) or PAGE_TIMEOUT_MS)
    try:
        budget_sec = int(opts.get("budget_sec", CRAWL_BUDGET_SEC) or CRAWL_BUDGET_SEC)
    except (TypeError, ValueError):
        budget_sec = CRAWL_BUDGET_SEC
    budget_sec = max(60, min(budget_sec, 1800))  # 1–30 minutes
    crawl_deadline = time.monotonic() + budget_sec

    seed_host = urlparse(seed).netloc
    scope_apex = str(opts.get("scope") or "").strip().lower() or _apex(seed_host)

    result = CrawlResult(target=seed, scope=scope_apex)

    from playwright.async_api import async_playwright

    def _record_request(method: str, url: str) -> None:
        if not url or url.startswith(("data:", "blob:")):
            return
        try:
            host = urlparse(url).netloc
        except Exception:
            return
        if _in_scope(host, scope_apex):
            path = urlparse(url).path or "/"
            q = urlparse(url).query
            key = f"{method.upper()} {path}" + (f"?{q[:120]}" if q else "")
            result.api_calls.setdefault(host, set()).add(key)
        else:
            if host:
                result.third_party.add(host)

    try:
        async with async_playwright() as pw:
            # --headless=new is far closer to headed Chrome than legacy headless
            # and drops many of the old automation tells (see _LAUNCH_ARGS). Falls
            # back to the system Chromium when the managed browser is missing.
            browser = await _launch_chromium(pw)
            try:
                context = await browser.new_context(**_build_context_kwargs(opts))

                # Seed authenticated cookies, if provided.
                cookies = opts.get("cookies")
                if isinstance(cookies, list) and cookies:
                    try:
                        await context.add_cookies(cookies)
                    except Exception as e:
                        result.errors.append(f"cookies: {str(e)[:120]}")

                # Stealth runs first so page scripts never see the automation
                # tells; instrumentation runs next to capture traffic.
                await context.add_init_script(_STEALTH)
                await context.add_init_script(_INSTRUMENTATION)

                # Seed localStorage (e.g. SPA auth tokens) before navigation.
                local_storage = opts.get("local_storage")
                if isinstance(local_storage, dict) and local_storage:
                    ls_json = json.dumps(local_storage)
                    await context.add_init_script(
                        "(() => { try { const d = " + ls_json + ";"
                        " const o = d[location.origin]; if (o) { for (const k in o)"
                        " localStorage.setItem(k, o[k]); } } catch(e){} })()"
                    )

                page = await context.new_page()

                # Playwright-level passive capture (covers navigations, images,
                # scripts, and any traffic the JS hooks might miss).
                def _on_request(req):
                    try:
                        url = req.url
                        _record_request(req.method, url)
                        rtype = req.resource_type
                        if rtype == "script" or url.split("?")[0].endswith(".js"):
                            if _in_scope(urlparse(url).netloc, scope_apex):
                                result.js_files.add(url.split("?")[0])
                        # Keep a small sample of XHR/fetch for replay_http_request
                        if (
                            rtype in ("xhr", "fetch")
                            and _in_scope(urlparse(url).netloc, scope_apex)
                            and len(result.api_samples) < 40
                        ):
                            headers = {}
                            try:
                                raw_h = req.headers or {}
                                for hk in (
                                    "content-type", "accept", "authorization",
                                    "x-requested-with", "x-csrf-token",
                                ):
                                    if hk in raw_h:
                                        headers[hk] = raw_h[hk][:200]
                            except Exception:
                                pass
                            sample = {
                                "method": req.method,
                                "url": url[:500],
                                "headers": headers,
                            }
                            try:
                                pd = req.post_data
                                if pd:
                                    sample["body"] = pd[:4000]
                            except Exception:
                                pass
                            result.api_samples.append(sample)
                    except Exception:
                        pass

                page.on("request", _on_request)
                page.on("websocket", lambda ws: result.websockets.add(ws.url)
                        if len(result.websockets) < 100 else None)

                # Authenticate first (optional) so the whole crawl runs as a
                # logged-in user. Cookies/localStorage set by the login persist
                # in this context for every subsequent page.
                login = opts.get("login")
                if isinstance(login, dict) and login:
                    authed = await _perform_login(page, login, timeout_ms, result)
                    result.authenticated = authed

                # BFS over in-scope links, seeded from the target.
                queue: List[str] = [seed]
                seen: Set[str] = set()

                while queue and len(result.pages_visited) < max_pages:
                    if time.monotonic() >= crawl_deadline:
                        result.errors.append(
                            f"crawl_budget_exhausted after {budget_sec}s "
                            f"({len(result.pages_visited)}/{max_pages} pages) — returning partial map"
                        )
                        await _emit_crawl_progress(
                            f"deep_crawl: budget exhausted at {len(result.pages_visited)} pages — finishing"
                        )
                        break

                    url = queue.pop(0)
                    norm = url.split("#")[0]
                    if norm in seen:
                        continue
                    seen.add(norm)

                    try:
                        # Cap per-page nav by remaining budget
                        remaining_ms = int(max(3000, (crawl_deadline - time.monotonic()) * 1000))
                        nav_timeout = min(timeout_ms, remaining_ms)
                        await page.goto(url, wait_until="domcontentloaded", timeout=nav_timeout)
                    except Exception as e:
                        result.errors.append(f"nav {url[:120]}: {str(e)[:160]}")
                        continue

                    result.pages_visited.append(page.url)

                    try:
                        await _emit_crawl_progress(
                            f"deep_crawl: page {len(result.pages_visited)}/{max_pages} — {page.url[:160]}"
                        )
                    except Exception:
                        pass

                    try:
                        await _drive_page(page, interact)
                    except Exception as e:
                        result.errors.append(f"interact {url[:80]}: {str(e)[:120]}")

                    # Let lazy fetches settle.
                    await asyncio.sleep(SETTLE_MS / 1000)

                    # Drain the in-page instrumentation buffer.
                    await _drain_calls(page, result)

                    # Harvest links + forms from the settled DOM.
                    try:
                        links, forms = await _harvest(page)
                        for f in forms:
                            if len(result.forms) < 60:
                                f = dict(f)
                                f.setdefault("page", page.url)
                                result.forms.append(f)
                        for link in links:
                            absu = urljoin(page.url, link).split("#")[0]
                            h = urlparse(absu).netloc
                            if absu.startswith("http") and _in_scope(h, scope_apex) and absu not in seen:
                                if absu not in queue and len(queue) < HARD_MAX_PAGES * 4:
                                    queue.append(absu)
                    except Exception as e:
                        result.errors.append(f"harvest {url[:80]}: {str(e)[:120]}")

                # Mine collected JS bundles for endpoints/source maps.
                if capture_js and result.js_files and time.monotonic() < crawl_deadline:
                    await _mine_js(context, result, deadline=crawl_deadline)
                elif capture_js and result.js_files:
                    result.errors.append("skipped JS mining — crawl budget exhausted")

                # Export session so the agent can hand off auth to execute_browser /
                # privileged re-crawls (tester methodology: login once, reuse session).
                try:
                    result.storage_state = await context.storage_state()
                except Exception as e:
                    result.errors.append(f"storage_state: {str(e)[:120]}")

                await context.close()
            finally:
                await browser.close()
    except Exception as e:
        logger.error("deep_crawl failed: %s", e)
        return {
            "success": False,
            "output": f"Deep crawl error: {str(e)[:400]}",
            "error": str(e),
            "exit_code": -1,
        }

    from app.services.agent.capability_map import build_capability_map_from_crawl

    cmap = build_capability_map_from_crawl(result)
    cmap_dict = cmap.to_dict()
    text = _format_output(result)
    text += "\n\n" + _format_capability_map_section(cmap_dict)

    auth_session = None
    if isinstance(result.storage_state, dict) and result.storage_state:
        cookies = result.storage_state.get("cookies") or []
        auth_session = {
            "target": result.target,
            "scope": result.scope,
            "authenticated": result.authenticated,
            "storage_state": result.storage_state,
            "cookies": cookies[:80],
            "cookie_names": [c.get("name") for c in cookies[:40] if isinstance(c, dict)],
        }
        text += (
            f"\n\n## Auth session export\n"
            f"Authenticated={result.authenticated!r}. "
            f"{len(cookies)} cookies exported for handoff to execute_browser / "
            f"execute_deep_crawl (storage_state). Cookie names: "
            f"{', '.join(auth_session['cookie_names'][:15]) or '(none)'}."
        )

    return {
        "success": True,
        "output": text,
        "error": "; ".join(result.errors[:5]) if result.errors else None,
        "exit_code": 0,
        "capability_map": cmap_dict,
        "auth_session": auth_session,
    }


# Fallback field-detection selectors, tried in order (case-insensitive attrs).
_USERNAME_SELECTORS = [
    'input[type="email"]',
    'input[autocomplete="username"]',
    'input[name*="user" i]',
    'input[name*="email" i]',
    'input[name*="login" i]',
    'input[id*="user" i]',
    'input[id*="email" i]',
    'input[type="text"]',
    'input:not([type="password"]):not([type="hidden"]):not([type="submit"]):not([type="checkbox"]):not([type="radio"])',
]
_SUBMIT_SELECTORS = [
    'button[type="submit"]',
    'input[type="submit"]',
    'button[name*="login" i]',
    'button[id*="login" i]',
    'button[id*="signin" i]',
    'button[class*="login" i]',
    'button',
]


async def _first_visible(page, selectors: List[str]):
    """Return the first visible element matching any selector, else None."""
    for sel in selectors:
        if not sel:
            continue
        try:
            for h in await page.query_selector_all(sel):
                try:
                    if await h.is_visible():
                        return h
                except Exception:
                    continue
        except Exception:
            continue
    return None


async def _perform_login(page, login: Dict[str, Any], timeout_ms: int, result: "CrawlResult") -> bool:
    """
    Log in from a username/password so the crawl runs as an authenticated user.

    Auto-detects the login form when selectors aren't given: it finds the visible
    password field, the best-matching username field, and a submit control (or
    presses Enter). Verifies success (explicit success_url/selector, else the
    heuristic "no visible password field remains"). Cookies/localStorage set by
    the login persist in the browser context for the rest of the crawl.
    """
    login_url = str(login.get("url") or login.get("login_url") or "").strip()

    # Credentials may be given inline, via *_env keys, or as env:/secret:/file:
    # references so they never have to sit inline in the agent's tool trace.
    raw_user = f"env:{login['username_env']}" if login.get("username_env") else login.get("username")
    raw_pass = f"env:{login['password_env']}" if login.get("password_env") else login.get("password")
    username = _resolve_secret(raw_user)
    password = _resolve_secret(raw_pass)

    if not login_url:
        result.errors.append("login requires a url")
        return False
    if not username or password is None:
        result.errors.append(
            "login credentials missing or unresolved — provide username/password, "
            "username_env/password_env, or env:/secret:/file: references"
        )
        return False
    if not login_url.startswith("http"):
        login_url = f"https://{login_url}"

    try:
        await page.goto(login_url, wait_until="domcontentloaded", timeout=timeout_ms)
    except Exception as e:
        result.errors.append(f"login nav: {str(e)[:120]}")
        return False
    await asyncio.sleep(SETTLE_MS / 1000)

    pass_sel = login.get("password_selector") or 'input[type="password"]'
    pass_handle = await _first_visible(page, [pass_sel])
    if not pass_handle:
        result.errors.append("login: no visible password field found")
        return False

    user_sel = login.get("username_selector")
    user_handle = (
        await _first_visible(page, [user_sel]) if user_sel
        else await _first_visible(page, _USERNAME_SELECTORS)
    )
    if not user_handle:
        result.errors.append("login: no username field found")
        return False

    try:
        await user_handle.fill(str(username))
        await asyncio.sleep(random.uniform(0.1, 0.3))
        await pass_handle.fill(str(password))
        await asyncio.sleep(random.uniform(0.1, 0.3))
    except Exception as e:
        result.errors.append(f"login fill: {str(e)[:120]}")
        return False

    # Optional extra fields (e.g. tenant/company/otp) as {selector: value}.
    # Values may also be env:/secret:/file: references.
    for sel, val in (login.get("extra_fields") or {}).items():
        h = await _first_visible(page, [sel])
        if h:
            resolved = _resolve_secret(val)
            if resolved is None:
                continue
            try:
                await h.fill(str(resolved))
            except Exception:
                pass

    # Submit: explicit selector, else a detected submit control, else Enter.
    submitted = False
    submit_sel = login.get("submit_selector")
    submit_handle = (
        await _first_visible(page, [submit_sel]) if submit_sel
        else await _first_visible(page, _SUBMIT_SELECTORS)
    )
    try:
        if submit_handle:
            await submit_handle.click(timeout=5000)
            submitted = True
    except Exception:
        submitted = False
    if not submitted:
        try:
            await pass_handle.press("Enter")
        except Exception as e:
            result.errors.append(f"login submit: {str(e)[:120]}")
            return False

    # Wait for the post-login navigation / XHR to settle.
    try:
        await page.wait_for_load_state("networkidle", timeout=timeout_ms)
    except Exception:
        await asyncio.sleep(SETTLE_MS / 1000)

    # Verify.
    success_url = str(login.get("success_url") or "").strip()
    success_selector = str(login.get("success_selector") or "").strip()
    ok = True
    if success_selector:
        ok = bool(await page.query_selector(success_selector))
    elif success_url:
        ok = success_url in (page.url or "")
    else:
        remaining_pw = await page.query_selector('input[type="password"]')
        try:
            ok = not (remaining_pw and await remaining_pw.is_visible())
        except Exception:
            ok = True

    if not ok:
        result.errors.append(
            "login may have failed (still shows a password field / not at success_url) — "
            "check credentials or pass explicit username_selector/password_selector/submit_selector"
        )
    return ok


async def _drive_page(page, interact: bool) -> None:
    """Scroll to trigger lazy loads, expand disclosures, click safe controls."""
    # Move the mouse to a couple of plausible spots first — some anti-bot scripts
    # only "arm" content after they observe pointer movement.
    try:
        for x, y in ((240, 200), (760, 430), (1180, 300)):
            await page.mouse.move(x + random.randint(-40, 40), y + random.randint(-30, 30),
                                  steps=random.randint(4, 9))
            await asyncio.sleep(random.uniform(0.05, 0.18))
    except Exception:
        pass

    # Progressive, irregular scroll to trigger IntersectionObserver / infinite
    # scroll — a human doesn't scroll in perfectly even increments.
    for _ in range(random.randint(5, 8)):
        step = random.randint(280, 620)
        try:
            await page.mouse.wheel(0, step)
        except Exception:
            await page.evaluate(f"window.scrollBy(0, {step})")
        await asyncio.sleep(random.uniform(0.18, 0.5))
    await page.evaluate("window.scrollTo(0, 0)")
    await asyncio.sleep(random.uniform(0.1, 0.3))

    # Expand all <details> so their content (and any lazy chunks) load.
    try:
        await page.evaluate(
            "document.querySelectorAll('details:not([open])').forEach(d => d.open = true)"
        )
    except Exception:
        pass

    if not interact:
        return

    # Click a bounded set of *safe*, visible controls (tabs, menu items, and
    # non-destructive buttons) to surface SPA views without mutating state.
    try:
        handles = await page.query_selector_all(
            "[role=tab], [role=menuitem], button, [role=button], nav a"
        )
    except Exception:
        handles = []

    # Tester methodology: click as many safe interactive controls as we can
    # afford so SPA routes/lazy bundles surface before attack planning.
    max_clicks = DEFAULT_MAX_CLICKS
    clicked = 0
    for h in handles[:80]:
        if clicked >= max_clicks:
            break
        try:
            if not await h.is_visible():
                continue
            text = ((await h.inner_text()) or "").strip()[:60]
            if text and _DESTRUCTIVE_TEXT.search(text):
                continue
            # Skip real form submit buttons.
            btype = (await h.get_attribute("type")) or ""
            if btype.lower() == "submit":
                continue
            await h.click(timeout=1500, no_wait_after=True)
            clicked += 1
            await asyncio.sleep(random.uniform(0.15, 0.45))
        except Exception:
            continue


async def _drain_calls(page, result: CrawlResult) -> None:
    """Pull the in-page instrumentation ring buffer and fold into the result."""
    try:
        calls = await page.evaluate(
            "(() => { const c = window.__interceptor_calls || []; "
            "window.__interceptor_calls = []; return c; })()"
        )
    except Exception:
        return
    if not isinstance(calls, list):
        return
    seed_apex = result.scope
    for c in calls[:MAX_CAPTURED_CALLS]:
        try:
            kind = c.get("kind")
            url = c.get("url") or ""
            method = c.get("method") or "GET"
            if kind == "websocket":
                result.websockets.add(url)
                continue
            if kind == "sse":
                result.sse.add(url)
            if url.startswith("channel:"):
                continue
            absu = urljoin(page.url, url)
            host = urlparse(absu).netloc
            if _in_scope(host, seed_apex):
                path = urlparse(absu).path or "/"
                q = urlparse(absu).query
                key = f"{method} {path}" + (f"?{q[:120]}" if q else "")
                result.api_calls.setdefault(host, set()).add(key)
            elif host:
                result.third_party.add(host)
        except Exception:
            continue


async def _harvest(page):
    """Return (links, forms) from the current DOM."""
    data = await page.evaluate(
        """
        () => {
          const links = Array.from(document.querySelectorAll('a[href]'))
            .map(a => a.getAttribute('href')).filter(Boolean).slice(0, 300);
          const forms = Array.from(document.querySelectorAll('form')).slice(0, 30).map(f => ({
            action: f.getAttribute('action') || '',
            method: (f.getAttribute('method') || 'GET').toUpperCase(),
            inputs: Array.from(f.querySelectorAll('input,select,textarea'))
              .map(i => i.getAttribute('name') || i.getAttribute('id') || '')
              .filter(Boolean).slice(0, 40)
          }));
          return { links, forms };
        }
        """
    )
    return data.get("links", []), data.get("forms", [])


async def _mine_js(context, result: CrawlResult, deadline: Optional[float] = None) -> None:
    """Fetch discovered JS bundles with the browser context and extract endpoints."""
    js_urls = sorted(result.js_files)[:MAX_JS_FETCH]
    for url in js_urls:
        if deadline is not None and time.monotonic() >= deadline:
            result.errors.append("js_mine_budget_exhausted")
            break
        try:
            resp = await context.request.get(url, timeout=10000)
            if not resp.ok:
                continue
            body = await resp.text()
        except Exception:
            continue
        if not body:
            continue
        body = body[:MAX_JS_BYTES]

        sm = _SOURCEMAP_PATTERN.search(body)
        if sm:
            rel = sm.group(1).strip()
            result.source_maps.add(rel if rel.startswith("data:") else urljoin(url, rel))

        for m in _ENDPOINT_PATTERN.finditer(body):
            v = m.group(1)
            if not v or len(v) < 4:
                continue
            if any(x in v for x in ("%s", "{{", "${", "<%")):
                continue
            if v.startswith("data:") or v.endswith((".svg", ".png", ".woff", ".css", ".jpg", ".gif")):
                continue
            result.endpoints_from_js.add(v[:300])
            if len(result.endpoints_from_js) > 800:
                break


def _format_output(r: CrawlResult) -> str:
    lines: List[str] = []
    lines.append("Interceptor-style deep crawl complete.")
    lines.append(f"Target: {r.target}  (scope: {r.scope})")
    if r.authenticated is not None:
        lines.append(f"Authenticated session: {'yes' if r.authenticated else 'FAILED (crawled unauthenticated)'}")
    lines.append(f"Pages visited: {len(r.pages_visited)}")
    for p in r.pages_visited[:25]:
        lines.append(f"  - {p}")

    total_api = sum(len(v) for v in r.api_calls.values())
    if r.api_calls:
        lines.append(f"\nFirst-party API / XHR endpoints ({total_api} across {len(r.api_calls)} hosts):")
        for host in sorted(r.api_calls):
            lines.append(f"  [{host}]")
            for key in sorted(r.api_calls[host])[:80]:
                lines.append(f"    {key}")
    else:
        lines.append("\nNo first-party API calls captured.")

    if r.websockets:
        lines.append(f"\nWebSocket channels ({len(r.websockets)}):")
        for w in sorted(r.websockets)[:20]:
            lines.append(f"    {w}")
    if r.sse:
        lines.append(f"\nServer-Sent Event streams ({len(r.sse)}):")
        for s in sorted(r.sse)[:20]:
            lines.append(f"    {s}")

    if r.js_files:
        lines.append(f"\nJavaScript files discovered ({len(r.js_files)}):")
        for j in sorted(r.js_files)[:60]:
            lines.append(f"    {j}")
    if r.source_maps:
        lines.append(f"\nSource maps exposed ({len(r.source_maps)}):")
        for s in sorted(r.source_maps)[:20]:
            lines.append(f"    {s}")

    if r.endpoints_from_js:
        lines.append(f"\nEndpoints/routes extracted from JS ({len(r.endpoints_from_js)}):")
        for e in sorted(r.endpoints_from_js)[:120]:
            lines.append(f"    {e}")

    if r.forms:
        lines.append(f"\nForms discovered ({len(r.forms)}):")
        for f in r.forms[:20]:
            inputs = ",".join(f.get("inputs", [])[:12])
            lines.append(f"    {f.get('method')} {f.get('action') or '(self)'}  inputs=[{inputs}]")

    if r.third_party:
        lines.append(f"\nThird-party / out-of-scope hosts contacted ({len(r.third_party)}):")
        for t in sorted(r.third_party)[:30]:
            lines.append(f"    {t}")

    lines.append(
        "\nNext steps: treat this crawl as your tester walkthrough. Build attacks from "
        "the capability map (forms/APIs/auth), spawn fireteam specialists with "
        "specialists=\"auto\", then probe matched surfaces (arjun/schemathesis/curl, "
        "scan_js_urls_for_secrets, validate_finding → create_finding)."
    )
    return "\n".join(lines)


def _format_capability_map_section(cmap: Dict[str, Any]) -> str:
    """Append a compact capability-map summary for the agent prompt/trace."""
    try:
        from app.services.agent.capability_map import format_capability_map_for_prompt
        return "## Application Capability Map\n" + format_capability_map_for_prompt(cmap)
    except Exception:
        caps = ", ".join(cmap.get("capabilities") or []) or "(none)"
        return (
            f"## Application Capability Map\n"
            f"quality={cmap.get('quality_score')} ready={cmap.get('ready_for_attack')} "
            f"capabilities=[{caps}]"
        )
