"""
Interaction-first browser crawl with full traffic capture.

The portable analog of Interceptor for a headless agent: instead of a browser
extension + native daemon monkey-patching fetch/XHR, we use Playwright — which
sees all network at the browser level — to (1) capture every request/response
into the SessionStore and (2) *exercise* the page (scroll, click, expand, fill)
so lazy-loaded chunks and XHR/API calls actually fire. A realistic interaction
crawl is also what makes a proxy in front (Caido, via AEGIS_BROWSER_PROXY)
capture a realistic surface.

The pure decision logic (what is safe to click, what is in scope, how a captured
response becomes a transaction) lives here and is unit-tested; the thin
Playwright driver calls it. Destructive controls (delete / logout / pay) are
filtered so the crawl can click aggressively.
"""

import logging
import os
import re
from typing import Callable, Dict, List, Optional
from urllib.parse import urlsplit

from agent.http_session import HttpRequest, HttpResponse, get_session_store

logger = logging.getLogger("agent.browser_crawl")

# Controls we must never click during an autonomous crawl.
_DESTRUCTIVE = re.compile(
    r"\b(delete|remove|destroy|wipe|erase|sign\s*out|log\s*out|logout|"
    r"deactivate|close\s+account|delete\s+account|pay|purchase|checkout|"
    r"place\s+order|confirm\s+order|unsubscribe|cancel\s+subscription|"
    r"reset|revoke|transfer|withdraw)\b",
    re.I,
)
# Element roles worth clicking to reveal surface.
_CLICKABLE_ROLES = {"button", "link", "menuitem", "tab", "menuitemcheckbox", "treeitem"}
# Non-capturable / noise content types to skip storing as transactions.
_SKIP_CONTENT = ("image/", "font/", "video/", "audio/", "text/css")


def is_destructive(label: str) -> bool:
    return bool(_DESTRUCTIVE.search(label or ""))


def crawl_host(seed: str) -> str:
    return (urlsplit(seed).hostname or "").lower()


def in_scope(url: str, host: str, include_subdomains: bool = False) -> bool:
    h = (urlsplit(url).hostname or "").lower()
    if not h or not host:
        return False
    return h == host or (include_subdomains and h.endswith("." + host))


def should_capture(content_type: str) -> bool:
    ct = (content_type or "").lower()
    return not any(ct.startswith(skip) or skip in ct for skip in _SKIP_CONTENT)


def pick_interactions(elements: List[dict], max_clicks: int = 40) -> List[dict]:
    """From page elements [{ref, role, name}], choose distinct, safe controls to
    click — deduped by (role, name), destructive controls removed, capped."""
    seen = set()
    picks = []
    for el in elements:
        role = (el.get("role") or "").lower()
        name = (el.get("name") or "").strip()
        if role not in _CLICKABLE_ROLES:
            continue
        if is_destructive(name):
            continue
        key = (role, name.lower())
        if key in seen:
            continue
        seen.add(key)
        picks.append(el)
        if len(picks) >= max_clicks:
            break
    return picks


def make_transaction(method: str, url: str, req_headers: Dict[str, str],
                     req_body: str, status: int, resp_headers: Dict[str, str],
                     resp_body: str):
    """Build (HttpRequest, HttpResponse) from one captured exchange."""
    return (
        HttpRequest(method=method or "GET", url=url,
                    headers={str(k): str(v) for k, v in (req_headers or {}).items()},
                    body=req_body or ""),
        HttpResponse(status=int(status or 0),
                     headers={str(k): str(v) for k, v in (resp_headers or {}).items()},
                     body=resp_body or ""),
    )


def _browser_proxy_kwargs() -> dict:
    proxy = os.environ.get("AEGIS_BROWSER_PROXY")
    return {"proxy": {"server": proxy}} if proxy else {}


def run_interactive_crawl(
    seed: str,
    *,
    host: Optional[str] = None,
    max_pages: int = 20,
    max_clicks: int = 40,
    probe_text: str = "aegis-probe",
    include_subdomains: bool = False,
    record: Optional[Callable[[HttpRequest, HttpResponse], None]] = None,
    max_body_bytes: int = 200_000,
) -> dict:
    """Drive a real Chromium (Playwright), capturing every in-scope response into
    the SessionStore while interacting to force lazy content. Returns a summary.

    Needs Playwright + a reachable target; the capture/interaction logic it uses
    is unit-tested separately.
    """
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:  # pragma: no cover - env without playwright
        return {"error": f"playwright unavailable: {e}"}

    host = host or crawl_host(seed)
    store_record = record or (lambda req, resp: get_session_store().record(req, resp, label="browser"))
    captured = {"count": 0}
    discovered: set = set()

    def _on_response(resp):
        try:
            req = resp.request
            if not in_scope(req.url, host, include_subdomains):
                return
            ctype = (resp.headers or {}).get("content-type", "")
            if not should_capture(ctype):
                return
            body = ""
            try:
                raw = resp.body()
                if raw and len(raw) <= max_body_bytes:
                    body = raw.decode("utf-8", "ignore")
            except Exception:
                body = ""
            txn = make_transaction(req.method, req.url, req.headers,
                                   req.post_data or "", resp.status, resp.headers, body)
            store_record(*txn)
            captured["count"] += 1
            discovered.add(req.url.split("?")[0])
        except Exception as e:  # never let capture break the crawl
            logger.debug("capture failed: %s", e)

    pages_visited = 0
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True, args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"])
        context = browser.new_context(ignore_https_errors=True, **_browser_proxy_kwargs())
        page = context.new_page()
        page.on("response", _on_response)

        frontier = [seed]
        seen_pages = set()
        while frontier and pages_visited < max_pages:
            url = frontier.pop(0)
            if url in seen_pages or not in_scope(url, host, include_subdomains):
                continue
            seen_pages.add(url)
            try:
                page.goto(url, wait_until="networkidle", timeout=20000)
            except Exception:
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=15000)
                except Exception:
                    continue
            pages_visited += 1

            # Scroll to force lazy content
            try:
                for _ in range(6):
                    page.mouse.wheel(0, 4000)
                    page.wait_for_timeout(250)
            except Exception:
                pass

            # Interact with safe controls to reveal more surface
            try:
                els = page.eval_on_selector_all(
                    "a,button,[role=button],[role=menuitem],[role=tab],summary",
                    "els => els.map(e => ({name: (e.innerText||e.getAttribute('aria-label')||'').slice(0,80),"
                    " role: e.getAttribute('role') || (e.tagName === 'A' ? 'link' : 'button')}))",
                ) or []
                for el in pick_interactions(els, max_clicks=max_clicks):
                    try:
                        loc = page.get_by_role(el["role"], name=el["name"], exact=True).first
                        loc.click(timeout=1500)
                        page.wait_for_timeout(150)
                    except Exception:
                        continue
            except Exception:
                pass

            # Probe the first text input (autocomplete/search XHR)
            try:
                inp = page.query_selector("input[type=text], input[type=search], input:not([type])")
                if inp:
                    inp.fill(probe_text, timeout=1500)
                    page.wait_for_timeout(300)
            except Exception:
                pass

            # Enqueue same-host links
            try:
                for href in page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)") or []:
                    if in_scope(href, host, include_subdomains) and href not in seen_pages:
                        frontier.append(href)
            except Exception:
                pass

        browser.close()

    return {
        "seed": seed, "host": host, "pages_visited": pages_visited,
        "requests_captured": captured["count"],
        "urls_discovered": sorted(discovered)[:200],
        "proxied_through": os.environ.get("AEGIS_BROWSER_PROXY") or None,
    }
