"""A scoped Playwright browser derived from Aegis's browser assessment flow.

This worker owns the browser context. The agent receives observations, never
cookies, storage state, raw response bodies, or unrestricted JavaScript eval.
"""

from __future__ import annotations

import asyncio
import secrets
from urllib.parse import parse_qsl, quote, unquote_plus, urlsplit, urlunsplit

from .browser_runtime import launch_options


NONCE_MARKER = "__PROWL_NONCE__"
MAX_LINKS_PER_PAGE = 300
FORM_INVENTORY_JS = """els => els.slice(0, 30).map((form, dom_index) => {
  const action = new URL(form.action);
  const fields = Array.from(form.querySelectorAll('input[name], textarea[name], select[name]'))
    .slice(0, 40).map(el => ({
      name: el.name.slice(0, 80),
      control_type: (el.type || el.tagName.toLowerCase()).toLowerCase().slice(0, 30),
      hidden: el.type === 'hidden'
    })).filter(field => field.name);
  return {dom_index, method: form.method.toUpperCase(), action: (action.origin + action.pathname).slice(0, 512), fields};
})"""


def origin(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
        raise ValueError("Absolute HTTP(S) URL without embedded credentials required")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("Invalid target port") from exc
    default = 443 if parts.scheme == "https" else 80
    return f"{parts.scheme}://{parts.hostname.lower()}{':' + str(port) if port != default else ''}"


def assert_in_scope(url: str, allowed_origins: list[str]) -> None:
    if origin(url) not in allowed_origins:
        raise ValueError("Target origin is outside this assessment")
    sensitive = ("token", "secret", "password", "api_key", "apikey", "authorization", "session", "jwt")
    if any(any(word in key.lower() for word in sensitive) for key, _ in parse_qsl(urlsplit(url).query)):
        raise ValueError("Credential-bearing URL query is not accepted")


def replace_observed_query_value(url: str, parameter: str, value: str) -> str:
    """Change exactly one observed query field without rebuilding its neighbors."""
    parts = urlsplit(url)
    fields = parts.query.split("&")
    if len(fields) > 40 or len(parts.query) > 2048:
        raise ValueError("Observed query exceeds XSS replay limit")
    matches = [index for index, field in enumerate(fields)
               if field and unquote_plus(field.split("=", 1)[0]) == parameter]
    if len(matches) != 1:
        raise ValueError("XSS replay requires one observed query field")
    index = matches[0]
    name = fields[index].split("=", 1)[0]
    fields[index] = name + "=" + quote(value, safe="")
    return urlunsplit(parts._replace(query="&".join(fields)))


def observed_query_keys(url: str) -> list[str]:
    query = urlsplit(url).query
    if len(query) > 2048:
        return []
    try:
        return sorted({key for key, _ in parse_qsl(
            query, keep_blank_values=True, max_num_fields=40)})
    except ValueError:
        return []


def _storage_for_origin(state: dict | None, target: str) -> dict | None:
    if not state:
        return None
    target_host = urlsplit(target).hostname or ""
    cookies = []
    for cookie in state.get("cookies", []):
        domain = str(cookie.get("domain", "")).lstrip(".").lower()
        if domain == target_host or target_host.endswith("." + domain):
            cookies.append(cookie)
    origins = []
    for row in state.get("origins", []):
        try:
            if origin(row.get("origin", "")) == origin(target):
                origins.append(row)
        except ValueError:
            continue
    return {"cookies": cookies, "origins": origins}


def _crawl_links(hrefs: list[str], allowed_origins: list[str]) -> list[str]:
    """Queue only same-origin link paths; never carry query secrets forward."""
    from .browser_actions import allowed_discovery_path

    found: list[str] = []
    for href in hrefs[:MAX_LINKS_PER_PAGE]:
        try:
            assert_in_scope(href, allowed_origins)
            parts = urlsplit(href)
            if not allowed_discovery_path(parts.path or "/"):
                continue
            value = origin(href) + (parts.path or "/")
            if len(value) > 512:
                continue
            if value not in found:
                found.append(value)
        except (TypeError, ValueError):
            continue
    return found


def _link_query_inputs(hrefs: list[str], allowed_origins: list[str]) -> list[dict]:
    """Keep query names from in-scope links without exposing their values."""
    from .browser_actions import allowed_discovery_path

    by_path: dict[str, set[str]] = {}
    for href in hrefs[:MAX_LINKS_PER_PAGE]:
        try:
            assert_in_scope(href, allowed_origins)
            parts = urlsplit(href)
            path = parts.path or "/"
            if not parts.query or not allowed_discovery_path(path) or len(path) > 300:
                continue
            names = {key[:80] for key, _ in parse_qsl(
                parts.query[:2048], keep_blank_values=True, max_num_fields=100,
            ) if key}
            if names:
                by_path.setdefault(path, set()).update(names)
        except (TypeError, ValueError):
            continue
    return [{"path": path, "query_keys": sorted(names)[:20]}
            for path, names in list(by_path.items())[:100]]


def _private_link_baselines(hrefs: list[str], allowed_origins: list[str]) -> list[str]:
    """Retain bounded, ordinary link URLs for session-local proof replay only."""
    from .browser_actions import allowed_discovery_path

    found: list[str] = []
    for href in hrefs[:MAX_LINKS_PER_PAGE]:
        try:
            assert_in_scope(href, allowed_origins)
            parts = urlsplit(href)
            if (not parts.query or parts.fragment or len(href) > 2048
                    or not allowed_discovery_path(parts.path or "/")
                    or href in found):
                continue
            names = [name.lower() for name, _ in parse_qsl(
                parts.query, keep_blank_values=True, max_num_fields=40,
            )]
            if not names or any(any(word in name for word in (
                "csrf", "xsrf", "nonce", "action", "delete", "remove",
                "purchase", "pay", "save", "send", "reset", "confirm",
                "unsubscribe", "logout", "signout",
            )) for name in names):
                continue
            found.append(href)
            if len(found) >= 80:
                break
        except (TypeError, ValueError):
            continue
    return found


async def _forms(page, expected_origin: str) -> list[dict]:
    """Return same-origin form input names and control types, never values."""
    rows = await page.locator("form").evaluate_all(FORM_INVENTORY_JS)
    found = []
    for row in rows:
        try:
            if origin(row["action"]) == expected_origin:
                found.append(row)
        except (KeyError, TypeError, ValueError):
            continue
    return found


async def _discovery_anchor(page, target: str):
    """Find a visible link for a path without carrying URL query values."""
    for anchor in (await page.query_selector_all("a[href]"))[:100]:
        try:
            href = await anchor.evaluate("el => el.href")
            parts = urlsplit(href)
            if (origin(href) + (parts.path or "/") != target or parts.query or parts.fragment
                    or await anchor.get_attribute("download") is not None
                    or (await anchor.get_attribute("target") or "").lower() not in ("", "_self")
                    or not await anchor.is_visible()):
                continue
            return anchor
        except (TypeError, ValueError):
            continue
    return None


async def check_browser(
    *, operation: str, url: str, allowed_origins: list[str],
    storage_state: dict | None = None, max_pages: int = 1,
    javascript_sources: list[dict] | None = None,
    traffic_exchanges: list[dict] | None = None,
    link_baselines: list[str] | None = None,
    max_actions: int = 3,
    form_action: str = "", form_field: str = "",
    form_payload_template: str = "",
    xhr_path: str = "", xhr_parameter: str = "",
    xhr_payload_template: str = "",
    xhr_query_keys: list[str] | None = None,
    xhr_actions: list[dict] | None = None,
    readback_url: str = "", cleanup_url_template: str = "",
) -> tuple[dict, bytes | None]:
    """Execute one bounded browser check with HTTP and WebSocket origin routing."""
    from playwright.async_api import async_playwright

    if operation not in ("map", "check_xss", "check_form_xss", "check_xhr_xss", "check_stored_xss", "crawl", "inspect_js"):
        raise ValueError("Unsupported browser operation")
    if operation == "inspect_js":
        from .browser_actions import MAX_DISCOVERY_ACTIONS
        if javascript_sources is None or traffic_exchanges is None:
            raise ValueError("JavaScript inspection requires private source and traffic collectors")
        if not 0 <= max_actions <= MAX_DISCOVERY_ACTIONS:
            raise ValueError("Discovery action limit must be between 0 and 6")
        if not 1 <= max_pages <= 10:
            raise ValueError("JavaScript inspection page limit must be between 1 and 10")
    if operation == "crawl" and not 1 <= max_pages <= 10:
        raise ValueError("Crawl page limit must be between 1 and 10")
    if xhr_actions is None:
        xhr_actions = []
    assert_in_scope(url, allowed_origins)
    nonce = secrets.token_hex(8) if operation in {"check_xss", "check_form_xss", "check_xhr_xss", "check_stored_xss"} else ""
    if operation == "check_xss" and NONCE_MARKER not in url:
        raise ValueError(f"XSS URL must contain {NONCE_MARKER}")
    if operation in {"check_form_xss", "check_stored_xss"}:
        import re
        if (not form_action or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,79}", form_field)
                or NONCE_MARKER not in form_payload_template
                or len(form_payload_template) > 300):
            raise ValueError("An observed form action, field, and bounded nonce payload are required")
        assert_in_scope(form_action, allowed_origins)
        if urlsplit(form_action).query or urlsplit(form_action).fragment:
            raise ValueError("Form XSS action must be an exact path")
    if operation == "check_stored_xss":
        cleanup_fields = parse_qsl(urlsplit(cleanup_url_template).query, keep_blank_values=True)
        if (not readback_url or not cleanup_url_template
                or len(cleanup_fields) != 1 or cleanup_fields[0][1] != NONCE_MARKER
                or urlsplit(readback_url).query or urlsplit(readback_url).fragment
                or urlsplit(cleanup_url_template).fragment
                or len(cleanup_url_template) > 2048):
            raise ValueError("Stored XSS needs an exact read page and nonce-addressed cleanup")
        assert_in_scope(readback_url, allowed_origins)
        assert_in_scope(cleanup_url_template.replace(NONCE_MARKER, nonce), allowed_origins)
    if operation == "check_xhr_xss":
        from .browser_actions import allowed_discovery_path
        import re
        if (urlsplit(url).query or urlsplit(url).fragment
                or not xhr_path.startswith("/") or xhr_path.startswith("//")
                or len(xhr_path) > 512 or not allowed_discovery_path(xhr_path)
                or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,79}", xhr_parameter)
                or not isinstance(xhr_query_keys, list)
                or not 1 <= len(xhr_query_keys) <= 20
                or xhr_parameter not in xhr_query_keys
                or xhr_query_keys != sorted(set(xhr_query_keys))
                or any(not isinstance(key, str) or not re.fullmatch(
                    r"[A-Za-z_][A-Za-z0-9_.-]{0,79}", key) for key in xhr_query_keys)
                or NONCE_MARKER not in xhr_payload_template
                or len(xhr_payload_template) > 300):
            raise ValueError("An exact rendering page, safe XHR path, field, and nonce payload are required")
        if not isinstance(xhr_actions, list) or len(xhr_actions) > 6:
            raise ValueError("XHR replay actions must be a bounded observed sequence")
        for action in xhr_actions:
            if (not isinstance(action, dict)
                    or action.get("kind") not in {"tab", "disclosure", "summary"}
                    or not isinstance(action.get("label"), str)
                    or not 0 < len(action["label"]) <= 80
                    or not isinstance(action.get("aria_controls"), str)
                    or len(action["aria_controls"]) > 80
                    or action.get("before_path") != (urlsplit(url).path or "/")):
                raise ValueError("XHR replay action is not bound to the rendering page")
    final_target = url.replace(NONCE_MARKER, nonce)
    assert_in_scope(final_target, allowed_origins)
    expected_origin = origin(final_target)
    requests: list[dict] = []
    blocked_requests = 0
    dialogs: list[str] = []
    script_tasks: list[asyncio.Task] = []
    traffic_tasks: list[asyncio.Task] = []
    body_slots = asyncio.Semaphore(4)
    seen_scripts: set[str] = set()
    seen_inline: set[tuple[str, int]] = set()
    request_actions: dict[object, str] = {}
    request_pages: dict[object, str] = {}
    request_rows: dict[object, dict] = {}
    seen_request_templates: set[tuple] = set()
    seen_exchange_shapes: set[tuple] = set()
    current_action_ref = "navigate"
    actions: list[dict] = []
    read_only_interaction = operation in {"check_xhr_xss", "check_form_xss", "check_stored_xss"}
    get_form_actions = 0
    approved_post_path = urlsplit(form_action).path or "/"
    post_action_active = False
    approved_post_requests = 0
    post_response_seen = False
    post_response_dialogs: list[str] = []
    xhr_mutated = False
    xhr_response_seen = False
    xhr_response_dialogs: list[str] = []
    xhr_request = None
    readback_active = False
    readback_response_seen = False
    readback_status = None
    readback_final_exact = False
    readback_error = ""
    readback_dialogs: list[str] = []
    cleanup_sent = False
    cleanup_success = False
    cleanup_status = None

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(**launch_options())
        try:
            context_args = {"service_workers": "block", "ignore_https_errors": False}
            scoped_state = _storage_for_origin(storage_state, final_target)
            if scoped_state:
                context_args["storage_state"] = scoped_state
            context = await browser.new_context(**context_args)

            async def route_request(route):
                nonlocal blocked_requests, approved_post_requests, xhr_mutated, xhr_request
                try:
                    allowed = origin(route.request.url) == expected_origin
                    if allowed and post_action_active:
                        from .browser_actions import allowed_discovery_path
                        method = route.request.method.upper()
                        path = urlsplit(route.request.url).path or "/"
                        allowed = ((method == "POST" and path == approved_post_path
                                    and approved_post_requests == 0)
                                   or (method in {"GET", "HEAD", "OPTIONS"}
                                       and allowed_discovery_path(path)))
                    elif allowed and read_only_interaction:
                        from .browser_actions import allowed_discovery_path

                        allowed = (route.request.method.upper() in {"GET", "HEAD", "OPTIONS"}
                                   and allowed_discovery_path(urlsplit(route.request.url).path or "/"))
                except ValueError:
                    allowed = False
                if allowed:
                    if (operation == "check_xhr_xss" and not xhr_mutated
                            and (not xhr_actions or current_action_ref == f"xhr-replay-{len(xhr_actions)}")
                            and route.request.method.upper() == "GET"
                            and route.request.resource_type in {"xhr", "fetch"}
                            and (urlsplit(route.request.url).path or "/") == xhr_path
                            and observed_query_keys(route.request.url) == xhr_query_keys):
                        try:
                            changed = replace_observed_query_value(
                                route.request.url, xhr_parameter,
                                xhr_payload_template.replace(NONCE_MARKER, nonce),
                            )
                            assert_in_scope(changed, allowed_origins)
                            xhr_request = route.request
                            xhr_mutated = True
                            await route.continue_(url=changed)
                        except ValueError:
                            await route.continue_()
                        return
                    if post_action_active and route.request.method.upper() == "POST":
                        approved_post_requests += 1
                    await route.continue_()
                else:
                    blocked_requests += 1
                    await route.abort()

            await context.route("**/*", route_request)

            if not hasattr(context, "route_web_socket"):
                raise RuntimeError("Playwright 1.48+ is required for WebSocket scope control")

            async def route_socket(socket):
                nonlocal blocked_requests
                value = socket.url.replace("wss://", "https://", 1).replace("ws://", "http://", 1)
                try:
                    allowed = origin(value) == expected_origin
                except ValueError:
                    allowed = False
                if allowed:
                    socket.connect_to_server()
                else:
                    blocked_requests += 1
                    await socket.close()

            await context.route_web_socket("**/*", route_socket)
            page = await context.new_page()

            def record_request(request):
                try:
                    if origin(request.url) != expected_origin:
                        return
                except ValueError:
                    return
                if request.resource_type in ("document", "xhr", "fetch", "script") and len(request_actions) < 200:
                    request_actions[request] = current_action_ref
                    if request.resource_type == "document":
                        request_pages[request] = request.url
                    else:
                        try:
                            request_pages[request] = request.frame.url
                        except Exception:
                            request_pages[request] = page.url
                if request.resource_type not in {"document", "xhr", "fetch", "script"}:
                    return
                parts = urlsplit(request.url)
                query_keys = tuple(sorted({key[:80] for key, _ in parse_qsl(parts.query[:2048])})[:20])
                template = (request.method, parts.path or "/", request.resource_type, query_keys)
                if template in seen_request_templates or len(requests) >= 300:
                    return
                seen_request_templates.add(template)
                row = {
                    "method": request.method, "path": (parts.path or "/")[:512],
                    "resource_type": request.resource_type,
                    "query_keys": list(query_keys),
                    "action_ref": current_action_ref,
                }
                requests.append(row)
                request_rows[request] = row

            page.on("request", record_request)

            def record_response(response):
                nonlocal post_response_seen, xhr_response_seen, readback_response_seen, readback_status
                try:
                    if origin(response.url) != expected_origin:
                        return
                    row = request_rows.get(response.request)
                    if (post_action_active and response.request.method.upper() == "POST"
                            and (urlsplit(response.url).path or "/") == approved_post_path):
                        post_response_seen = True
                    if response.request is xhr_request:
                        xhr_response_seen = True
                    if (readback_active and response.request.resource_type == "document"
                            and response.url == readback_url):
                        readback_response_seen = True
                        readback_status = response.status
                    if row is not None:
                        row["status"] = response.status
                        row["content_type"] = response.headers.get("content-type", "").split(";", 1)[0][:80]
                except Exception:
                    return

            page.on("response", record_response)

            if traffic_exchanges is not None and operation in {"map", "crawl", "inspect_js"}:
                from .browser_traffic import MAX_BODY_BYTES, MAX_EXCHANGES, package_exchange

                async def capture_exchange(response):
                    try:
                        request = response.request
                        if origin(response.url) != expected_origin or request.resource_type not in {"document", "xhr", "fetch"}:
                            return
                        if request.resource_type == "document":
                            from .browser_actions import allowed_discovery_path
                            parts = urlsplit(response.url)
                            if (request.method.upper() != "GET" or not parts.query
                                    or not allowed_discovery_path(parts.path or "/")):
                                return
                        if len(traffic_exchanges) >= MAX_EXCHANGES:
                            return
                        declared = response.headers.get("content-length", "")
                        if declared.isdigit() and int(declared) > MAX_BODY_BYTES:
                            return
                        request_body = request.post_data_buffer or b""
                        if len(request_body) > MAX_BODY_BYTES:
                            return
                        async with body_slots:
                            response_body = await response.body()
                        initiator_page = request_pages.get(request, "")
                        public, private = package_exchange(
                            url=response.url, expected_origin=expected_origin,
                            action_ref=request_actions.get(request, "unattributed"),
                            method=request.method, resource_type=request.resource_type,
                            status=response.status,
                            content_type=response.headers.get("content-type", ""),
                            request_body=request_body, response_body=response_body,
                            request_content_type=request.headers.get("content-type", ""),
                            page_url=initiator_page,
                            request_headers=request.headers,
                        )
                        shape = (public["method"], public["path"],
                                 tuple(public["query_keys"]), public["request_content_type"],
                                 public["graphql_document_sha256"],
                                 tuple((field.get("location"), field.get("path"))
                                       for field in public["body_fields"]))
                        if shape not in seen_exchange_shapes and len(traffic_exchanges) < MAX_EXCHANGES:
                            seen_exchange_shapes.add(shape)
                            traffic_exchanges.append({"public": public, "private": private})
                    except Exception:
                        return

                def queue_exchange(response):
                    try:
                        relevant = response.request.resource_type in {"document", "xhr", "fetch"} and origin(response.url) == expected_origin
                    except ValueError:
                        relevant = False
                    if relevant and len(traffic_tasks) < MAX_EXCHANGES * 3:
                        traffic_tasks.append(asyncio.create_task(capture_exchange(response)))

                page.on("response", queue_exchange)

            if operation == "inspect_js":
                from .javascript import MAX_SOURCE_BYTES, MAX_SOURCES

                async def capture_script(response):
                    try:
                        source_url = response.url
                        if origin(source_url) != expected_origin or response.status != 200:
                            return
                        if response.request.resource_type != "script":
                            return
                        path = urlsplit(source_url).path or "/"
                        source_key = expected_origin + path
                        if source_key in seen_scripts or len(seen_scripts) >= MAX_SOURCES:
                            return
                        content_type = response.headers.get("content-type", "").lower()
                        if content_type and not any(value in content_type for value in ("javascript", "ecmascript", "text/plain")):
                            return
                        declared = response.headers.get("content-length", "")
                        if declared.isdigit() and int(declared) > MAX_SOURCE_BYTES:
                            return
                        seen_scripts.add(source_key)
                        async with body_slots:
                            data = await response.body()
                        if 0 < len(data) <= MAX_SOURCE_BYTES:
                            javascript_sources.append({"url": source_key, "kind": "external",
                                                       "page_path": urlsplit(request_pages.get(response.request, "")).path or "",
                                                       "page_paths": [urlsplit(request_pages.get(response.request, "")).path or ""],
                                                       "action_ref": request_actions.get(response.request, "unattributed"),
                                                       "data": data})
                    except Exception:
                        return

                def queue_script(response):
                    try:
                        relevant = response.request.resource_type == "script" and origin(response.url) == expected_origin
                    except ValueError:
                        relevant = False
                    if relevant and len(script_tasks) < MAX_SOURCES * 3:
                        script_tasks.append(asyncio.create_task(capture_script(response)))

                page.on("response", queue_script)

            async def accept_dialog(dialog):
                dialogs.append(dialog.message[:200])
                if post_response_seen:
                    post_response_dialogs.append(dialog.message[:200])
                if xhr_response_seen:
                    xhr_response_dialogs.append(dialog.message[:200])
                if readback_active and readback_response_seen:
                    readback_dialogs.append(dialog.message[:200])
                await dialog.dismiss()

            page.on("dialog", lambda dialog: asyncio.create_task(accept_dialog(dialog)))

            async def settle_capture():
                """Finish response reads before recording each discovery checkpoint."""
                for _ in range(3):
                    scripts = len(script_tasks)
                    exchanges = len(traffic_tasks)
                    await asyncio.gather(*script_tasks, *traffic_tasks, return_exceptions=True)
                    if scripts == len(script_tasks) and exchanges == len(traffic_tasks):
                        break

            async def checkpoint(ref: str, kind: str, start: tuple[int, int, int], **details) -> dict:
                await settle_capture()
                return {"ref": ref, "kind": kind, **details,
                        "request_count": len(requests) - start[0],
                        "scripts_added": len(javascript_sources or []) - start[1],
                        "traffic_count": len(traffic_exchanges or []) - start[2]}

            async def collect_inline():
                page_path = urlsplit(page.url).path or "/"
                inline_sources = await page.locator("script:not([src])").evaluate_all(
                    "els => els.filter(e => !e.type || /javascript|ecmascript|module/i.test(e.type))"
                    ".slice(0, 10).map((e, i) => ({index: i, text: (e.textContent || '').slice(0, 1000001)}))"
                )
                for row in inline_sources:
                    key = (page_path, row["index"])
                    data = row["text"].encode()
                    if key not in seen_inline and 0 < len(data) <= MAX_SOURCE_BYTES and len(javascript_sources) < MAX_SOURCES:
                        seen_inline.add(key)
                        javascript_sources.append({"url": expected_origin + page_path,
                                                   "kind": "inline", "index": row["index"],
                                                   "page_path": page_path,
                                                   "action_ref": current_action_ref, "data": data})

            if operation == "crawl":
                queue = [final_target]
                visited: set[str] = set()
                pages: list[dict] = []
                while queue and len(pages) < max_pages:
                    page_url = queue.pop(0)
                    if page_url in visited:
                        continue
                    visited.add(page_url)
                    request_start = len(requests)
                    try:
                        response = await page.goto(page_url, wait_until="domcontentloaded", timeout=20_000)
                        assert_in_scope(page.url, allowed_origins)
                        hrefs = await page.locator("a[href]").evaluate_all(
                            f"els => els.slice(0, {MAX_LINKS_PER_PAGE}).map(e => e.href)"
                        )
                        if link_baselines is not None:
                            link_baselines.extend(_private_link_baselines(hrefs, [expected_origin]))
                        links = _crawl_links(hrefs, [expected_origin])
                        forms = await _forms(page, expected_origin)
                        pages.append({
                            "url": page_url,
                            "final_path": urlsplit(page.url).path or "/",
                            "status": response.status if response else None,
                            "title": (await page.title())[:200],
                            "links": links,
                            "link_query_inputs": _link_query_inputs(hrefs, [expected_origin]),
                            "forms": forms,
                            "requests": requests[request_start:],
                        })
                        queue.extend(link for link in links if link not in visited and link not in queue)
                    except Exception as exc:
                        pages.append({"url": page_url, "error": type(exc).__name__})
                result = {
                    "operation": "crawl", "target_template": url,
                    "final_origin": expected_origin, "pages": pages,
                    "pages_visited": len(pages), "requests": requests,
                    "blocked_requests": blocked_requests,
                }
                await settle_capture()
                await context.unroute_all(behavior="ignoreErrors")
                await context.close()
                return result, None
            response = await page.goto(final_target, wait_until="domcontentloaded", timeout=20_000)
            xhr_actions_replayed = 0
            if operation == "check_xhr_xss" and xhr_actions:
                from .browser_actions import allowed_discovery_control

                for index, action in enumerate(xhr_actions, start=1):
                    if (urlsplit(page.url).path or "/") != action["before_path"]:
                        raise ValueError("XHR replay page changed before the observed UI action")
                    matches = []
                    for control in (await page.query_selector_all(
                        "[role=tab], button[aria-expanded='false'][aria-controls], summary"
                    ))[:24]:
                        if not await control.is_visible():
                            continue
                        role = (await control.get_attribute("role") or "").lower()
                        tag = await control.evaluate("el => el.tagName.toLowerCase()")
                        kind = "tab" if role == "tab" else "summary" if tag == "summary" else "disclosure"
                        label = " ".join((await control.inner_text()).split())[:80]
                        controls_id = (await control.get_attribute("aria-controls") or "")[:80]
                        in_form = await control.evaluate("el => Boolean(el.closest('form'))")
                        button_type = await control.get_attribute("type") or ""
                        if (kind == action["kind"] and label == action["label"]
                                and controls_id == action["aria_controls"]
                                and allowed_discovery_control(kind=kind, label=label,
                                                              in_form=in_form, button_type=button_type)):
                            matches.append(control)
                    if len(matches) != 1:
                        raise ValueError("Observed XHR UI control is missing or ambiguous")
                    current_action_ref = f"xhr-replay-{index}"
                    await matches[0].click(timeout=3_000, no_wait_after=True)
                    xhr_actions_replayed += 1
                    await page.wait_for_timeout(350)
            await page.wait_for_timeout(1200 if operation in {"check_xss", "check_form_xss", "check_xhr_xss", "check_stored_xss"} else 650)
            form_submitted = False
            if operation in {"check_form_xss", "check_stored_xss"}:
                # Use the observed page's native submit path, including its JS
                # handler. Route policy permits POST only to the approved path.
                forms = await _forms(page, expected_origin)
                matching = [row for row in forms if row.get("method") == "POST"
                            and row.get("action") == form_action
                            and any(field.get("name") == form_field and
                                    field.get("control_type") in {"text", "search", "email", "textarea"}
                                    for field in row.get("fields") or [])]
                if len(matching) != 1:
                    raise ValueError("The observed POST form is missing or ambiguous on its source page")
                current_action_ref = "approved-post-form"
                try:
                    post_action_active = True
                    form = page.locator("form").nth(int(matching[0]["dom_index"]))
                    payload = form_payload_template.replace(NONCE_MARKER, nonce)
                    try:
                        await form.evaluate("""(form, data) => {
                        const field = [...form.elements].find(el => el.name === data.name);
                        if (!field) throw Error('Observed POST field disappeared');
                        form.noValidate = true;
                        field.value = data.value;
                        field.dispatchEvent(new Event('input', {bubbles: true}));
                        field.dispatchEvent(new Event('change', {bubbles: true}));
                        }""", {"name": form_field, "value": payload})
                        submitters = form.locator("button, input[type=submit]")
                        if await submitters.count() == 1:
                            await submitters.first.click(timeout=3_000, no_wait_after=True)
                        else:
                            await form.evaluate("form => form.requestSubmit()")
                    except Exception:
                        # A native form navigation can destroy the evaluation
                        # context after the POST was already sent.
                        await page.wait_for_timeout(400)
                        if not approved_post_requests:
                            raise
                    await page.wait_for_timeout(1500)
                    form_submitted = approved_post_requests > 0
                finally:
                    post_action_active = False
            if operation == "check_stored_xss" and form_submitted:
                # A new navigation separates persistence from the POST response.
                # Cleanup is attempted even if the readback page errors.
                try:
                    readback_active = True
                    await page.goto(readback_url, wait_until="domcontentloaded", timeout=20_000)
                    await page.wait_for_timeout(1200)
                    readback_final_exact = page.url == readback_url
                except Exception as exc:
                    readback_error = type(exc).__name__
                finally:
                    readback_active = False
                    cleanup_sent = True
                    try:
                        cleanup = await context.request.delete(
                            cleanup_url_template.replace(NONCE_MARKER, nonce),
                            max_redirects=0, timeout=10_000,
                        )
                        cleanup_status = cleanup.status
                        cleanup_success = 200 <= cleanup.status < 300
                    except Exception:
                        cleanup_success = False
            if operation == "inspect_js":
                from .browser_actions import (
                    MAX_GET_FORM_ACTIONS, allowed_discovery_control,
                    safe_get_form_field,
                )

                page_observations: list[dict] = []

                async def observe_page(status: int | None = None) -> list[str]:
                    """Preserve inputs on every inspected page, not only the seed."""
                    hrefs = await page.locator("a[href]").evaluate_all(
                        f"els => els.slice(0, {MAX_LINKS_PER_PAGE}).map(e => e.href)"
                    )
                    if link_baselines is not None:
                        link_baselines.extend(_private_link_baselines(hrefs, [expected_origin]))
                    render_path = urlsplit(page.url).path or "/"
                    loaded_scripts = await page.locator("script[src]").evaluate_all(
                        "els => els.slice(0, 80).map(e => e.src)"
                    )
                    loaded_keys = set()
                    for value in loaded_scripts:
                        try:
                            if isinstance(value, str) and origin(value) == expected_origin:
                                loaded_keys.add(expected_origin + (urlsplit(value).path or "/"))
                        except ValueError:
                            continue
                    for source in javascript_sources or []:
                        if source.get("kind") != "external" or source.get("url") not in loaded_keys:
                            continue
                        paths = source.setdefault("page_paths", [])
                        if render_path not in paths and len(paths) < max_pages:
                            paths.append(render_path)
                    page_observations.append({
                        "url": expected_origin + (urlsplit(page.url).path or "/"),
                        "status": status,
                        "final_path": urlsplit(page.url).path or "/",
                        "links": _crawl_links(hrefs, [expected_origin]),
                        "link_query_inputs": _link_query_inputs(hrefs, [expected_origin]),
                        "forms": await _forms(page, expected_origin),
                    })
                    return hrefs

                async def submit_safe_get_forms() -> None:
                    """Exercise bounded search forms with inert values and GET-only routing."""
                    nonlocal current_action_ref, read_only_interaction, get_form_actions
                    if get_form_actions >= MAX_GET_FORM_ACTIONS:
                        return
                    page_url = page.url
                    forms = await _forms(page, expected_origin)
                    for form_row in forms:
                        field = safe_get_form_field(form_row)
                        if not field or get_form_actions >= MAX_GET_FORM_ACTIONS:
                            continue
                        form = page.locator("form").nth(int(form_row["dom_index"]))
                        try:
                            if not await form.is_visible():
                                continue
                            current_action_ref = f"get-form-{get_form_actions + 1}"
                            start = (len(requests), len(javascript_sources), len(traffic_exchanges))
                            marker = "prowl-observe-" + secrets.token_hex(6)
                            read_only_interaction = True
                            await form.evaluate("""(form, data) => {
                                const field = [...form.elements].find(el => el.name === data.name);
                                if (!field) throw Error('Observed form field disappeared');
                                field.value = data.value;
                                field.dispatchEvent(new Event('input', {bubbles: true}));
                                field.dispatchEvent(new Event('change', {bubbles: true}));
                                form.requestSubmit();
                            }""", {"name": field, "value": marker})
                            await page.wait_for_timeout(500)
                            assert_in_scope(page.url, allowed_origins)
                            if link_baselines is not None and urlsplit(page.url).query:
                                link_baselines.append(page.url)
                            get_form_actions += 1
                            actions.append(await checkpoint(
                                current_action_ref, "get_form", start,
                                path=urlsplit(form_row["action"]).path or "/",
                                field=field, status="completed",
                            ))
                        except ValueError:
                            raise
                        except Exception as exc:
                            actions.append({"ref": current_action_ref, "kind": "get_form",
                                            "path": urlsplit(form_row["action"]).path or "/",
                                            "field": field, "status": type(exc).__name__})
                        finally:
                            current_action_ref = "restore"
                            try:
                                if page.url != page_url:
                                    await page.goto(page_url, wait_until="domcontentloaded", timeout=20_000)
                                    assert_in_scope(page.url, allowed_origins)
                            finally:
                                read_only_interaction = False

                await collect_inline()
                actions.append(await checkpoint("navigate", "navigate", (0, 0, 0),
                                                path=urlsplit(page.url).path or "/", status="completed"))
                current_action_ref = "scroll"
                start = (len(requests), len(javascript_sources), len(traffic_exchanges))
                await page.mouse.wheel(0, 1200)
                await page.wait_for_timeout(450)
                await collect_inline()
                actions.append(await checkpoint("scroll", "scroll", start,
                                                path=urlsplit(page.url).path or "/", status="completed"))
                seen_controls: set[tuple[str, str, str, str]] = set()
                while len(actions) - 2 < max_actions:
                    selected = None
                    controls = await page.query_selector_all(
                        "[role=tab], button[aria-expanded='false'][aria-controls], summary"
                    )
                    for index, control in enumerate(controls[:24]):
                        try:
                            if not await control.is_visible():
                                continue
                            role = (await control.get_attribute("role") or "").lower()
                            tag = await control.evaluate("el => el.tagName.toLowerCase()")
                            kind = "tab" if role == "tab" else "summary" if tag == "summary" else "disclosure"
                            label = " ".join((await control.inner_text()).split())[:80]
                            in_form = await control.evaluate("el => Boolean(el.closest('form'))")
                            button_type = await control.get_attribute("type") or ""
                            controls_id = (await control.get_attribute("aria-controls") or "")[:80]
                            page_path = urlsplit(page.url).path or "/"
                            fingerprint = (page_path, kind, label, controls_id)
                            if fingerprint in seen_controls or not allowed_discovery_control(
                                kind=kind, label=label, in_form=in_form, button_type=button_type,
                            ):
                                continue
                            selected = (control, index, kind, label, controls_id, page_path, fingerprint)
                            break
                        except Exception:
                            continue
                    if selected is None:
                        break
                    control, index, kind, label, controls_id, before_path, fingerprint = selected
                    seen_controls.add(fingerprint)
                    ref = f"ui-{len(actions) - 1}"
                    current_action_ref = ref
                    start = (len(requests), len(javascript_sources), len(traffic_exchanges))
                    try:
                        await control.click(timeout=1500, no_wait_after=True)
                        await page.wait_for_timeout(400)
                        status = "completed"
                    except Exception as exc:
                        status = type(exc).__name__
                    assert_in_scope(page.url, allowed_origins)
                    await collect_inline()
                    actions.append(await checkpoint(
                        ref, kind, start, label=label, aria_controls=controls_id,
                        control_index=index, before_path=before_path,
                        after_path=urlsplit(page.url).path or "/", status=status,
                    ))
                current_action_ref = "settle"
                await page.wait_for_timeout(300)
                await settle_capture()
                page_paths = [urlsplit(page.url).path or "/"]
                hrefs = await observe_page(response.status if response else None)
                await submit_safe_get_forms()
                from app.services.crawl_priority import next_crawl_url_index, route_family

                queue = _crawl_links(hrefs, [expected_origin])
                visited = {expected_origin + page_paths[0]}
                visited_families = {route_family(expected_origin + page_paths[0]): 1}
                while queue and len(page_paths) < max_pages:
                    next_url = queue.pop(next_crawl_url_index(queue, visited_families))
                    if next_url in visited:
                        continue
                    visited.add(next_url)
                    ref = f"page-{len(page_paths) + 1}"
                    current_action_ref = ref
                    start = (len(requests), len(javascript_sources), len(traffic_exchanges))
                    try:
                        anchor = await _discovery_anchor(page, next_url)
                        if anchor:
                            navigation_mode = "click"
                            await anchor.click(timeout=8_000)
                        else:
                            navigation_mode = "direct"
                            response = await page.goto(next_url, wait_until="domcontentloaded", timeout=20_000)
                        assert_in_scope(page.url, allowed_origins)
                        await page.wait_for_timeout(450)
                        await settle_capture()
                        await collect_inline()
                        page_path = urlsplit(page.url).path or "/"
                        page_paths.append(page_path)
                        family = route_family(page.url)
                        visited_families[family] = visited_families.get(family, 0) + 1
                        actions.append(await checkpoint(ref, "navigate_link", start, path=page_path,
                                                        navigation_mode=navigation_mode, status="completed"))
                        hrefs = await observe_page(response.status if navigation_mode == "direct" and response else 200)
                        await submit_safe_get_forms()
                        queue.extend(link for link in _crawl_links(hrefs, [expected_origin])
                                     if link not in visited and link not in queue)
                    except ValueError:
                        raise
                    except Exception as exc:
                        actions.append({"ref": ref, "kind": "navigate_link", "path": urlsplit(next_url).path or "/",
                                        "status": type(exc).__name__})
            assert_in_scope(page.url, allowed_origins)
            result = {
                "operation": operation,
                "target_template": url,
                "final_origin": origin(page.url),
                "final_path": urlsplit(page.url).path or "/",
                "status": response.status if response else None,
                "title": (await page.title())[:200],
                "requests": requests,
                "blocked_requests": blocked_requests,
            }
            if operation == "map":
                hrefs = await page.locator("a[href]").evaluate_all(
                    f"els => els.slice(0, {MAX_LINKS_PER_PAGE}).map(e => e.href)"
                )
                if link_baselines is not None:
                    link_baselines.extend(_private_link_baselines(hrefs, [expected_origin]))
                result["links"] = _crawl_links(hrefs, [expected_origin])
                result["link_query_inputs"] = _link_query_inputs(hrefs, [expected_origin])
                result["forms"] = await _forms(page, expected_origin)
            elif operation in {"check_xss", "check_form_xss", "check_xhr_xss", "check_stored_xss"}:
                # A dialog containing a fresh server nonce is execution evidence.
                # Reflection or an unrelated dialog alone is not proof.
                result["executed"] = (
                    any(nonce in message for message in post_response_dialogs)
                    and form_submitted and post_response_seen
                    if operation == "check_form_xss" else
                    any(nonce in message for message in xhr_response_dialogs)
                    and xhr_mutated and xhr_response_seen
                    if operation == "check_xhr_xss" else
                    any(nonce in message for message in readback_dialogs)
                    and form_submitted and post_response_seen and readback_response_seen
                    and readback_final_exact and readback_status is not None
                    and 200 <= readback_status < 300
                    and cleanup_success
                    if operation == "check_stored_xss" else
                    any(nonce in message for message in dialogs)
                )
                result["dialog_count"] = len(dialogs)
                result["nonce"] = nonce
                if operation in {"check_form_xss", "check_stored_xss"}:
                    result["form_action"] = form_action
                    result["form_field"] = form_field
                    result["form_payload_template"] = form_payload_template
                    result["post_submitted"] = form_submitted
                    result["post_response_seen"] = post_response_seen
                if operation == "check_stored_xss":
                    result["readback_url"] = readback_url
                    result["readback_response_seen"] = readback_response_seen
                    result["readback_status"] = readback_status
                    result["readback_final_exact"] = readback_final_exact
                    result["readback_error"] = readback_error
                    result["readback_executed"] = any(nonce in message for message in readback_dialogs)
                    result["cleanup_url_template"] = cleanup_url_template
                    result["cleanup_sent"] = cleanup_sent
                    result["cleanup_success"] = cleanup_success
                    result["cleanup_status"] = cleanup_status
                if operation == "check_xhr_xss":
                    result["xhr_path"] = xhr_path
                    result["xhr_parameter"] = xhr_parameter
                    result["xhr_payload_template"] = xhr_payload_template
                    result["xhr_query_keys"] = xhr_query_keys
                    result["xhr_mutated"] = xhr_mutated
                    result["xhr_response_seen"] = xhr_response_seen
                    result["xhr_actions"] = xhr_actions
                    result["xhr_actions_replayed"] = xhr_actions_replayed
                # Give the specialist context without exposing page source or
                # mistaking reflection for execution. Scan a bounded DOM slice.
                try:
                    result["reflection_contexts"] = await page.evaluate("""token => {
                        const contexts = new Set();
                        const walker = document.createTreeWalker(document, NodeFilter.SHOW_TEXT);
                        let node, seen = 0;
                        while ((node = walker.nextNode()) && seen++ < 3000) {
                            if (!node.textContent.includes(token)) continue;
                            const tag = node.parentElement?.tagName;
                            contexts.add(tag === 'SCRIPT' ? 'javascript' :
                                         tag === 'STYLE' ? 'css' : 'html_text');
                        }
                        seen = 0;
                        for (const element of document.querySelectorAll('*')) {
                            if (seen++ >= 3000) break;
                            for (const attribute of element.attributes) {
                                if (attribute.value.includes(token)) contexts.add('html_attribute');
                            }
                        }
                        return [...contexts].sort();
                    }""", nonce)
                except Exception:
                    result["reflection_contexts"] = []
            else:
                result["script_count"] = len(javascript_sources)
                result["collection_limit"] = MAX_SOURCES
                result["actions"] = actions
                result["traffic_count"] = len(traffic_exchanges)
                result["max_actions"] = max_actions
                result["max_pages"] = max_pages
                result["page_paths"] = page_paths
                result["pages_inspected"] = len(page_paths)
                result["pages"] = page_observations
                result["get_form_actions"] = get_form_actions
            await settle_capture()
            screenshot = await page.screenshot(full_page=True)
            await context.unroute_all(behavior="ignoreErrors")
            await context.close()
            return result, screenshot
        finally:
            await browser.close()
