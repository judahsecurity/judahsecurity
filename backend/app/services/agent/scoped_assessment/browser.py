"""A scoped Playwright browser derived from Aegis's browser assessment flow.

This worker owns the browser context. The agent receives observations, never
cookies, storage state, raw response bodies, or unrestricted JavaScript eval.
"""

from __future__ import annotations

import asyncio
import secrets
from urllib.parse import parse_qsl, urlsplit

from .browser_runtime import launch_options


NONCE_MARKER = "__PROWL_NONCE__"
FORM_INVENTORY_JS = """els => els.slice(0, 30).map(form => {
  const action = new URL(form.action);
  const fields = Array.from(form.querySelectorAll('input[name], textarea[name], select[name]'))
    .slice(0, 40).map(el => ({
      name: el.name.slice(0, 80),
      control_type: (el.type || el.tagName.toLowerCase()).toLowerCase().slice(0, 30),
      hidden: el.type === 'hidden'
    })).filter(field => field.name);
  return {method: form.method.toUpperCase(), action: (action.origin + action.pathname).slice(0, 512), fields};
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
    for href in hrefs[:100]:
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
    for href in hrefs[:100]:
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
    max_actions: int = 3,
    approved_action_paths: set[str] | None = None,
) -> tuple[dict, bytes | None]:
    """Execute one bounded browser check with HTTP and WebSocket origin routing."""
    from playwright.async_api import async_playwright

    if operation not in ("map", "check_xss", "crawl", "inspect_js"):
        raise ValueError("Unsupported browser operation")
    if operation == "inspect_js":
        from .browser_actions import MAX_DISCOVERY_ACTIONS
        if javascript_sources is None or traffic_exchanges is None:
            raise ValueError("JavaScript inspection requires private source and traffic collectors")
        if not 0 <= max_actions <= MAX_DISCOVERY_ACTIONS:
            raise ValueError("Discovery action limit must be between 0 and 6")
        if not 1 <= max_pages <= 4:
            raise ValueError("JavaScript inspection page limit must be between 1 and 4")
    if operation == "crawl" and not 1 <= max_pages <= 10:
        raise ValueError("Crawl page limit must be between 1 and 10")
    assert_in_scope(url, allowed_origins)
    nonce = secrets.token_hex(8) if operation == "check_xss" else ""
    if operation == "check_xss" and NONCE_MARKER not in url:
        raise ValueError(f"XSS URL must contain {NONCE_MARKER}")
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
    request_rows: dict[object, dict] = {}
    current_action_ref = "navigate"
    actions: list[dict] = []
    approval_required_actions: list[dict] = []
    approved_action_paths = set(approved_action_paths or ())

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(**launch_options())
        try:
            context_args = {"service_workers": "block", "ignore_https_errors": False}
            scoped_state = _storage_for_origin(storage_state, final_target)
            if scoped_state:
                context_args["storage_state"] = scoped_state
            context = await browser.new_context(**context_args)

            async def route_request(route):
                nonlocal blocked_requests
                try:
                    allowed = origin(route.request.url) == expected_origin
                except ValueError:
                    allowed = False
                if allowed:
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
                if request.resource_type in ("xhr", "fetch", "script") and len(request_actions) < 200:
                    request_actions[request] = current_action_ref
                if len(requests) >= 100:
                    return
                parts = urlsplit(request.url)
                row = {
                    "method": request.method, "path": (parts.path or "/")[:512],
                    "resource_type": request.resource_type,
                    "query_keys": sorted({key[:80] for key, _ in parse_qsl(parts.query[:2048])})[:20],
                    "action_ref": current_action_ref,
                }
                requests.append(row)
                request_rows[request] = row

            page.on("request", record_request)

            def record_response(response):
                try:
                    if origin(response.url) != expected_origin:
                        return
                    row = request_rows.get(response.request)
                    if row is not None:
                        row["status"] = response.status
                        row["content_type"] = response.headers.get("content-type", "").split(";", 1)[0][:80]
                except Exception:
                    return

            page.on("response", record_response)

            if operation == "inspect_js":
                from .javascript import MAX_SOURCE_BYTES, MAX_SOURCES
                from .browser_traffic import MAX_BODY_BYTES, MAX_EXCHANGES, package_exchange

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

                async def capture_exchange(response):
                    try:
                        request = response.request
                        if origin(response.url) != expected_origin or request.resource_type not in ("xhr", "fetch"):
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
                        public, private = package_exchange(
                            url=response.url, expected_origin=expected_origin,
                            action_ref=request_actions.get(request, "unattributed"),
                            method=request.method, resource_type=request.resource_type,
                            status=response.status,
                            content_type=response.headers.get("content-type", ""),
                            request_body=request_body, response_body=response_body,
                            request_content_type=request.headers.get("content-type", ""),
                        )
                        if len(traffic_exchanges) < MAX_EXCHANGES:
                            traffic_exchanges.append({"public": public, "private": private})
                    except Exception:
                        return

                def queue_exchange(response):
                    try:
                        relevant = response.request.resource_type in ("xhr", "fetch") and origin(response.url) == expected_origin
                    except ValueError:
                        relevant = False
                    if relevant and len(traffic_tasks) < MAX_EXCHANGES * 3:
                        traffic_tasks.append(asyncio.create_task(capture_exchange(response)))

                page.on("response", queue_exchange)

            async def accept_dialog(dialog):
                dialogs.append(dialog.message[:200])
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
                            "els => els.slice(0, 100).map(e => e.href)"
                        )
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
                await context.close()
                return result, None
            response = await page.goto(final_target, wait_until="domcontentloaded", timeout=20_000)
            await page.wait_for_timeout(650)
            if operation == "inspect_js":
                from .browser_actions import allowed_discovery_control, allowed_operator_action

                approved_action_count = 0
                passive_action_count = 0

                async def inspect_operator_action() -> None:
                    nonlocal current_action_ref, approved_action_count
                    path = urlsplit(page.url).path or "/"
                    for control in (await page.query_selector_all(
                        "button, input[type=submit], input[type=button]"
                    ))[:24]:
                        try:
                            if not await control.is_visible():
                                continue
                            label = " ".join((await control.inner_text()
                                              or await control.get_attribute("value") or "").split())[:80]
                            if not allowed_operator_action(label):
                                continue
                            if path not in approved_action_paths:
                                if len(approval_required_actions) < 8:
                                    approval_required_actions.append({
                                        "page_path": path, "label": label,
                                        "status": "approval_required",
                                    })
                                continue
                            if approved_action_count + passive_action_count >= max_actions:
                                return
                            if label.strip().lower() == "subscribe":
                                email_field = page.locator("input[type=email]")
                                if await email_field.count() != 1:
                                    actions.append({"kind": "approved_control", "path": path,
                                                    "label": label, "status": "missing_single_email_input"})
                                    continue
                                await email_field.fill(
                                    "aegis-capture-" + secrets.token_hex(4) + "@example.invalid"
                                )
                            ref = f"approved-ui-{approved_action_count + 1}"
                            current_action_ref = ref
                            start = (len(requests), len(javascript_sources), len(traffic_exchanges))
                            approved_action_count += 1
                            try:
                                await control.click(timeout=1500, no_wait_after=True)
                                await page.wait_for_timeout(450)
                                assert_in_scope(page.url, allowed_origins)
                                await settle_capture()
                                status = "completed"
                            except ValueError:
                                raise
                            except Exception as exc:
                                status = type(exc).__name__
                            actions.append(await checkpoint(
                                ref, "approved_control", start, label=label,
                                before_path=path, after_path=urlsplit(page.url).path or "/",
                                status=status, approved_by_policy=True,
                            ))
                            if (urlsplit(page.url).path or "/") != path:
                                return
                        except ValueError:
                            raise
                        except Exception:
                            continue

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
                await inspect_operator_action()
                seen_controls: set[tuple[str, str, str, str]] = set()
                passive_limit = max_actions - min(len(approved_action_paths), max_actions)
                while passive_action_count < passive_limit:
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
                    passive_action_count += 1
                current_action_ref = "settle"
                await page.wait_for_timeout(300)
                await settle_capture()
                page_paths = [urlsplit(page.url).path or "/"]
                hrefs = await page.locator("a[href]").evaluate_all(
                    "els => els.slice(0, 100).map(e => e.href)"
                )
                queue = _crawl_links(hrefs, [expected_origin])
                visited = {expected_origin + page_paths[0]}
                while queue and len(page_paths) < max_pages:
                    next_url = queue.pop(0)
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
                        actions.append(await checkpoint(ref, "navigate_link", start, path=page_path,
                                                        navigation_mode=navigation_mode, status="completed"))
                        await inspect_operator_action()
                        hrefs = await page.locator("a[href]").evaluate_all(
                            "els => els.slice(0, 100).map(e => e.href)"
                        )
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
                    "els => els.slice(0, 100).map(e => e.href)"
                )
                result["links"] = _crawl_links(hrefs, [expected_origin])
                result["link_query_inputs"] = _link_query_inputs(hrefs, [expected_origin])
                result["forms"] = await _forms(page, expected_origin)
            elif operation == "check_xss":
                # A dialog containing a fresh server nonce is execution evidence.
                # Reflection or an unrelated dialog alone is not proof.
                result["executed"] = any(nonce in message for message in dialogs)
                result["dialog_count"] = len(dialogs)
                result["nonce"] = nonce
            else:
                result["script_count"] = len(javascript_sources)
                result["collection_limit"] = MAX_SOURCES
                result["actions"] = actions
                result["approval_required_actions"] = approval_required_actions
                result["traffic_count"] = len(traffic_exchanges)
                result["max_actions"] = max_actions
                result["max_pages"] = max_pages
                result["page_paths"] = page_paths
                result["pages_inspected"] = len(page_paths)
            screenshot = await page.screenshot(full_page=True)
            await context.close()
            return result, screenshot
        finally:
            await browser.close()
