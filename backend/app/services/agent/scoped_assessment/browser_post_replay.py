"""Replay one captured POST at a time from its source page with fresh page state.

The browser may refresh narrowly named anti-CSRF fields. A request is sent only
when every other captured field and the selected SQLi field still match.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from urllib.parse import urlsplit

from .body_probe import match_browser_post_body, plan_observed_body
from .browser import _storage_for_origin, assert_in_scope, origin
from .browser_actions import allowed_discovery_control, allowed_discovery_path
from .browser_runtime import launch_options
from .http_observe import MAX_BODY, _sql_error_family


async def replay_observed_post_controls(
    private_exchange: bytes, *, parameter: str, payloads: dict[str, str],
    allowed_origins: list[str], storage_state: dict | None,
) -> dict[str, dict]:
    """Issue bounded controls through fresh page loads; return redacted receipts."""
    from playwright.async_api import async_playwright

    if not payloads or len(payloads) > 6 or any(
        not isinstance(key, str) or not isinstance(suffix, str)
        or len(suffix) > 100 or "__PROWL_NONCE__" in suffix
        for key, suffix in payloads.items()
    ):
        raise ValueError("POST browser controls must be bounded fixed suffixes")
    captured = json.loads(private_exchange)
    target, mime, baseline, _ = plan_observed_body(
        private_exchange, parameter=parameter, allowed_origins=allowed_origins,
    )
    page_url = captured.get("page_url")
    if (not isinstance(page_url, str) or not page_url or origin(page_url) != origin(target)
            or urlsplit(page_url).query or urlsplit(page_url).fragment
            or not allowed_discovery_path(urlsplit(page_url).path or "/")):
        raise ValueError("Captured POST has no safe source page for fresh replay")
    actions = captured.get("replay_actions") or []
    if not isinstance(actions, list) or len(actions) > 6:
        raise ValueError("Captured POST replay actions are invalid")
    page_path = urlsplit(page_url).path or "/"
    for action in actions:
        if (not isinstance(action, dict) or action.get("kind") not in {"tab", "disclosure", "summary"}
                or not isinstance(action.get("label"), str)
                or not 0 < len(action["label"]) <= 80
                or not isinstance(action.get("aria_controls"), str)
                or len(action["aria_controls"]) > 80
                or action.get("before_path") != page_path):
            raise ValueError("Captured POST replay action is not bound to its source page")
    expected_origin = origin(target)
    assert_in_scope(page_url, allowed_origins)
    target_path = urlsplit(target).path or "/"
    planned = {}
    for key, suffix in payloads.items():
        if suffix:
            _, _, _, planned[key] = plan_observed_body(
                private_exchange, parameter=parameter, allowed_origins=allowed_origins,
                payload=suffix,
            )
        else:
            planned[key] = baseline
    receipts: dict[str, dict] = {}

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(**launch_options())
        try:
            for key, suffix in payloads.items():
                context_args = {"service_workers": "block", "ignore_https_errors": False}
                scoped_state = _storage_for_origin(storage_state, page_url)
                if scoped_state:
                    context_args["storage_state"] = scoped_state
                context = await browser.new_context(**context_args)
                try:
                    selected = False
                    selected_request = None
                    sent_body = b""
                    match_mode = ""
                    volatile_fields: list[str] = []
                    current_action = "navigate"
                    response_future = asyncio.get_running_loop().create_future()

                    async def route_request(route):
                        nonlocal selected, selected_request, sent_body, match_mode, volatile_fields
                        request = route.request
                        try:
                            in_origin = origin(request.url) == expected_origin
                            path = urlsplit(request.url).path or "/"
                            method = request.method.upper()
                            if (in_origin and method == "POST" and path == target_path
                                    and request.url == target and not selected
                                    and request.resource_type in {"xhr", "fetch"}
                                    and (not actions or current_action == f"replay-{len(actions)}")
                                    and request.headers.get("content-type", "").split(";", 1)[0].strip().lower() == mime):
                                matched = match_browser_post_body(
                                    baseline, request.post_data_buffer, mime=mime,
                                    parameter=parameter, payload="__PROWL_NONCE__",
                                )
                                if matched is not None:
                                    changed, match_mode, volatile_fields = matched
                                    sent_body = changed.replace(b"__PROWL_NONCE__", suffix.encode())
                                    selected_request = request
                                    selected = True
                                    await route.continue_(post_data=sent_body)
                                    return
                            allowed = in_origin and method in {"GET", "HEAD", "OPTIONS"} and allowed_discovery_path(path)
                        except (TypeError, ValueError):
                            allowed = False
                        if allowed:
                            await route.continue_()
                        else:
                            await route.abort()

                    async def route_socket(socket):
                        value = socket.url.replace("wss://", "https://", 1).replace("ws://", "http://", 1)
                        try:
                            allowed = origin(value) == expected_origin
                        except ValueError:
                            allowed = False
                        if allowed:
                            socket.connect_to_server()
                        else:
                            await socket.close()

                    async def record_response(response):
                        if response.request is not selected_request or response_future.done():
                            return
                        try:
                            declared = response.headers.get("content-length", "")
                            if declared.isdigit() and int(declared) > MAX_BODY:
                                data, truncated = b"", True
                            else:
                                data = await response.body()
                                truncated = len(data) > MAX_BODY
                                data = data[:MAX_BODY]
                            content_type = response.headers.get("content-type", "").split(";", 1)[0].lower()[:100]
                            arrays: dict[str, int] = {}
                            if content_type == "application/json" and not truncated:
                                try:
                                    parsed = json.loads(data)
                                    if isinstance(parsed, dict):
                                        arrays = {name: min(len(parsed[name]), 1000)
                                                  for name in ("results", "items", "records", "data")
                                                  if isinstance(parsed.get(name), list)}
                                except (UnicodeDecodeError, ValueError):
                                    pass
                            response_future.set_result({
                                "status": response.status, "content_type": content_type,
                                "bytes_captured": len(data), "truncated": truncated,
                                "body_sha256": hashlib.sha256(data).hexdigest(),
                                "request_sha256": hashlib.sha256(sent_body).hexdigest(),
                                "variant_sha256": hashlib.sha256(planned[key]).hexdigest(),
                                "json_array_lengths": arrays,
                                "sql_error_family": _sql_error_family(data),
                                "redirected": bool(response.headers.get("location")),
                                "body_match_mode": match_mode,
                                "volatile_fields": volatile_fields,
                            })
                        except Exception as exc:
                            response_future.set_exception(exc)

                    await context.route("**/*", route_request)
                    if not hasattr(context, "route_web_socket"):
                        raise RuntimeError("Playwright 1.48+ is required for WebSocket scope control")
                    await context.route_web_socket("**/*", route_socket)
                    page = await context.new_page()
                    page.on("response", lambda response: asyncio.create_task(record_response(response)))
                    await page.goto(page_url, wait_until="domcontentloaded", timeout=20_000)
                    for index, action in enumerate(actions, start=1):
                        if (urlsplit(page.url).path or "/") != page_path:
                            raise ValueError("POST replay page changed before observed UI action")
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
                            raise ValueError("Observed POST UI control is missing or ambiguous")
                        current_action = f"replay-{index}"
                        await matches[0].click(timeout=3_000, no_wait_after=True)
                        await page.wait_for_timeout(350)
                    if not selected:
                        await page.wait_for_timeout(800)
                    if not selected:
                        raise ValueError("Fresh POST did not match captured input and replay action")
                    receipts[key] = await asyncio.wait_for(response_future, timeout=8)
                finally:
                    await context.close()
        finally:
            await browser.close()
    return receipts
