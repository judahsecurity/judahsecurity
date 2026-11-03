"""Replay captured GET or POST inputs from their source page with fresh state.

The browser may refresh narrowly named anti-CSRF fields. A request is sent only
when every other captured field and the selected SQLi field still match.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from urllib.parse import unquote_plus, urlsplit

from .body_probe import match_browser_post_body, plan_observed_body
from .browser import _storage_for_origin, assert_in_scope, origin
from .browser_actions import allowed_discovery_control, allowed_discovery_path
from .browser_runtime import launch_options
from .http_observe import MAX_BODY, _sql_error_family
from .query_probe import plan_observed_query


# Each control is a fresh page load. The POST budget limits control count;
# this cap also bounds incidental page requests per control.
MAX_HTTP_REQUESTS_PER_CONTROL = 24


def has_replayable_source(private_exchange: bytes, allowed_origins: list[str]) -> bool:
    """Select browser-first replay only for reproducible observed page actions."""
    try:
        captured = json.loads(private_exchange)
        page_url = captured.get("page_url")
        target = captured.get("url")
        if (not isinstance(page_url, str) or not isinstance(target, str)
                or origin(page_url) != origin(target)
                or urlsplit(page_url).query or urlsplit(page_url).fragment
                or not allowed_discovery_path(urlsplit(page_url).path or "/")):
            return False
        assert_in_scope(page_url, allowed_origins)
        actions = captured.get("replay_actions") or []
        if not isinstance(actions, list) or len(actions) > 6:
            return False
        page_path = urlsplit(page_url).path or "/"
        for action in actions:
            if (not isinstance(action, dict) or action.get("kind") not in {"tab", "disclosure", "summary"}
                    or not isinstance(action.get("label"), str)
                    or not 0 < len(action["label"]) <= 80
                    or not isinstance(action.get("aria_controls"), str)
                    or len(action["aria_controls"]) > 80
                    or action.get("before_path") != page_path):
                return False
        action_ref = str(captured.get("action_ref") or "")
        return bool(actions) or action_ref == "navigate" or bool(re.fullmatch(r"page-[1-9][0-9]?", action_ref))
    except (TypeError, ValueError):
        return False


def _valid_get_variant(baseline: str, changed: str, parameter: str) -> bool:
    """Keep every observed GET field except the selected query value byte-for-byte."""
    try:
        old, new = urlsplit(baseline), urlsplit(changed)
        if (origin(baseline) != origin(changed) or old.path != new.path
                or new.fragment or len(changed) > 2048):
            return False
        first, second = old.query.split("&"), new.query.split("&")
        if len(first) != len(second) or len(first) > 40:
            return False
        selected = 0
        for before, after in zip(first, second, strict=True):
            before_name, _, _ = before.partition("=")
            after_name, _, _ = after.partition("=")
            if before_name != after_name:
                return False
            if unquote_plus(before_name) == parameter:
                selected += 1
            elif before != after:
                return False
        return selected == 1
    except (TypeError, ValueError):
        return False


async def _replay_observed_controls(
    private_exchange: bytes, *, parameter: str, payloads: dict[str, str],
    allowed_origins: list[str], storage_state: dict | None, request_method: str,
) -> dict[str, dict]:
    """Issue bounded GET or POST controls through fresh page loads."""
    from playwright.async_api import async_playwright

    if (request_method not in {"GET", "POST"} or not payloads
            or len(payloads) > (8 if request_method == "GET" else 6) or any(
        not isinstance(key, str) or not isinstance(suffix, str)
        or len(suffix) > (2048 if request_method == "GET" else 100)
        or "__PROWL_NONCE__" in suffix
        for key, suffix in payloads.items()
    )):
        raise ValueError("Browser controls must be bounded fixed variants")
    captured = json.loads(private_exchange)
    if request_method == "POST":
        target, mime, baseline, _ = plan_observed_body(
            private_exchange, parameter=parameter, allowed_origins=allowed_origins,
        )
    else:
        target, _ = plan_observed_query(
            private_exchange, parameter=parameter, allowed_origins=allowed_origins,
        )
        if captured.get("resource_type") not in {"xhr", "fetch"}:
            raise ValueError("Browser GET replay requires observed XHR or fetch traffic")
        mime, baseline = "", b""
    page_url = captured.get("page_url")
    if (not isinstance(page_url, str) or not page_url or origin(page_url) != origin(target)
            or urlsplit(page_url).query or urlsplit(page_url).fragment
            or not allowed_discovery_path(urlsplit(page_url).path or "/")):
        raise ValueError("Captured request has no safe source page for fresh replay")
    actions = captured.get("replay_actions") or []
    if not isinstance(actions, list) or len(actions) > 6:
        raise ValueError("Captured request replay actions are invalid")
    page_path = urlsplit(page_url).path or "/"
    for action in actions:
        if (not isinstance(action, dict) or action.get("kind") not in {"tab", "disclosure", "summary"}
                or not isinstance(action.get("label"), str)
                or not 0 < len(action["label"]) <= 80
                or not isinstance(action.get("aria_controls"), str)
                or len(action["aria_controls"]) > 80
                or action.get("before_path") != page_path):
            raise ValueError("Captured request replay action is not bound to its source page")
    expected_origin = origin(target)
    assert_in_scope(page_url, allowed_origins)
    target_path = urlsplit(target).path or "/"
    planned = {}
    for key, suffix in payloads.items():
        if request_method == "GET":
            if not _valid_get_variant(target, suffix, parameter):
                raise ValueError("GET replay variant changed an unselected request field")
            assert_in_scope(suffix, allowed_origins)
            planned[key] = suffix
        elif suffix:
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
                    request_count = 0
                    read_count = 0
                    blocked_count = 0
                    request_cap_hit = False

                    async def route_request(route):
                        nonlocal selected, selected_request, sent_body, match_mode, volatile_fields
                        nonlocal request_count, read_count, blocked_count, request_cap_hit
                        request = route.request
                        request_count += 1
                        if request_count > MAX_HTTP_REQUESTS_PER_CONTROL:
                            request_cap_hit = True
                            blocked_count += 1
                            await route.abort()
                            return
                        try:
                            in_origin = origin(request.url) == expected_origin
                            path = urlsplit(request.url).path or "/"
                            method = request.method.upper()
                            if (in_origin and method == "POST" and request_method == "POST" and path == target_path
                                    and request.url == target and not selected
                                    and request.resource_type in {"xhr", "fetch"}
                                    and (not actions or current_action == f"replay-{len(actions)}")
                                    and request.headers.get("content-type", "").split(";", 1)[0].strip().lower() == mime):
                                matched = match_browser_post_body(
                                    baseline, request.post_data_buffer, mime=mime,
                                    parameter=parameter, payload=suffix, require_nonce=False,
                                )
                                if matched is not None:
                                    changed, match_mode, volatile_fields = matched
                                    sent_body = changed
                                    selected_request = request
                                    selected = True
                                    await route.continue_(post_data=sent_body)
                                    return
                            if (in_origin and method == "GET" and request_method == "GET"
                                    and path == target_path and request.resource_type in {"xhr", "fetch"}):
                                if (request.url == target and not selected
                                        and (not actions or current_action == f"replay-{len(actions)}")):
                                    sent_body = planned[key].encode()
                                    match_mode = "exact"
                                    selected_request = request
                                    selected = True
                                    read_count += 1
                                    await route.continue_(url=planned[key])
                                    return
                                blocked_count += 1
                                await route.abort()
                                return
                            allowed = in_origin and method in {"GET", "HEAD", "OPTIONS"} and allowed_discovery_path(path)
                        except (TypeError, ValueError):
                            allowed = False
                        if allowed:
                            read_count += 1
                            await route.continue_()
                        else:
                            blocked_count += 1
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
                                "variant_sha256": hashlib.sha256(
                                    planned[key].encode() if request_method == "GET" else planned[key]
                                ).hexdigest(),
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
                            raise ValueError("Browser replay page changed before observed UI action")
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
                            raise ValueError("Observed browser UI control is missing or ambiguous")
                        current_action = f"replay-{index}"
                        await matches[0].click(timeout=3_000, no_wait_after=True)
                        await page.wait_for_timeout(350)
                    if not selected:
                        await page.wait_for_timeout(800)
                    if request_cap_hit:
                        raise ValueError("Browser replay request cap exceeded")
                    if not selected:
                        raise ValueError("Fresh browser request did not match captured input and replay action")
                    try:
                        receipt = await asyncio.wait_for(response_future, timeout=8)
                    except asyncio.TimeoutError as exc:
                        raise ValueError("Browser replay response missing") from exc
                    if request_cap_hit:
                        raise ValueError("Browser replay request cap exceeded")
                    receipt["browser_requests_seen"] = request_count
                    receipt["browser_read_requests_sent"] = read_count
                    receipt["browser_requests_blocked"] = blocked_count
                    receipts[key] = receipt
                finally:
                    await context.close()
        finally:
            await browser.close()
    return receipts


async def replay_observed_post_controls(
    private_exchange: bytes, *, parameter: str, payloads: dict[str, str],
    allowed_origins: list[str], storage_state: dict | None,
) -> dict[str, dict]:
    return await _replay_observed_controls(
        private_exchange, parameter=parameter, payloads=payloads,
        allowed_origins=allowed_origins, storage_state=storage_state,
        request_method="POST",
    )


async def replay_observed_get_controls(
    private_exchange: bytes, *, parameter: str, variants: dict[str, str],
    allowed_origins: list[str], storage_state: dict | None,
) -> dict[str, dict]:
    return await _replay_observed_controls(
        private_exchange, parameter=parameter, payloads=variants,
        allowed_origins=allowed_origins, storage_state=storage_state,
        request_method="GET",
    )
