"""
Browser Automation Service for security testing.

Provides Playwright-based headless browser automation for the AI agent
to perform live web application exploit testing:
- XSS payload injection and reflected/stored detection
- Form-based injection testing (SQLi, command injection, template injection)
- Authentication bypass (cookie manipulation, forced browsing)
- SSRF detection via network request interception
- JavaScript execution and DOM inspection
- Multi-step exploit chains with session persistence

Actions are submitted as JSON and executed sequentially in a single
browser context, preserving cookies/sessions across steps.
"""

import asyncio
import json
import logging
import os
import re
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)

SCREENSHOTS_DIR = os.environ.get("SCREENSHOTS_DIR", "/app/data/screenshots")
MAX_ACTIONS = 20
PAGE_TIMEOUT_MS = 20000
ACTION_TIMEOUT_MS = 10000


@dataclass
class ActionResult:
    action: str
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


@dataclass
class BrowserSessionResult:
    success: bool
    actions_executed: int
    results: List[Dict[str, Any]] = field(default_factory=list)
    console_logs: List[str] = field(default_factory=list)
    network_requests: List[Dict[str, str]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    final_url: Optional[str] = None
    final_cookies: List[Dict[str, str]] = field(default_factory=list)


def _check_playwright() -> bool:
    try:
        from playwright.async_api import async_playwright  # noqa: F401
        return True
    except ImportError:
        return False


async def execute_browser_actions(actions_json: str) -> Dict[str, Any]:
    """
    Execute a sequence of browser actions for security testing.

    Args:
        actions_json: JSON string describing the action sequence.

    Supported action types:
        navigate      — {"action": "navigate", "url": "https://target.com/login"}
        fill          — {"action": "fill", "selector": "#username", "value": "admin"}
        click         — {"action": "click", "selector": "#submit"}
        type          — {"action": "type", "selector": "input", "value": "text", "delay": 50}
        execute_js    — {"action": "execute_js", "script": "document.cookie"}
        get_source    — {"action": "get_source"}
        get_cookies   — {"action": "get_cookies"}
        set_cookie    — {"action": "set_cookie", "name": "role", "value": "admin", "url": "..."}
        screenshot    — {"action": "screenshot"}
        wait          — {"action": "wait", "ms": 2000}
        check_xss     — {"action": "check_xss", "url": "https://target.com/search?q=<script>alert(1)</script>"}
        submit_form   — {"action": "submit_form", "url": "https://target.com/login",
                         "fields": {"username": "admin", "password": "test"}, "submit_selector": "#login-btn"}
        check_response— {"action": "check_response", "url": "https://target.com/admin",
                         "expected_status": 403, "description": "auth bypass test"}

    Returns:
        Dict with results of all actions, console logs, and intercepted network requests.
    """
    if not _check_playwright():
        return {
            "success": False,
            "output": "Playwright not installed. Run: pip install playwright && playwright install chromium",
            "error": "playwright_not_available",
        }

    try:
        if isinstance(actions_json, dict):
            spec = actions_json
        else:
            spec = json.loads(actions_json)
    except (json.JSONDecodeError, TypeError) as e:
        return {
            "success": False,
            "output": f"Invalid JSON: {e}. Pass a JSON object with an 'actions' array.",
            "error": "invalid_json",
        }

    actions = spec if isinstance(spec, list) else spec.get("actions", [])
    if not actions:
        return {
            "success": False,
            "output": "No actions provided. Include an 'actions' array.",
            "error": "no_actions",
        }

    if len(actions) > MAX_ACTIONS:
        actions = actions[:MAX_ACTIONS]

    # Auth handoff from deep_crawl / prior browser session
    storage_state = None if isinstance(spec, list) else spec.get("storage_state")
    seed_cookies = None if isinstance(spec, list) else spec.get("cookies")
    login_spec = None if isinstance(spec, list) else spec.get("login")

    from playwright.async_api import async_playwright

    session = BrowserSessionResult(success=True, actions_executed=0)
    exported_storage_state = None

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
            ],
        )
        try:
            ctx_kwargs: Dict[str, Any] = {
                "viewport": {"width": 1280, "height": 720},
                "ignore_https_errors": True,
                "user_agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
            }
            if isinstance(storage_state, dict) and storage_state:
                ctx_kwargs["storage_state"] = storage_state
            context = await browser.new_context(**ctx_kwargs)
            if isinstance(seed_cookies, list) and seed_cookies and not storage_state:
                try:
                    await context.add_cookies(seed_cookies)
                except Exception as e:
                    session.errors.append(f"cookies: {str(e)[:120]}")
            page = await context.new_page()

            # Optional self-service login before the action chain
            if isinstance(login_spec, dict) and login_spec:
                try:
                    from app.services.deep_crawl_service import _perform_login
                    login_result = type("R", (), {"errors": []})()
                    ok = await _perform_login(page, login_spec, 25000, login_result)
                    session.results.append(asdict(ActionResult(
                        action="login",
                        success=bool(ok),
                        data={"authenticated": bool(ok)},
                        error=None if ok else "; ".join(getattr(login_result, "errors", [])[:3]),
                    )))
                    session.actions_executed += 1
                except Exception as e:
                    session.errors.append(f"login: {str(e)[:200]}")

            page.on("console", lambda msg: session.console_logs.append(
                f"[{msg.type}] {msg.text}"
            ))

            page.on("request", lambda req: session.network_requests.append({
                "method": req.method,
                "url": req.url,
            }) if len(session.network_requests) < 200 else None)

            for action_spec in actions:
                if not isinstance(action_spec, dict):
                    session.errors.append(f"Invalid action (not a dict): {action_spec}")
                    continue
                action_type = action_spec.get("action", "").lower()
                try:
                    result = await _execute_action(page, context, action_type, action_spec, session)
                    session.results.append(asdict(result))
                    session.actions_executed += 1
                except Exception as e:
                    err_msg = f"Action '{action_type}' failed: {str(e)[:500]}"
                    session.results.append(asdict(ActionResult(
                        action=action_type, success=False, error=err_msg
                    )))
                    session.errors.append(err_msg)
                    session.actions_executed += 1

            session.final_url = page.url
            try:
                cookies = await context.cookies()
                session.final_cookies = [
                    {"name": c["name"], "value": c["value"], "domain": c.get("domain", "")}
                    for c in cookies
                ]
            except Exception:
                pass
            try:
                exported_storage_state = await context.storage_state()
            except Exception:
                exported_storage_state = None

            await context.close()
        finally:
            await browser.close()

    output = _format_session_output(session)
    auth_session = None
    if isinstance(exported_storage_state, dict) and exported_storage_state:
        auth_session = {
            "target": session.final_url,
            "authenticated": True,
            "storage_state": exported_storage_state,
            "cookies": exported_storage_state.get("cookies") or [],
        }
    return {
        "success": session.success and not session.errors,
        "output": output,
        "error": "; ".join(session.errors) if session.errors else None,
        "exit_code": 0 if not session.errors else 1,
        "auth_session": auth_session,
    }


async def _execute_action(
    page, context, action_type: str, spec: Dict[str, Any], session: BrowserSessionResult
) -> ActionResult:
    """Dispatch and execute a single browser action."""

    if action_type == "navigate":
        url = spec.get("url", "")
        if not url:
            return ActionResult(action="navigate", success=False, error="'url' required")
        resp = await page.goto(url, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
        await asyncio.sleep(0.5)
        status = resp.status if resp else None
        title = await page.title()
        return ActionResult(action="navigate", success=True, data={
            "url": page.url, "status": status, "title": title,
        })

    elif action_type == "fill":
        selector = spec.get("selector", "")
        value = spec.get("value", "")
        await page.fill(selector, value, timeout=ACTION_TIMEOUT_MS)
        return ActionResult(action="fill", success=True, data={
            "selector": selector, "value": value,
        })

    elif action_type == "click":
        selector = spec.get("selector", "")
        await page.click(selector, timeout=ACTION_TIMEOUT_MS)
        await asyncio.sleep(0.5)
        return ActionResult(action="click", success=True, data={
            "selector": selector, "url_after": page.url,
        })

    elif action_type == "type":
        selector = spec.get("selector", "")
        value = spec.get("value", "")
        delay = spec.get("delay", 50)
        await page.type(selector, value, delay=delay, timeout=ACTION_TIMEOUT_MS)
        return ActionResult(action="type", success=True, data={
            "selector": selector, "value": value,
        })

    elif action_type == "execute_js":
        script = spec.get("script", "")
        if not script:
            return ActionResult(action="execute_js", success=False, error="'script' required")
        result = await page.evaluate(script)
        result_str = str(result)[:5000] if result is not None else "undefined"
        return ActionResult(action="execute_js", success=True, data={
            "result": result_str,
        })

    elif action_type == "get_source":
        content = await page.content()
        truncated = content[:10000]
        return ActionResult(action="get_source", success=True, data={
            "length": len(content),
            "content": truncated + ("..." if len(content) > 10000 else ""),
        })

    elif action_type == "get_cookies":
        cookies = await context.cookies()
        return ActionResult(action="get_cookies", success=True, data={
            "cookies": [
                {"name": c["name"], "value": c["value"][:200], "domain": c.get("domain", ""),
                 "httpOnly": c.get("httpOnly", False), "secure": c.get("secure", False),
                 "sameSite": c.get("sameSite", "")}
                for c in cookies
            ]
        })

    elif action_type == "set_cookie":
        name = spec.get("name", "")
        value = spec.get("value", "")
        url = spec.get("url", page.url)
        await context.add_cookies([{
            "name": name, "value": value, "url": url,
        }])
        return ActionResult(action="set_cookie", success=True, data={
            "name": name, "value": value,
        })

    elif action_type == "screenshot":
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
        path = os.path.join(SCREENSHOTS_DIR, "browser_auto", f"screenshot_{ts}.png")
        Path(os.path.dirname(path)).mkdir(parents=True, exist_ok=True)
        await page.screenshot(path=path, full_page=spec.get("full_page", False))
        return ActionResult(action="screenshot", success=True, data={
            "path": path,
        })

    elif action_type == "wait":
        ms = min(spec.get("ms", 1000), 10000)
        await asyncio.sleep(ms / 1000)
        return ActionResult(action="wait", success=True, data={"ms": ms})

    elif action_type == "check_xss":
        url = spec.get("url", "")
        payload = spec.get("payload", "")
        if not url:
            return ActionResult(action="check_xss", success=False, error="'url' required")

        dialog_triggered = []
        page.on("dialog", lambda d: _handle_dialog(d, dialog_triggered))

        resp = await page.goto(url, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
        await asyncio.sleep(1)
        source = await page.content()

        reflected = False
        if payload:
            reflected = payload in source
        else:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for vals in params.values():
                for v in vals:
                    if v in source and ("<" in v or ">" in v or "script" in v.lower()):
                        reflected = True
                        break

        xss_detected = bool(dialog_triggered) or reflected
        alert_text = dialog_triggered[0] if dialog_triggered else None

        return ActionResult(action="check_xss", success=True, data={
            "xss_detected": xss_detected,
            "dialog_triggered": bool(dialog_triggered),
            "alert_text": alert_text,
            "reflected_in_source": reflected,
            "url": page.url,
            "status": resp.status if resp else None,
        })

    elif action_type == "submit_form":
        url = spec.get("url", "")
        fields = spec.get("fields", {})
        submit_selector = spec.get("submit_selector", "")

        if url:
            await page.goto(url, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
            await asyncio.sleep(0.5)

        for selector, value in fields.items():
            try:
                await page.fill(selector, str(value), timeout=ACTION_TIMEOUT_MS)
            except Exception:
                try:
                    await page.type(selector, str(value), timeout=ACTION_TIMEOUT_MS)
                except Exception as e:
                    return ActionResult(action="submit_form", success=False,
                                       error=f"Failed to fill '{selector}': {e}")

        if submit_selector:
            await page.click(submit_selector, timeout=ACTION_TIMEOUT_MS)
        else:
            await page.keyboard.press("Enter")
        await asyncio.sleep(1)

        status = None
        title = await page.title()
        source_snippet = (await page.content())[:3000]

        return ActionResult(action="submit_form", success=True, data={
            "url_after": page.url,
            "title": title,
            "response_snippet": source_snippet,
        })

    elif action_type == "check_response":
        url = spec.get("url", "")
        expected_status = spec.get("expected_status")
        description = spec.get("description", "response check")

        if not url:
            return ActionResult(action="check_response", success=False, error="'url' required")

        resp = await page.goto(url, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
        actual_status = resp.status if resp else None
        title = await page.title()
        source_snippet = (await page.content())[:3000]

        bypass_detected = False
        if expected_status and actual_status and actual_status != expected_status:
            bypass_detected = True

        return ActionResult(action="check_response", success=True, data={
            "description": description,
            "url": page.url,
            "status": actual_status,
            "expected_status": expected_status,
            "bypass_detected": bypass_detected,
            "title": title,
            "response_snippet": source_snippet,
        })

    else:
        return ActionResult(
            action=action_type, success=False,
            error=f"Unknown action: '{action_type}'. Supported: navigate, fill, click, type, "
                  f"execute_js, get_source, get_cookies, set_cookie, screenshot, wait, "
                  f"check_xss, submit_form, check_response"
        )


async def _handle_dialog(dialog, triggered_list: list):
    """Accept dialogs (alert/confirm/prompt) and record them."""
    triggered_list.append(dialog.message)
    try:
        await dialog.accept()
    except Exception:
        pass


def _format_session_output(session: BrowserSessionResult) -> str:
    """Format session results for the agent."""
    lines = [f"Browser session completed: {session.actions_executed} actions executed\n"]

    for i, r in enumerate(session.results, 1):
        status = "OK" if r.get("success") else "FAIL"
        lines.append(f"--- Action {i}: {r.get('action', '?')} [{status}] ---")
        if r.get("data"):
            for k, v in r["data"].items():
                val_str = str(v)
                if len(val_str) > 500:
                    val_str = val_str[:500] + "..."
                lines.append(f"  {k}: {val_str}")
        if r.get("error"):
            lines.append(f"  ERROR: {r['error']}")
        lines.append("")

    if session.console_logs:
        lines.append(f"--- Console Logs ({len(session.console_logs)}) ---")
        for log in session.console_logs[:30]:
            lines.append(f"  {log[:300]}")
        if len(session.console_logs) > 30:
            lines.append(f"  ... ({len(session.console_logs) - 30} more)")
        lines.append("")

    if session.final_url:
        lines.append(f"Final URL: {session.final_url}")
    if session.final_cookies:
        lines.append(f"Session Cookies: {len(session.final_cookies)}")
        for c in session.final_cookies[:10]:
            lines.append(f"  {c['name']}={c['value'][:60]}{'...' if len(c['value']) > 60 else ''} (domain={c['domain']})")

    outgoing = [r for r in session.network_requests if not r["url"].startswith("data:")]
    if outgoing:
        unique_domains = set()
        for r in outgoing:
            try:
                from urllib.parse import urlparse
                unique_domains.add(urlparse(r["url"]).netloc)
            except Exception:
                pass
        lines.append(f"\nNetwork: {len(outgoing)} requests to {len(unique_domains)} domains")
        for d in sorted(unique_domains)[:20]:
            lines.append(f"  - {d}")

    return "\n".join(lines)
