"""XSStrike console-output parser (complete vs partial runs).

Ported from Vanguard ``run_xsstrike``: a completed run is ``ok``; a run killed
by a timeout with payload signal is ``partial`` (worth a retry or a browser
check); a timeout or error with no signal is ``inconclusive``. Fixes: the
efficiency regex ``[5-9]\\d`` missed ``Efficiency: 100``; the bare
``Confirmed|Successful`` fallback matched unrelated text and is dropped.
Observations are leads for browser verification, never confirmations.
"""

from __future__ import annotations

import re
from typing import Any, List, Optional

from asm_scanner_core.parsers.base import Observation, ParsedResult, run_status, strip_ansi

TOOL = "xsstrike"

_PARAM = re.compile(r"Testing parameter:\s*(?P<name>\S+)", re.I)
_PAYLOAD = re.compile(r"Payload:\s*(?P<payload>.+)$", re.I)
_EFFICIENCY = re.compile(r"Efficiency:\s*(?P<n>\d{1,3})", re.I)
_CONFIDENCE = re.compile(r"Confidence:\s*(?P<n>\d{1,2})", re.I)
_DOM = re.compile(r"Potentially vulnerable objects found", re.I)
_VULN_PAGE = re.compile(r"Vulnerable webpage:\s*(?P<url>\S+)", re.I)
_NO_PARAMS = re.compile(r"No parameters to test", re.I)
_NO_REFLECTION = re.compile(r"No reflection found", re.I)
_WAF = re.compile(r"WAF detected:\s*(?P<waf>.+)$", re.I | re.M)


def parse_xsstrike(output: str, exit_code: Optional[int] = None, *, timed_out: bool = False,
                   target: str = "", **_context: Any) -> ParsedResult:
    text = strip_ansi(output or "")
    observations: List[Observation] = []
    current_param = ""
    pending: Optional[dict] = None

    def flush() -> None:
        nonlocal pending
        if pending is None:
            return
        efficiency = pending.get("efficiency")
        severity = "medium" if efficiency is not None and efficiency >= 90 else "low"
        observations.append(Observation(
            kind="xss_candidate",
            title="XSStrike reflected payload candidate" + (f" in '{pending['param']}'" if pending["param"] else ""),
            severity=severity, target=pending.get("url") or target, parameter=pending["param"],
            detail=pending["payload"][:200],
            attributes={"efficiency": efficiency, "confidence": pending.get("confidence"),
                        "verified_in_browser": False},
        ))
        pending = None

    for line in text.splitlines():
        param = _PARAM.search(line)
        if param:
            flush()
            current_param = param.group("name")
            continue
        payload = _PAYLOAD.search(line)
        if payload:
            flush()
            pending = {"param": current_param, "payload": payload.group("payload").strip()}
            continue
        efficiency = _EFFICIENCY.search(line)
        if efficiency and pending is not None:
            pending["efficiency"] = int(efficiency.group("n"))
            continue
        confidence = _CONFIDENCE.search(line)
        if confidence and pending is not None:
            pending["confidence"] = int(confidence.group("n"))
            continue
        page = _VULN_PAGE.search(line)
        if page:
            flush()
            observations.append(Observation(kind="xss_candidate", title="XSStrike flagged vulnerable webpage",
                                            severity="medium", target=page.group("url"),
                                            attributes={"verified_in_browser": False}))
    flush()
    if _DOM.search(text):
        observations.append(Observation(kind="dom_sink", title="XSStrike found potentially vulnerable DOM objects",
                                        severity="low", target=target,
                                        attributes={"verified_in_browser": False}))
    waf = _WAF.search(text)
    if waf and "offline" not in waf.group("waf").lower():
        observations.append(Observation(kind="waf", title=f"WAF detected: {waf.group('waf').strip()}",
                                        target=target, attributes={"vendor": waf.group("waf").strip()}))
    signal = any(o.kind == "xss_candidate" for o in observations)
    status, reason = run_status(exit_code=exit_code, timed_out=timed_out, have_data=signal)
    if status == "partial":
        reason = "incomplete run with payload signal; retry or verify in a browser"
    if status == "ok" and not observations and not (_NO_PARAMS.search(text) or _NO_REFLECTION.search(text)
                                                    or _PARAM.search(text)):
        status, reason = "inconclusive", "no XSStrike verdict in output"
    return ParsedResult(tool=TOOL, status=status, observations=observations,
                        counts={"payload_candidates": sum(1 for o in observations if o.kind == "xss_candidate"),
                                "parameters_tested": len(set(_PARAM.findall(text)))},
                        reason=reason)
