"""Arjun parameter-discovery parser (JSON from ``-oJ`` or console output).

Ported from Vanguard ``run_arjun``, keeping its semantics: a timeout or a
target that stopped answering is *inconclusive* (surface not fully mapped),
never an empty "no parameters" result. Fix: current Arjun writes
``{url: {"params": [...], "method": ..., "headers": ...}}``; Vanguard's
``params.extend(p_list)`` on that dict added the keys "params", "method",
"headers" as parameter names. Both the dict and the older list form are read.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from asm_scanner_core.parsers.base import Observation, ParsedResult, extract_json, run_status, strip_ansi

TOOL = "arjun"

_FOUND = re.compile(r"Parameters? found:\s*(?P<names>.+)$", re.I | re.M)
_NONE = re.compile(r"No parameters were discovered", re.I)
_TARGET_TIMEOUT = re.compile(r"timed out|connection (?:refused|reset|error)|unable to connect|"
                             r"target is (?:unstable|not stable)", re.I)


def parse_arjun(output: str, exit_code: Optional[int] = None, *, timed_out: bool = False,
                target: str = "", **_context: Any) -> ParsedResult:
    text = strip_ansi(output or "")
    found: Dict[str, Dict[str, Any]] = {}
    data = extract_json(text)
    if isinstance(data, dict) and data and all(isinstance(v, (dict, list)) for v in data.values()):
        for url, entry in data.items():
            if isinstance(entry, dict):
                names = entry.get("params") or entry.get("parameters") or []
                method = str(entry.get("method") or "GET").upper()
            else:
                names, method = entry, "GET"
            found[str(url)] = {"names": [str(n) for n in names if isinstance(n, (str, int))], "method": method}
    else:
        for match in _FOUND.finditer(text):
            names = [n.strip() for n in match.group("names").split(",") if n.strip()]
            found.setdefault(target, {"names": [], "method": "GET"})["names"].extend(names)
    observations: List[Observation] = []
    for url, entry in found.items():
        for name in dict.fromkeys(entry["names"]):
            observations.append(Observation(kind="parameter", title=f"Parameter discovered: {name}",
                                            target=url, parameter=name,
                                            attributes={"method": entry["method"]}))
    status, reason = run_status(exit_code=exit_code, timed_out=timed_out, have_data=bool(observations))
    if status == "ok" and not observations:
        if _TARGET_TIMEOUT.search(text):
            status, reason = "inconclusive", "target timed out or became unstable; surface not fully mapped"
        elif not (_NONE.search(text) or isinstance(data, dict)):
            status, reason = "inconclusive", "no Arjun verdict in output"
    if timed_out:
        reason = reason or "timed out"
    return ParsedResult(tool=TOOL, status=status, observations=observations,
                        counts={"parameters": len(observations), "urls": len(found)}, reason=reason)
