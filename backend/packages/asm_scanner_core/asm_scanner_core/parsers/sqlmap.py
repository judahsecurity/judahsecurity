"""sqlmap console-output parser: injectable parameters, techniques, DBMS.

Ported from Vanguard ``run_sqlmap``. Fixes:

* Vanguard's fallback ``\\binjectable\\b`` matched sqlmap's negative verdicts
  ("all tested parameters do not appear to be injectable", "does not seem to
  be injectable") and produced a critical "(detected)" finding on clean runs.
  Negative lines are now excluded and the injection-point block is the source.
* The ``Parameter: ... injectable`` regex ran with DOTALL across the whole
  output and could pair a parameter with an unrelated later line; parameters
  are now read from the ``---`` injection-point block or the explicit
  "parameter 'x' is vulnerable" line.
* Techniques are kept per parameter, and the back-end DBMS is extracted.

Payload strings are not returned (they can echo other request fields).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from asm_scanner_core.parsers.base import Observation, ParsedResult, run_status, strip_ansi

TOOL = "sqlmap"

_BLOCK = re.compile(r"injection point\(s\)[^\n]*\n---\n(?P<body>.*?)\n---", re.S | re.I)
_PARAM = re.compile(r"^Parameter:\s*(?P<name>.+?)\s+\((?P<place>[^)]+)\)\s*$", re.M)
_TYPE = re.compile(r"^\s+Type:\s*(?P<type>.+?)\s*$", re.M)
_TITLE = re.compile(r"^\s+Title:\s*(?P<title>.+?)\s*$", re.M)
_VULN_LINE = re.compile(
    r"(?P<place>GET|POST|Cookie|Header|URI|User-Agent|Referer|Host|\(custom\) POST|JSON|XML)?\s*"
    r"parameter\s+'(?P<name>[^']+)'\s+(?:is vulnerable|appears to be '(?P<tech>[^']+)' injectable)",
    re.I,
)
_NEGATIVE = re.compile(r"(?:not|n't)\s+(?:seem|appear)s?\s+to\s+be\s+injectable|false positive", re.I)
_DBMS = re.compile(r"back-end DBMS(?: is|:)\s*(?P<dbms>[^\n\r]+)", re.I)
_RESUMED = re.compile(r"sqlmap resumed the following injection point", re.I)
_CRITICAL = re.compile(r"\[CRITICAL\]\s*(?P<msg>[^\n]+)")
_ENDED = re.compile(r"\[\*\]\s*ending @|fetched data logged to", re.I)
_NO_INJECTION = re.compile(r"all tested parameters do not appear to be injectable", re.I)


def _technique_family(type_line: str) -> str:
    lowered = type_line.lower()
    for key, letter in (("boolean", "B"), ("error", "E"), ("union", "U"), ("stacked", "S"),
                        ("time", "T"), ("inline", "Q")):
        if key in lowered:
            return letter
    return ""


def parse_sqlmap(output: str, exit_code: Optional[int] = None, *, timed_out: bool = False,
                 **_context: Any) -> ParsedResult:
    text = strip_ansi(output or "").replace("\r\n", "\n")
    params: Dict[tuple, Dict[str, Any]] = {}
    for block in _BLOCK.finditer(text):
        body = block.group("body")
        heads = list(_PARAM.finditer(body))
        for index, head in enumerate(heads):
            end = heads[index + 1].start() if index + 1 < len(heads) else len(body)
            section = body[head.end():end]
            key = (head.group("name").strip(), head.group("place").strip().upper())
            row = params.setdefault(key, {"types": [], "titles": []})
            for type_match in _TYPE.finditer(section):
                if type_match.group("type") not in row["types"]:
                    row["types"].append(type_match.group("type"))
            for title_match in _TITLE.finditer(section):
                if title_match.group("title") not in row["titles"]:
                    row["titles"].append(title_match.group("title"))
    from_block = set(params)
    refuted = set()
    for line in text.splitlines():
        if _NEGATIVE.search(line):
            named = re.search(r"parameter\s+'([^']+)'", line, re.I)
            if named:
                refuted.add(named.group(1).strip())
            continue
        match = _VULN_LINE.search(line)
        if not match:
            continue
        name = match.group("name").strip()
        place = (match.group("place") or "").strip().upper()
        existing = next((k for k in params if k[0] == name and (not place or k[1] == place)), None)
        row = params.setdefault(existing or (name, place), {"types": [], "titles": []})
        if match.group("tech") and match.group("tech") not in row["titles"]:
            row["titles"].append(match.group("tech"))

    # A line-level "appears injectable" later refuted by sqlmap itself is dropped;
    # parameters listed in the injection-point block are authoritative.
    for key in [k for k in params if k not in from_block and k[0] in refuted]:
        params.pop(key)
    dbms_match = None
    for dbms_match in _DBMS.finditer(text):
        pass
    dbms = dbms_match.group("dbms").strip() if dbms_match else ""
    resumed = bool(_RESUMED.search(text))
    observations: List[Observation] = []
    for (name, place), row in sorted(params.items()):
        techniques = row["types"] or row["titles"]
        letters = "".join(sorted({_technique_family(t) for t in techniques} - {""}))
        observations.append(Observation(
            kind="sql_injection", title=f"sqlmap reports injectable parameter '{name}'"
            + (f" ({place})" if place else ""),
            severity="high", parameter=name,
            detail="; ".join(techniques),
            attributes={"place": place, "techniques": techniques, "technique_letters": letters,
                        "titles": row["titles"], "dbms": dbms, "resumed_from_session": resumed},
        ))
    status, reason = run_status(exit_code=exit_code, timed_out=timed_out, have_data=bool(observations))
    critical = [m.group("msg").strip() for m in _CRITICAL.finditer(text)]
    if status == "ok" and not observations:
        if critical and not _NO_INJECTION.search(text):
            status, reason = "inconclusive", critical[-1]
        elif not (_NO_INJECTION.search(text) or _ENDED.search(text)):
            status, reason = "inconclusive", "sqlmap did not report a verdict"
    counts = {"injectable_parameters": len(observations)}
    if dbms:
        counts["dbms_identified"] = 1
    return ParsedResult(tool=TOOL, status=status, observations=observations, counts=counts, reason=reason)
