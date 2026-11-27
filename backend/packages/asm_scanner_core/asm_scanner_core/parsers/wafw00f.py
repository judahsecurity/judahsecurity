"""wafw00f parser (text output, or JSON from ``-f json -o -``).

Ported from Vanguard ``run_wafw00f``. Fix: Vanguard took everything after
"is behind", so the vendor read "Cloudflare (Cloudflare Inc.) WAF" with ANSI
codes; the vendor and manufacturer are now separated and the WAF suffix dropped.
The generic-detection line ("seems to be behind a WAF") is reported as an
unidentified WAF instead of being lost.
"""

from __future__ import annotations

import re
from typing import Any, List, Optional

from asm_scanner_core.parsers.base import Observation, ParsedResult, extract_json, run_status, strip_ansi

TOOL = "wafw00f"

_BEHIND = re.compile(
    r"The site\s+(?P<site>\S+)\s+is behind\s+(?P<vendor>.+?)(?:\s+\((?P<maker>[^)]*)\))?\s+WAF\.?\s*$",
    re.I,
)
_BEHIND_LOOSE = re.compile(r"(?P<site>\S+)\s+is behind\s+(?P<vendor>.+?)\.?\s*$", re.I)
_GENERIC = re.compile(r"(?P<site>\S+)\s+seems to be behind a WAF", re.I)
_NONE = re.compile(r"No WAF detected", re.I)


def vendor_from_line(line: str) -> Optional[dict]:
    text = strip_ansi(line).strip()
    match = _BEHIND.search(text)
    if match:
        return {"site": match.group("site"), "vendor": match.group("vendor").strip(),
                "manufacturer": (match.group("maker") or "").strip()}
    match = _BEHIND_LOOSE.search(text)
    if match:
        vendor = re.sub(r"\s+WAF$", "", match.group("vendor").strip(), flags=re.I)
        vendor_match = re.match(r"(.+?)\s+\(([^)]*)\)$", vendor)
        if vendor_match:
            return {"site": match.group("site"), "vendor": vendor_match.group(1).strip(),
                    "manufacturer": vendor_match.group(2).strip()}
        return {"site": match.group("site"), "vendor": vendor, "manufacturer": ""}
    return None


def parse_wafw00f(output: str, exit_code: Optional[int] = None, *, timed_out: bool = False,
                  **_context: Any) -> ParsedResult:
    text = strip_ansi(output or "")
    observations: List[Observation] = []
    understood = False
    data = extract_json(text)
    if isinstance(data, list) and all(isinstance(r, dict) for r in data) and data:
        understood = True
        for row in data:
            if row.get("detected") and row.get("firewall") and str(row.get("firewall")).lower() != "none":
                vendor = str(row.get("firewall"))
                generic = vendor.lower() == "generic"
                observations.append(Observation(
                    kind="waf", title=f"WAF detected: {'unidentified (generic detection)' if generic else vendor}",
                    target=str(row.get("url") or ""),
                    attributes={"vendor": "" if generic else vendor,
                                "manufacturer": str(row.get("manufacturer") or ""), "generic": generic},
                ))
    else:
        for line in text.splitlines():
            if "is behind" in line:
                understood = True
                found = vendor_from_line(line)
                if found:
                    observations.append(Observation(
                        kind="waf", title=f"WAF detected: {found['vendor']}", target=found["site"],
                        attributes={"vendor": found["vendor"], "manufacturer": found["manufacturer"],
                                    "generic": False},
                    ))
            elif _GENERIC.search(line):
                understood = True
                observations.append(Observation(
                    kind="waf", title="WAF detected: unidentified (generic detection)",
                    target=_GENERIC.search(line).group("site"),
                    attributes={"vendor": "", "manufacturer": "", "generic": True},
                ))
            elif _NONE.search(line):
                understood = True
    status, reason = run_status(exit_code=exit_code, timed_out=timed_out, have_data=bool(observations))
    if status == "ok" and not understood:
        status, reason = "inconclusive", "no WAF verdict in output"
    return ParsedResult(tool=TOOL, status=status, observations=observations,
                        counts={"wafs": len(observations)}, reason=reason)
