"""katana JSON-lines parser: endpoint counts and ``-fx`` form extraction.

Ported from Vanguard ``run_katana``, which ran with ``-fx`` but discarded the
extracted forms. Forms (method, action, enctype, input names) become
observations; endpoints are counted, not listed, since crawl URLs already flow
through the backend's discovery ingestion. Plain-URL output is counted too.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from asm_scanner_core.parsers.base import Observation, ParsedResult, iter_json_lines, run_status, strip_ansi

TOOL = "katana"


def _forms(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    response = data.get("response") if isinstance(data.get("response"), dict) else {}
    forms = response.get("forms") or data.get("forms") or []
    return [f for f in forms if isinstance(f, dict)]


def parse_katana(output: str, exit_code: Optional[int] = None, *, timed_out: bool = False,
                 **_context: Any) -> ParsedResult:
    text = strip_ansi(output or "")
    endpoints = set()
    seen_forms = set()
    observations: List[Observation] = []
    json_lines = 0
    for data in iter_json_lines(text):
        json_lines += 1
        request = data.get("request") if isinstance(data.get("request"), dict) else {}
        endpoint = str(request.get("endpoint") or data.get("endpoint") or "")
        if endpoint:
            endpoints.add(endpoint)
        for form in _forms(data):
            action = str(form.get("action") or endpoint)
            method = str(form.get("method") or "GET").upper()
            names = [str(n) for n in (form.get("parameters") or form.get("inputs") or [])
                     if isinstance(n, (str, int))]
            key = (method, action.split("?")[0], tuple(sorted(names)))
            if key in seen_forms:
                continue
            seen_forms.add(key)
            observations.append(Observation(
                kind="form", title=f"{method} form -> {urlsplit(action).path or action}",
                target=action.split("?")[0],
                attributes={"method": method, "enctype": form.get("enctype") or "",
                            "inputs": names, "found_on": endpoint.split("?")[0]},
            ))
    if not json_lines:
        endpoints.update(line.strip() for line in text.splitlines() if line.strip().startswith("http"))
    status, reason = run_status(exit_code=exit_code, timed_out=timed_out,
                                have_data=bool(endpoints or observations))
    return ParsedResult(tool=TOOL, status=status, observations=observations,
                        counts={"endpoints": len(endpoints), "forms": len(observations)}, reason=reason)
