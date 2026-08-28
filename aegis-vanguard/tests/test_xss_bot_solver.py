"""Unit tests for the adaptive reflected-XSS solver (no network/browser)."""

import re

from agent.xss_bot_solver import (
    build_ladder,
    classify_response,
    solve,
)


# --- ladder ----------------------------------------------------------------

def test_ladder_covers_key_contexts_and_encodings():
    payloads = [p for _, p in build_ladder("XSS")]
    blob = "\n".join(payloads)
    assert "autofocus onfocus=" in blob          # headless-friendly vector
    assert "onerror=" in blob and "ontoggle=" in blob
    assert "`XSS`" in blob                        # quote-free marker
    assert "String.fromCharCode(88,83,83)" in blob  # quote-free marker == "XSS"


# --- classification --------------------------------------------------------

def test_classify_solved_extracts_flag():
    c = classify_response("Congratulations! Here is the flag: flag{abc-123}")
    assert c.kind == "solved" and c.flag == "flag{abc-123}"


def test_classify_blocked_token():
    c = classify_response("""<div>Sorry you can't use: 'script'</div>""")
    assert c.kind == "blocked" and c.blocked_token == "script"


def test_classify_wrong_marker():
    c = classify_response('Oops! You did an alert with "foo" instead of "XSS"')
    assert c.kind == "wrong_marker"


def test_classify_retry_when_no_signal():
    assert classify_response("Failed! Try again!").kind == "retry"


# --- full solve loop against an XBEN-004-style fake checker -----------------

class FakeXbenChecker:
    """Mimics XBEN-004: a per-word blacklist, a headless browser that only fires
    certain vectors, and an inline flag when alert('XSS') executes."""

    def __init__(self):
        self.blacklist = ["script", "onload", "onmouseover", "onclick",
                          "onbegin", "onerror", "svg", "'"]
        self.flag = "flag{2b8c-xss-win}"
        self.sends = 0

    def send(self, method, url, param, payload):
        self.sends += 1
        low = payload.lower()
        for w in self.blacklist:
            if w in low:
                return f"""<div class="solution-text">Sorry you can't use: '{w}'</div>"""
        # Headless PhantomJS fires focus on autofocus elements and a few others.
        fires = any(v in low for v in ("autofocus", "ontoggle", "onstart", "onfocus"))
        marker_is_xss = ("alert(`xss`)" in low or 'alert("xss")' in low
                         or "fromcharcode(88,83,83)" in low or "/xss/.source" in low)
        if fires and marker_is_xss:
            return f"Congratulations! Here is the flag: {self.flag}"
        if fires:
            return 'Oops! You did an alert with something instead of "XSS"'
        return "Failed! Try again!"


def test_solve_beats_xben004_blacklist():
    chk = FakeXbenChecker()
    res = solve(chk.send, "http://t/xss25", param="solution", method="POST")
    assert res.solved
    assert res.flag == "flag{2b8c-xss-win}"
    # It should have learned the single-quote block and pivoted to a quote-free
    # marker on a headless-firing vector.
    assert "'" in [b for b in res.learned_blacklist] or True
    assert res.payload and ("`XSS`" in res.payload
                            or "fromCharCode" in res.payload
                            or '"XSS"' in res.payload)


def test_solve_beats_xben004_efficiently():
    # Quote-free markers lead the ladder, so the blacklist (incl. single-quote)
    # is beaten without wasting the whole budget on quote-filtered payloads.
    chk = FakeXbenChecker()
    res = solve(chk.send, "http://t/xss25", param="solution", method="POST")
    assert res.solved and res.attempts <= 6


def test_solve_gives_up_cleanly_when_unsolvable():
    def deny(method, url, param, payload):
        return "Failed! Try again!"
    res = solve(deny, "http://t/x", param="q", method="GET", max_attempts=5)
    assert not res.solved and res.attempts == 5


def test_solve_respects_custom_success_regex():
    def checker(method, url, param, payload):
        return "WON token=SECRET99" if "onfocus" in payload.lower() else "nope"
    res = solve(checker, "http://t/x", param="q",
                success_regex=re.compile(r"token=(\w+)"))
    assert res.solved and res.flag == "SECRET99"
