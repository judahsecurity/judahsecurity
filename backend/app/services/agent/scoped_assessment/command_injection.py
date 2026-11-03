"""Bounded time-based OS command injection proof on an operator-approved input.

A server that pauses for an attacker-chosen interval is executing an injected
shell command. The probe measures a stable zero-delay baseline and a fresh
bounded-delay probe against the *same* operator-supplied injection template,
each repeated, and confirms only a consistent, repeatable delay separation.

Nothing here is model generated: the injection template is operator policy
(the hunter forms it from an observed endpoint), the sleep interval is bounded,
and the correlation token is nonce bound. The payload only induces a timed
sleep; it writes nothing and reads nothing. A separate actor must repeat the
recipe with a different nonce before a finding is published.
"""

from __future__ import annotations

import time
from urllib.error import HTTPError
from urllib.request import Request, build_opener

from app.services.agent.assessment_proxy import assessment_urllib_handlers

from .browser import assert_in_scope
from .http_observe import _cookie_header, _NoRedirect

# The token an operator-supplied injection template carries where the injected
# sleep interval (in seconds) is substituted.
DELAY_TOKEN = "__PROWL_DELAY__"

MIN_DELAY = 2
MAX_DELAY = 8
MIN_TRIALS = 2
MAX_TRIALS = 5
# A probe sample must clear the slowest control sample by at least this
# fraction of the injected delay. Keeps slow-but-honest endpoints from being
# mistaken for an injected sleep while tolerating ordinary jitter.
SEPARATION_RATIO = 0.6
_REQUEST_TIMEOUT = MAX_DELAY + 12
_READ_CAP = 4096


def command_timing_proof_valid(result: dict) -> bool:
    """Structural gate: a repeated, bounded delay separation with a fresh token."""
    if (not isinstance(result, dict)
            or result.get("operation") != "scoped_command_timing"
            or result.get("test_type") != "command_injection"):
        return False
    parameter = result.get("parameter")
    nonce = str(result.get("nonce", ""))
    delay = result.get("delay_seconds")
    if (not isinstance(parameter, str) or not parameter or len(parameter) > 128
            or not nonce or len(nonce) > 40 or not nonce.isalnum()
            or not isinstance(delay, int) or not MIN_DELAY <= delay <= MAX_DELAY):
        return False
    control = result.get("control") or {}
    probe = result.get("probe") or {}
    control_samples = control.get("samples")
    probe_samples = probe.get("samples")
    if (not isinstance(control_samples, list) or not isinstance(probe_samples, list)
            or not MIN_TRIALS <= len(control_samples) <= MAX_TRIALS
            or len(control_samples) != len(probe_samples)
            or not all(isinstance(value, (int, float)) and value >= 0
                       for value in [*control_samples, *probe_samples])):
        return False
    separation = min(probe_samples) - max(control_samples)
    return separation >= SEPARATION_RATIO * delay and result.get("proof_confirmed") is True


def _timed_get(opener, url: str, headers: dict) -> float | None:
    """Return elapsed seconds for one bounded GET, or None if it never answered."""
    request = Request(url, headers=headers, method="GET")
    start = time.perf_counter()
    try:
        response = opener.open(request, timeout=_REQUEST_TIMEOUT)
    except HTTPError:
        # A 4xx/5xx still consumed measurable server time, which is what we time.
        return round(time.perf_counter() - start, 4)
    except OSError:
        return None
    with response:
        response.read(_READ_CAP)
    return round(time.perf_counter() - start, 4)


def _unconfirmed(parameter: str, nonce: str, delay: int, trials: int) -> dict:
    return {
        "operation": "scoped_command_timing", "test_type": "command_injection",
        "parameter": parameter, "nonce": nonce, "delay_seconds": delay,
        "trials": trials, "requests_sent": 0,
        "control": {"samples": [], "max": None},
        "probe": {"samples": [], "min": None},
        "separation": None, "proof_confirmed": False, "finding": False,
    }


def probe_command_timing(injection_template: str, *, parameter: str,
                         delay_seconds: int, allowed_origin: str,
                         state: dict | None, nonce: str, trials: int = 3) -> dict:
    """Prove time-based command injection with a bounded, repeated delay.

    ``injection_template`` is an in-scope URL carrying ``__PROWL_DELAY__`` where
    the injected sleep interval is substituted. The zero-delay control sets the
    baseline; the bounded-delay probe must clear it by a repeatable margin.
    """
    if not nonce or len(nonce) > 40 or not nonce.isalnum():
        raise ValueError("A bounded alphanumeric nonce is required")
    if DELAY_TOKEN not in injection_template:
        raise ValueError(f"The injection template must carry {DELAY_TOKEN}")
    if not parameter or len(parameter) > 128:
        raise ValueError("A bounded parameter name is required")
    delay = int(delay_seconds)
    if not MIN_DELAY <= delay <= MAX_DELAY:
        raise ValueError("The injected delay must be bounded")
    trials = max(MIN_TRIALS, min(MAX_TRIALS, int(trials or 3)))

    control_url = injection_template.replace(DELAY_TOKEN, "0")
    probe_url = injection_template.replace(DELAY_TOKEN, str(delay))
    for url in (control_url, probe_url):
        assert_in_scope(url, [allowed_origin])

    headers = {"Accept": "*/*"}
    cookie = _cookie_header(state, control_url)
    if cookie:
        headers["Cookie"] = cookie
    opener = build_opener(*assessment_urllib_handlers(), _NoRedirect())

    control_samples: list[float] = []
    probe_samples: list[float] = []
    for samples, url in ((control_samples, control_url), (probe_samples, probe_url)):
        for _ in range(trials):
            elapsed = _timed_get(opener, url, headers)
            if elapsed is None:
                return _unconfirmed(parameter, nonce, delay, trials)
            samples.append(elapsed)

    control_max = max(control_samples)
    probe_min = min(probe_samples)
    separation = round(probe_min - control_max, 4)
    confirmed = separation >= SEPARATION_RATIO * delay
    return {
        "operation": "scoped_command_timing", "test_type": "command_injection",
        "parameter": parameter, "nonce": nonce, "delay_seconds": delay,
        "trials": trials, "requests_sent": 2 * trials,
        "control": {"samples": control_samples, "max": control_max},
        "probe": {"samples": probe_samples, "min": probe_min},
        "separation": separation,
        "proof_confirmed": confirmed, "finding": False,
    }
