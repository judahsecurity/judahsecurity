"""Unit tests for the ReAct loop breaker (agent/core.py).

The full run loop needs a live model backend, so these cover the pure decision
helpers that govern it: the per-call signature and the warn/block thresholds.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent.core import _call_signature, _loop_action


def test_signature_is_stable_regardless_of_key_order():
    a = _call_signature("xss_test", {"target_url": "http://x/", "timeout": 30})
    b = _call_signature("xss_test", {"timeout": 30, "target_url": "http://x/"})
    assert a == b


def test_signature_distinguishes_tool_and_args():
    base = _call_signature("xss_test", {"target_url": "http://x/"})
    assert base != _call_signature("xss_test", {"target_url": "http://y/"})
    assert base != _call_signature("test_dom_xss", {"target_url": "http://x/"})


def test_signature_survives_unserializable_input():
    # Must not raise on an object json can't encode.
    sig = _call_signature("t", {"obj": object()})
    assert sig.startswith("t|")


def test_loop_action_thresholds():
    # Defaults: warn at 3, block at 6.
    assert _loop_action(1) == "ok"
    assert _loop_action(2) == "ok"
    assert _loop_action(3) == "warn"
    assert _loop_action(5) == "warn"
    assert _loop_action(6) == "block"
    assert _loop_action(9) == "block"


def test_loop_action_custom_thresholds():
    assert _loop_action(2, warn=2, block=4) == "warn"
    assert _loop_action(4, warn=2, block=4) == "block"
    # Thresholds of 0 disable that tier.
    assert _loop_action(100, warn=0, block=0) == "ok"
