"""Exact-call metrics must distinguish real mutations and fresh verifier work."""

from app.services.agent.action_fingerprint import action_fingerprint


def _fingerprint(args, *, run="run-1", verifier=""):
    return action_fingerprint(
        run_id=run, tool_name="execute_browser", target="https://example.test",
        tool_args=args, secret_key="test-key-kept-out-of-receipts",
        verifier_run_id=verifier,
    )


def test_equivalent_json_calls_share_an_opaque_fingerprint():
    first = _fingerprint({"args": '{"actions":[{"action":"get_source","url":"https://example.test/a?q=secret"}]}',
                          "_execution_trace": [{"iteration": 1}]})
    second = _fingerprint({"args": '{ "actions": [ { "url": "https://example.test/a?q=secret", "action": "get_source" } ] }',
                           "_execution_trace": [{"iteration": 2}]})
    assert first == second
    assert len(first) == 64
    assert "secret" not in first


def test_payload_identity_and_verifier_run_change_the_fingerprint():
    baseline = {"args": '{"url":"https://example.test/catalog?category=gin"}'}
    mutant = {"args": '{"url":"https://example.test/catalog?category=gin%27"}'}
    assert _fingerprint(baseline) != _fingerprint(mutant)
    assert _fingerprint(baseline) != _fingerprint(baseline, verifier="verify-1")
    assert _fingerprint(baseline, verifier="verify-1") != _fingerprint(baseline, verifier="verify-2")
    assert _fingerprint(baseline) != _fingerprint(baseline, run="run-2")
