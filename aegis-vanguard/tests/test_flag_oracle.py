"""Flag oracle: a flag counts only when it appears in a REAL tool response.

These tests pin the property that makes the benchmark a measurement instead of
a demo: capture is sourced from executed-tool output, blocked calls and agent
prose never count, and grading is a deterministic pass/fail against the
expected flag.
"""

import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

from agent.flag_oracle import (
    FlagOracle,
    grade,
    get_flag_oracle,
    reset_flag_oracle,
    set_flag_oracle,
    _load_captured_flags,
    _main,
)

REAL_FLAG = "FLAG{6e5d772fb6e28ca52985079acf7bfa46d729870e6bae73166208f1fdcd831667}"


def _http_result(body: str) -> str:
    """Shape of a real send_http_request result: status + headers + body."""
    return json.dumps({"status": 200, "headers": {"Server": "Apache"}, "body": body})


class ScanCaptureTest(unittest.TestCase):
    def setUp(self):
        reset_flag_oracle()

    def test_captures_flag_from_real_response_with_provenance(self):
        oracle = FlagOracle(expected_flag=REAL_FLAG)
        oracle.scan(
            "send_http_request",
            {"url": "http://t/redirect.php?url=http://internal-service"},
            _http_result(f"<h1>Internal Service</h1> FLAG: {REAL_FLAG}"),
        )
        caps = oracle.captures
        self.assertEqual(len(caps), 1)
        self.assertEqual(caps[0].flag, REAL_FLAG)
        self.assertEqual(caps[0].tool_name, "send_http_request")
        self.assertIn("redirect.php", caps[0].argument_summary)
        self.assertIn(REAL_FLAG, caps[0].context)

    def test_dedupes_same_flag_from_same_tool(self):
        oracle = FlagOracle()
        for _ in range(3):
            oracle.scan("send_http_request", {"url": "http://t"}, _http_result(REAL_FLAG))
        self.assertEqual(len(oracle.captures), 1)

    def test_distinct_tools_recorded_separately(self):
        oracle = FlagOracle()
        oracle.scan("send_http_request", {"url": "http://t"}, _http_result(REAL_FLAG))
        oracle.scan("run_custom_probe", {"url": "http://t"}, _http_result(REAL_FLAG))
        self.assertEqual(len(oracle.captures), 2)

    def test_empty_or_error_result_captures_nothing(self):
        oracle = FlagOracle()
        oracle.scan("send_http_request", {"url": "http://t"}, "")
        oracle.scan("send_http_request", {"url": "http://t"},
                    json.dumps({"error": "blocked_by_guardrail"}))
        self.assertEqual(oracle.captures, [])

    def test_context_excerpt_is_redacted_but_keeps_flag(self):
        oracle = FlagOracle()
        body = f"Authorization: Bearer tok_live_supersecret1234567890 :: {REAL_FLAG}"
        oracle.scan("send_http_request", {"url": "http://t"}, _http_result(body))
        ctx = oracle.captures[0].context
        self.assertIn(REAL_FLAG, ctx)
        self.assertNotIn("tok_live_supersecret1234567890", ctx)

    def test_disabled_oracle_captures_nothing(self):
        oracle = FlagOracle(enabled=False)
        oracle.scan("send_http_request", {"url": "http://t"}, _http_result(REAL_FLAG))
        self.assertEqual(oracle.captures, [])

    def test_custom_pattern(self):
        oracle = FlagOracle(pattern=r"secret-[0-9a-f]{6}")
        oracle.scan("t", {}, "leaked secret-abc123 here")
        self.assertEqual(oracle.captured_flags(), ["secret-abc123"])


class GradeTest(unittest.TestCase):
    def test_pass_when_expected_flag_captured(self):
        v = grade(REAL_FLAG, [REAL_FLAG])
        self.assertEqual(v.status, "PASS")
        self.assertTrue(v.passed)

    def test_fail_when_expected_flag_absent_but_others_present(self):
        v = grade(REAL_FLAG, ["FLAG{something-else}"])
        self.assertEqual(v.status, "FAIL")
        self.assertFalse(v.passed)
        self.assertIn("FLAG{something-else}", v.captured_flags)

    def test_fail_when_nothing_captured(self):
        v = grade(REAL_FLAG, [])
        self.assertEqual(v.status, "FAIL")
        self.assertIn("unverified prose", v.reason)

    def test_no_expected_flag_is_not_a_pass(self):
        v = grade(None, [REAL_FLAG])
        self.assertEqual(v.status, "NO_EXPECTED_FLAG")
        self.assertFalse(v.passed)

    def test_oracle_verdict_delegates_to_grade(self):
        oracle = FlagOracle(expected_flag=REAL_FLAG)
        oracle.scan("send_http_request", {"url": "http://t"}, _http_result(REAL_FLAG))
        self.assertEqual(oracle.verdict().status, "PASS")


class SingletonTest(unittest.TestCase):
    def setUp(self):
        reset_flag_oracle()

    def tearDown(self):
        reset_flag_oracle()

    def test_set_and_get_share_ledger(self):
        oracle = set_flag_oracle(FlagOracle(expected_flag=REAL_FLAG))
        get_flag_oracle().scan("send_http_request", {"url": "http://t"},
                               _http_result(REAL_FLAG))
        self.assertIs(get_flag_oracle(), oracle)
        self.assertEqual(oracle.verdict().status, "PASS")

    def test_get_autocreates_from_env(self):
        os.environ["AEGIS_EXPECTED_FLAG"] = REAL_FLAG
        try:
            self.assertEqual(get_flag_oracle().expected_flag, REAL_FLAG)
        finally:
            del os.environ["AEGIS_EXPECTED_FLAG"]
            reset_flag_oracle()


class ThreadSafetyTest(unittest.TestCase):
    def test_concurrent_scans_lose_nothing(self):
        oracle = FlagOracle()
        flags = [f"FLAG{{{i:04d}}}" for i in range(200)]

        def worker(f):
            oracle.scan(f"tool_{f}", {"url": "http://t"}, _http_result(f))

        threads = [threading.Thread(target=worker, args=(f,)) for f in flags]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(set(oracle.captured_flags()), set(flags))


class OfflineGraderTest(unittest.TestCase):
    def test_load_captured_flags_from_report_dict(self):
        report = {"captures": [{"flag": REAL_FLAG, "tool_name": "x"}], "verdict": {}}
        self.assertEqual(_load_captured_flags(report), [REAL_FLAG])

    def test_load_captured_flags_from_raw_list(self):
        self.assertEqual(_load_captured_flags([REAL_FLAG]), [REAL_FLAG])

    def test_cli_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            good = Path(tmp) / "good.json"
            good.write_text(json.dumps({"captures": [{"flag": REAL_FLAG}]}))
            self.assertEqual(_main(["--captures", str(good), "--expected", REAL_FLAG]), 0)

            bad = Path(tmp) / "bad.json"
            bad.write_text(json.dumps({"captures": []}))
            self.assertEqual(_main(["--captures", str(bad), "--expected", REAL_FLAG]), 2)


class ExecuteToolWiringTest(unittest.TestCase):
    """The end-to-end guarantee: only executed tools capture; blocked ones don't."""

    def setUp(self):
        reset_flag_oracle()
        self.oracle = set_flag_oracle(FlagOracle(expected_flag=REAL_FLAG))

    def tearDown(self):
        reset_flag_oracle()

    def _runner(self):
        from agent.core import AgentRunner
        from agent.guardrails import GuardrailEngine
        from agent.tools import ToolDef, ToolRegistry

        # max_risk=safe → a 'critical' tool is blocked before it can execute.
        runner = AgentRunner(guardrails=GuardrailEngine(max_risk="safe"))
        reg = ToolRegistry()
        reg.register(ToolDef(
            name="safe_probe", description="", category="recon", risk_level="safe",
            function=lambda url="": _http_result(f"internal body FLAG: {REAL_FLAG}"),
            parameters={"url": {"type": "string"}}, required_params=[],
        ))
        reg.register(ToolDef(
            name="danger_probe", description="", category="exploit", risk_level="critical",
            function=lambda url="": _http_result("FLAG{should-never-be-captured}"),
            parameters={"url": {"type": "string"}}, required_params=[],
        ))
        return runner

    def test_executed_tool_captures_blocked_tool_does_not(self):
        runner = self._runner()
        agent = SimpleNamespace(name="tester")

        out_ok = runner._execute_tool(agent, "safe_probe", {"url": "http://t"}, "u1")
        self.assertIn(REAL_FLAG, out_ok)

        out_blocked = runner._execute_tool(agent, "danger_probe", {"url": "http://t"}, "u2")
        self.assertIn("blocked_by_guardrail", out_blocked)

        flags = self.oracle.captured_flags()
        self.assertIn(REAL_FLAG, flags)
        self.assertNotIn("FLAG{should-never-be-captured}", flags)
        self.assertEqual(self.oracle.verdict().status, "PASS")


if __name__ == "__main__":
    os.chdir(Path(__file__).resolve().parents[1])
    unittest.main()
