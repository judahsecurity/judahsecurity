"""Preflight verdict logic: a required failure blocks readiness; warnings don't."""

import os
import unittest
from pathlib import Path

import importlib.util

_spec = importlib.util.spec_from_file_location(
    "aegis_doctor", Path(__file__).resolve().parents[1] / "doctor.py")
doctor = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(doctor)


class SummarizeTest(unittest.TestCase):
    def test_required_fail_blocks(self):
        rows = [("llm", "required", "fail", "no key"),
                ("caido", "optional", "warn", "meh")]
        s = doctor.summarize(rows)
        self.assertFalse(s["ready"])
        self.assertEqual(len(s["blockers"]), 1)

    def test_warnings_do_not_block(self):
        rows = [("browser", "required", "ok", "chromium ok"),
                ("guardrails", "recommended", "warn", "posture note"),
                ("secrets_db", "recommended", "warn", "missing")]
        s = doctor.summarize(rows)
        self.assertTrue(s["ready"])
        self.assertEqual(len(s["warnings"]), 2)

    def test_recommended_fail_does_not_block(self):
        # only REQUIRED fails block
        rows = [("pkg:httpx", "recommended", "fail", "missing")]
        self.assertTrue(doctor.summarize(rows)["ready"])

    def test_capability_modules_check_passes_here(self):
        # our own modules must import in the repo
        rows = doctor.check_capability_modules()
        self.assertEqual(rows[0][2], "ok")


if __name__ == "__main__":
    os.chdir(Path(__file__).resolve().parents[1])
    unittest.main()
