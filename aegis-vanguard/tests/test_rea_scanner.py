"""REA integration: artifact discovery, output parsing, finding mapping.

The REA CLI is mocked with output shaped like rea-agents 6.9.0
(`audit-release-exposure` / `inspect-binary-hardening --format json`).
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import rea_scanner  # noqa: E402


def _audit_payload(root: str) -> dict:
    return {
        "evidence_id": "ev_audit",
        "operation": "audit_release_exposure",
        "normalized_result": {
            "target": {"selected_path": root, "kind": "directory"},
            "checks": [
                {
                    "id": "javascript.source_map_sources",
                    "status": "exposed",
                    "severity": "high",
                    "confidence": "observed",
                    "observation": {
                        "counts": {"embedded": 1},
                        "samples": [f"{root}/dist/app.js.map"],
                    },
                    "locations": [{"kind": "artifact-path", "path": f"{root}/dist/app.js.map"}],
                    "remediation": "Ship the release without sourcesContent.",
                    "next_probe": None,
                },
                {
                    "id": "text.credential_markers",
                    "status": "exposed",
                    "severity": "high",
                    "confidence": "observed",
                    "observation": {
                        "counts": {"stripe.live_secret": 1},
                        "samples": [f"stripe.live_secret {root}/dist/config.js:1"],
                    },
                    "locations": [{"kind": "artifact-path", "path": f"{root}/dist/config.js"}],
                    "remediation": "Remove the provider-prefixed credential.",
                    "next_probe": None,
                },
                {"id": "javascript.source_maps", "status": "not_observed", "severity": None,
                 "locations": [], "observation": {}},
                {"id": "electron.run_as_node", "status": "unknown", "severity": None,
                 "locations": [], "observation": {}, "next_probe": "inspect_electron_fuses"},
                {"id": "android.manifest", "status": "not_assessed", "severity": None,
                 "locations": [], "observation": {}, "next_probe": "inspect_android_package"},
            ],
            "summary": {"highest_exposed_severity": "high"},
            "limitations": ["static only"],
        },
    }


def _hardening_payload(path: str, weak: bool) -> dict:
    state = "disabled" if weak else "enabled"
    return {
        "evidence_id": "ev_hard",
        "normalized_result": {
            "format": "elf",
            "images": [{
                "format": "elf", "status": "parsed", "architecture": "x86_64",
                "rows": [
                    {"property": "pie", "state": state, "confidence": "observed", "basis": "e_type"},
                    {"property": "nx", "state": state, "confidence": "observed", "basis": "PT_GNU_STACK"},
                    {"property": "rpath", "state": "enabled" if weak else "disabled",
                     "confidence": "observed", "basis": "DT_RPATH"},
                    {"property": "stripped", "state": "enabled", "confidence": "observed"},
                    {"property": "aarch64_bti_pac", "state": "not_applicable"},
                ],
            }],
        },
    }


class _Checkout:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self.tmp.name)
        for sub in ("dist", "bin", "node_modules/pkg"):
            os.makedirs(os.path.join(self.root, sub))
        elf = b"\x7fELF" + b"\0" * 4096
        for rel in ("bin/weak", "bin/strong", "node_modules/pkg/vendored.so"):
            Path(self.root, rel).write_bytes(elf)
        Path(self.root, "bin/tiny").write_bytes(b"\x7fELF")  # under min_bytes
        Path(self.root, "dist/app.asar").write_bytes(b"\0" * 2048)
        Path(self.root, "dist/readme.txt").write_bytes(b"MZ" + b"x" * 2048)  # MZ, not PE

    def fake_run(self, cmd, capture_output, text, timeout):
        sub, target = cmd[1], cmd[2]
        if sub == "audit-release-exposure":
            out = _audit_payload(self.root) if target == self.root else {
                "normalized_result": {"checks": []}}
        elif sub == "inspect-binary-hardening":
            out = _hardening_payload(target, weak=target.endswith("weak"))
        else:
            raise AssertionError(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(out), stderr="")


class DiscoveryTest(unittest.TestCase):
    def test_finds_binaries_and_packages_skips_noise(self):
        co = _Checkout()
        self.addCleanup(co.tmp.cleanup)
        found = {a["relpath"]: a["kind"] for a in rea_scanner.discover_artifacts(co.root)}
        self.assertEqual(found, {"bin/weak": "elf", "bin/strong": "elf", "dist/app.asar": "asar"})


class HardeningMappingTest(unittest.TestCase):
    def test_disabled_mitigations_are_weaknesses(self):
        self.assertEqual(
            rea_scanner.hardening_weakness({"property": "nx", "state": "disabled"})["severity"],
            "medium",
        )
        self.assertIsNone(rea_scanner.hardening_weakness({"property": "nx", "state": "enabled"}))
        self.assertIsNone(rea_scanner.hardening_weakness({"property": "pie", "state": "unknown"}))
        self.assertIsNone(rea_scanner.hardening_weakness({"property": "stripped", "state": "enabled"}))

    def test_unwanted_properties(self):
        self.assertEqual(
            rea_scanner.hardening_weakness({"property": "rpath", "state": "enabled"})["severity"], "low")
        self.assertIsNone(rea_scanner.hardening_weakness({"property": "rpath", "state": "disabled"}))


class ScanTest(unittest.TestCase):
    def setUp(self):
        self.co = _Checkout()
        self.addCleanup(self.co.tmp.cleanup)
        patcher = mock.patch.object(rea_scanner, "rea_command", return_value=["/usr/bin/rea"])
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_scan_maps_exposed_checks_and_weak_binaries(self):
        with mock.patch.object(rea_scanner.subprocess, "run", side_effect=self.co.fake_run) as run:
            res = rea_scanner.scan(self.co.root)
        commands = [(c.args[0][1], os.path.relpath(c.args[0][2], self.co.root)) for c in run.call_args_list]
        self.assertIn(("audit-release-exposure", "."), commands)
        self.assertIn(("audit-release-exposure", "dist/app.asar"), commands)
        self.assertIn(("inspect-binary-hardening", "bin/weak"), commands)
        self.assertNotIn(("inspect-binary-hardening", "node_modules/pkg/vendored.so"), commands)
        for c in run.call_args_list:
            self.assertEqual(c.args[0][-2:], ["--format", "json"])

        rules = {f["rule"]: f for f in res["findings"]}
        self.assertEqual(set(rules), {
            "rea.javascript.source_map_sources",
            "rea.text.credential_markers",
            "rea.native.hardening",
        })
        self.assertEqual(rules["rea.javascript.source_map_sources"]["file"], "dist/app.js.map")
        self.assertEqual(
            rules["rea.text.credential_markers"]["evidence"]["samples"],
            ["stripe.live_secret dist/config.js:1"],
        )
        hard = rules["rea.native.hardening"]
        self.assertEqual(hard["file"], "bin/weak")
        self.assertEqual(hard["severity"], "medium")
        self.assertEqual({w["property"] for w in hard["evidence"]["weaknesses"]}, {"pie", "nx", "rpath"})
        # Unknown / not_assessed checks are coverage gaps, never findings.
        self.assertEqual(res["coverage_gaps"], ["electron.run_as_node", "android.manifest"])
        self.assertEqual(res["findings"][0]["severity"], "high")

    def test_cli_error_is_reported_not_raised(self):
        def boom(cmd, **_):
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="bad target")
        with mock.patch.object(rea_scanner.subprocess, "run", side_effect=boom):
            res = rea_scanner.scan(self.co.root)
        self.assertEqual(res["findings"], [])
        self.assertTrue(any("rea exited 1" in e for e in res["errors"]))

    def test_exit_3_fail_on_still_parses(self):
        payload = json.dumps(_audit_payload(self.co.root))
        with mock.patch.object(rea_scanner.subprocess, "run",
                               return_value=subprocess.CompletedProcess([], 3, stdout=payload, stderr="")):
            res = rea_scanner.audit_release_exposure(self.co.root)
        self.assertEqual(len(res["exposed"]), 2)


class NotInstalledTest(unittest.TestCase):
    def test_missing_cli_is_soft(self):
        co = _Checkout()
        self.addCleanup(co.tmp.cleanup)
        with mock.patch.object(rea_scanner, "rea_command", return_value=None):
            res = rea_scanner.scan(co.root)
        self.assertEqual(res["error"], "rea not installed")
        self.assertEqual(res["findings"], [])
        self.assertIn("rea-agents@", res["install_hint"])

    def test_rea_bin_override(self):
        with mock.patch.dict(os.environ, {"REA_BIN": "/opt/rea/bin/rea"}):
            self.assertEqual(rea_scanner.rea_command(), ["/opt/rea/bin/rea"])


class BridgeSubmissionTest(unittest.TestCase):
    def test_run_rea_submits_vulnerabilities(self):
        import scanners
        fake = {
            "source_dir": "/src",
            "findings": [{"title": "Release exposure: x", "severity": "high",
                          "rule": "rea.x", "file": "dist/a.map", "remediation": "fix"}],
            "count": 1,
            "audits": [{"big": True}],
            "hardening": [],
        }
        bridge = mock.Mock()
        with mock.patch.object(rea_scanner, "scan", return_value=fake):
            res = scanners.run_rea("/src", bridge=bridge)
        bridge.submit_vulnerability.assert_called_once()
        kwargs = bridge.submit_vulnerability.call_args.kwargs
        self.assertEqual(kwargs["source"], "rea")
        self.assertEqual(kwargs["severity"], "high")
        self.assertIn("rea", kwargs["tags"])
        bridge.flush.assert_called_once()
        self.assertNotIn("audits", res)


if __name__ == "__main__":
    unittest.main()
