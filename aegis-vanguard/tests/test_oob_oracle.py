"""OOB interaction oracle: a blind vuln is proven only by a correlated callback.

The local listener catches real HTTP callbacks in-process, so these tests fire
an actual request at the minted payload_url and assert the oracle records it,
registers a verified `oob` proof token, and thereby flips a matching finding to
CONFIRMED through the proof gate.
"""

import json
import os
import unittest
import urllib.request
from pathlib import Path

from agent.oob_oracle import (
    LocalListenerBackend,
    OobOracle,
    RemoteCollaboratorBackend,
    get_oob_oracle,
    reset_oob_oracle,
    set_oob_oracle,
)
from agent.finding_oracle import (
    grade_finding,
    reset_proof_ledger,
    set_proof_ledger,
    ProofLedger,
    CONFIRMED,
    NEEDS_EVIDENCE,
)


def _hit(url: str):
    with urllib.request.urlopen(url, timeout=5) as r:
        r.read()


class LocalListenerTest(unittest.TestCase):
    def setUp(self):
        reset_oob_oracle()
        reset_proof_ledger()
        set_proof_ledger(ProofLedger())
        self.oracle = set_oob_oracle(OobOracle(LocalListenerBackend()))

    def tearDown(self):
        reset_oob_oracle()
        reset_proof_ledger()

    def test_callback_fires_and_registers_proof(self):
        probe = self.oracle.register_probe(label="ssrf /redirect.php")
        self.assertIn("/oob/", probe.payload_url)

        # No callback yet.
        early = self.oracle.check(probe.probe_id)
        self.assertFalse(early["fired"])

        # Simulate the target's server-side fetch reaching our host.
        _hit(probe.payload_url)

        got = self.oracle.check(probe.probe_id)
        self.assertTrue(got["fired"])
        self.assertEqual(got["proof"], "oob verified")
        self.assertEqual(got["events"][0]["protocol"], "http")

        # The finding gate now confirms a finding for that subject.
        v = grade_finding({"title": "Blind SSRF", "endpoint": "ssrf /redirect.php"})
        self.assertEqual(v.status, CONFIRMED)

    def test_no_callback_is_not_proof(self):
        probe = self.oracle.register_probe(label="ssrf /x")
        got = self.oracle.check(probe.probe_id)
        self.assertFalse(got["fired"])
        v = grade_finding({"title": "Blind SSRF", "endpoint": "ssrf /x"})
        self.assertEqual(v.status, NEEDS_EVIDENCE)

    def test_nonce_isolation(self):
        a = self.oracle.register_probe(label="a")
        b = self.oracle.register_probe(label="b")
        _hit(a.payload_url)
        self.assertTrue(self.oracle.check(a.probe_id)["fired"])
        self.assertFalse(self.oracle.check(b.probe_id)["fired"])

    def test_unknown_probe_id(self):
        self.assertIn("error", self.oracle.check("nope"))


class RemoteBackendTest(unittest.TestCase):
    def test_unconfigured_raises_actionable(self):
        b = RemoteCollaboratorBackend(poll_url=None, payload_base=None)
        with self.assertRaises(RuntimeError) as ctx:
            b.new_probe()
        self.assertIn("AEGIS_OOB_PUBLIC_BASE", str(ctx.exception))


class ToolWiringTest(unittest.TestCase):
    def setUp(self):
        reset_oob_oracle()
        reset_proof_ledger()
        set_proof_ledger(ProofLedger())
        set_oob_oracle(OobOracle(LocalListenerBackend()))

    def tearDown(self):
        reset_oob_oracle()
        reset_proof_ledger()

    def test_oob_probe_and_check_tools(self):
        from agent import agents
        probe = json.loads(agents.oob_probe("ssrf /fetch"))
        self.assertIn("payload_url", probe)
        _hit(probe["payload_url"])
        checked = json.loads(agents.oob_check(probe["probe_id"]))
        self.assertTrue(checked["fired"])


if __name__ == "__main__":
    os.chdir(Path(__file__).resolve().parents[1])
    unittest.main()
