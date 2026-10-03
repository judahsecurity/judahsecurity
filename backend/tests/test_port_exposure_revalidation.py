"""The on-demand validator must use Nmap's actual port state for exposure findings."""

import asyncio
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.finding_revalidation_service import revalidate_finding


def nmap_result(state: str):
    return type("Result", (), {
        "returncode": 0,
        "stderr": "",
        "stdout": (
            '<nmaprun><host><ports><port protocol="tcp" portid="22">'
            f'<state state="{state}" /></port></ports></host></nmaprun>'
        ),
    })()


class PortExposureRevalidationTests(unittest.TestCase):
    def setUp(self):
        self.finding = {
            "title": "[Port 22/tcp] SSH Service Exposed",
            "severity": "medium",
            "detected_by": "port_scanner",
            "source_kind": "network_service",
            "asset": "203.0.113.10",
            "target": "203.0.113.10:22",
            "metadata": {"port": 22, "protocol": "tcp"},
        }

    def test_filtered_port_cannot_confirm_exposure(self):
        with patch("app.services.finding_revalidation_service.subprocess.run", return_value=nmap_result("filtered")):
            verdict = asyncio.run(revalidate_finding(self.finding))
        self.assertEqual(verdict["verdict"], "false_positive")
        self.assertEqual(verdict["port_state"], "filtered")
        self.assertFalse(verdict["still_open"])

    def test_open_port_confirms_exposure(self):
        with patch("app.services.finding_revalidation_service.subprocess.run", return_value=nmap_result("open")):
            verdict = asyncio.run(revalidate_finding(self.finding))
        self.assertEqual(verdict["verdict"], "confirmed")
        self.assertTrue(verdict["still_open"])

    def test_nmap_failure_is_inconclusive(self):
        with patch("app.services.finding_revalidation_service.subprocess.run", side_effect=FileNotFoundError):
            verdict = asyncio.run(revalidate_finding(self.finding))
        self.assertEqual(verdict["verdict"], "needs_more_evidence")
        self.assertIsNone(verdict["still_open"])

    def test_open_port_does_not_prove_agent_service_claim(self):
        finding = {**self.finding, "detected_by": "agent", "title": "Unauthenticated Redis Exposure"}
        with patch("app.services.finding_revalidation_service.subprocess.run", return_value=nmap_result("open")):
            verdict = asyncio.run(revalidate_finding(finding))
        self.assertEqual(verdict["verdict"], "needs_more_evidence")
        self.assertEqual(verdict["port_state"], "open")


if __name__ == "__main__":
    unittest.main()
