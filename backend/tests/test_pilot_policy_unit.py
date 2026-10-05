"""Bounded pilot policy tests that run without the full backend stack."""

import asyncio
import sys
import time
import types
import unittest
from unittest.mock import AsyncMock, patch

from app.services.agent.pilot_policy import PilotDenied, PilotPolicy
from app.services.agent.pilot_port_probe import parse_ports, probe_ports, resolve_public_address


def policy(session_id="first", organization_id=1):
    with patch.dict("os.environ", {"AEGIS_AGENT_EGRESS_IP": "8.8.8.8"}):
        return PilotPolicy.from_config(
            {
                "target": "https://ginandjuice.shop:443",
                "source_ip": "8.8.8.8",
                "expires_at_ms": int(time.time() * 1000) + 60_000,
            },
            organization_id,
            session_id,
        )


class PilotPolicyTests(unittest.TestCase):
    def test_exact_host_across_ports_and_method_and_tool(self):
        item = policy()
        item.check_request("https://ginandjuice.shop/shop?q=1", "GET")
        item.check_request("https://ginandjuice.shop:443/", "HEAD")
        item.check_request("https://ginandjuice.shop:8443/", "GET")
        item.check_request("http://ginandjuice.shop:8080/", "OPTIONS")
        for url in (
            "https://admin.ginandjuice.shop/",
            "https://ginandjuice.shop.evil.test/",
            "http://127.0.0.1/",
        ):
            with self.subTest(url=url), self.assertRaises(PilotDenied):
                item.check_request(url, "GET")
        with self.assertRaises(PilotDenied):
            item.check_request("https://ginandjuice.shop/", "POST")
        item.check_tool("execute_browser")
        item.check_tool("probe_pilot_ports")
        item.check_port_probe(53, "udp")
        item.check_port_probe(22, "tcp")
        with self.assertRaises(PilotDenied):
            item.check_port_probe(0, "tcp")
        with self.assertRaises(PilotDenied):
            item.check_port_probe(53, "sctp")
        with self.assertRaises(PilotDenied):
            item.check_tool("execute_feroxbuster")

    def test_seed_accepts_fqdn_or_public_https_ip(self):
        with patch.dict("os.environ", {"AEGIS_AGENT_EGRESS_IP": "8.8.8.8"}):
            config = {"source_ip": "8.8.8.8",
                      "expires_at_ms": int(time.time() * 1000) + 60_000}
            for target, expected in (
                ("ginandjuice.shop", "https://ginandjuice.shop:443"),
                ("https://8.8.4.4", "https://8.8.4.4:443"),
            ):
                self.assertEqual(PilotPolicy.from_config(
                    {**config, "target": target}, 1, "x").target, expected)
            for target in ("https://127.0.0.1", "http://ginandjuice.shop",
                           "https://ginandjuice.shop/path", "*.ginandjuice.shop"):
                with self.subTest(target=target), self.assertRaises(PilotDenied):
                    PilotPolicy.from_config({**config, "target": target}, 1, "x")

    def test_probe_port_batch_validation(self):
        self.assertEqual(parse_ports("22,80,443"), [22, 80, 443])
        for ports in ([22, 22], list(range(1, 22)), "1-100", [0], []):
            with self.subTest(ports=ports), self.assertRaises(PilotDenied):
                parse_ports(ports)

    def test_preflight_and_shared_key(self):
        self.assertEqual(policy("first", 1).budget_key, policy("second", 2).budget_key)
        with self.assertRaises(PilotDenied):
            PilotPolicy.from_config({"target": "https://ginandjuice.shop",
                                     "source_ip": "unknown",
                                     "expires_at_ms": int(time.time() * 1000) + 60_000}, 1, "x")
        with patch.dict("os.environ", {"AEGIS_AGENT_EGRESS_IP": "8.8.8.8"}):
            with self.assertRaisesRegex(PilotDenied, "window"):
                PilotPolicy.from_config({"target": "https://ginandjuice.shop",
                                         "source_ip": "8.8.8.8",
                                         "expires_at_ms": int(time.time() * 1000) - 1}, 1, "x")
        with patch.dict("os.environ", {"AEGIS_AGENT_EGRESS_IP": "1.1.1.1"}):
            with self.assertRaisesRegex(PilotDenied, "configured public"):
                PilotPolicy.from_config({"target": "https://ginandjuice.shop",
                                         "source_ip": "8.8.8.8",
                                         "expires_at_ms": int(time.time() * 1000) + 60_000}, 1, "x")


class PilotBudgetTests(unittest.IsolatedAsyncioTestCase):
    async def test_port_probe_rejects_private_ip_before_traffic(self):
        with self.assertRaisesRegex(PilotDenied, "non-public"):
            await resolve_public_address("127.0.0.1", "tcp")

    async def test_port_probes_use_one_shared_reservation_each(self):
        item = policy()
        with patch("app.services.agent.pilot_port_probe.resolve_public_address",
                   new=AsyncMock(return_value="8.8.8.8")), \
             patch("app.services.agent.pilot_port_probe._tcp_probe",
                   new=AsyncMock(side_effect=[{"state": "open"}, {"state": "closed"}])), \
             patch.object(PilotPolicy, "acquire_port_probe",
                          new=AsyncMock(side_effect=[1, 2])) as reserve:
            result = await probe_ports(item, "tcp", [80, 443])
        self.assertEqual([entry["state"] for entry in result["observations"]],
                         ["open", "closed"])
        self.assertEqual(reserve.await_count, 2)
        self.assertEqual(reserve.await_args_list[0].args, (80, "tcp"))

    async def test_reservation_and_redis_failure(self):
        item = policy()
        seen = []

        class FakeClient:
            def eval(self, *args):
                seen.append(args)
                return [1, 0, 1]

        fake_redis = types.SimpleNamespace(
            Redis=types.SimpleNamespace(from_url=lambda *_args, **_kw: FakeClient())
        )
        with patch.dict(sys.modules, {"redis": fake_redis}):
            self.assertEqual(await item.acquire("https://ginandjuice.shop/", "GET"), 1)
            self.assertEqual(await item.acquire_port_probe(53, "udp"), 1)
        self.assertEqual(seen[0][2], item.budget_key)
        self.assertEqual(seen[0][3], "ginandjuice.shop")

        class BrokenClient:
            def eval(self, *args):
                raise ConnectionError("Redis unavailable")

        fake_redis.Redis.from_url = lambda *_args, **_kw: BrokenClient()
        with patch.dict(sys.modules, {"redis": fake_redis}):
            with self.assertRaisesRegex(PilotDenied, "gate unavailable"):
                await item.acquire("https://ginandjuice.shop/", "GET")


if __name__ == "__main__":
    unittest.main()
