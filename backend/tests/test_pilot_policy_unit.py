"""Bounded pilot policy tests that run without the full backend stack."""

import asyncio
import sys
import time
import types
import unittest
from unittest.mock import patch

from app.services.agent.pilot_policy import PilotDenied, PilotPolicy


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
    def test_exact_origin_method_and_tool(self):
        item = policy()
        item.check_request("https://ginandjuice.shop/shop?q=1", "GET")
        item.check_request("https://ginandjuice.shop:443/", "HEAD")
        for url in (
            "https://admin.ginandjuice.shop/",
            "https://ginandjuice.shop:8443/",
            "http://ginandjuice.shop/",
            "https://ginandjuice.shop.evil.test/",
        ):
            with self.subTest(url=url), self.assertRaises(PilotDenied):
                item.check_request(url, "GET")
        with self.assertRaises(PilotDenied):
            item.check_request("https://ginandjuice.shop/", "POST")
        item.check_tool("execute_browser")
        with self.assertRaises(PilotDenied):
            item.check_tool("execute_feroxbuster")

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
        self.assertEqual(seen[0][2], item.budget_key)

        class BrokenClient:
            def eval(self, *args):
                raise ConnectionError("Redis unavailable")

        fake_redis.Redis.from_url = lambda *_args, **_kw: BrokenClient()
        with patch.dict(sys.modules, {"redis": fake_redis}):
            with self.assertRaisesRegex(PilotDenied, "gate unavailable"):
                await item.acquire("https://ginandjuice.shop/", "GET")


if __name__ == "__main__":
    unittest.main()
