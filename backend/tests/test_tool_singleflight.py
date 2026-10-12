"""Concurrent recon calls share work without caching later verification."""

import asyncio
import unittest

from app.services.agent.tool_singleflight import ToolSingleFlight


class ToolSingleFlightTests(unittest.TestCase):
    def test_concurrent_calls_share_one_result_then_allow_fresh_call(self):
        async def check():
            flight = ToolSingleFlight()
            entered = asyncio.Event()
            release = asyncio.Event()
            calls = 0

            async def operation():
                nonlocal calls
                calls += 1
                entered.set()
                await release.wait()
                return {"success": True, "artifact_id": "proof-1"}

            owner = asyncio.create_task(flight.run("run:exact-call", operation))
            await entered.wait()
            follower = asyncio.create_task(flight.run("run:exact-call", operation))
            await asyncio.sleep(0)
            release.set()
            first, second = await asyncio.gather(owner, follower)
            self.assertEqual(calls, 1)
            self.assertEqual(first, ({"success": True, "artifact_id": "proof-1"}, False))
            self.assertEqual(second, ({"success": True, "artifact_id": "proof-1"}, True))

            third = await flight.run("run:exact-call", operation)
            self.assertEqual(calls, 2)
            self.assertFalse(third[1])

        asyncio.run(check())

    def test_distinct_keys_and_failures_do_not_poison_next_call(self):
        async def check():
            flight = ToolSingleFlight()
            calls = 0

            async def operation():
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise RuntimeError("scanner failed")
                return {"success": True}

            with self.assertRaisesRegex(RuntimeError, "scanner failed"):
                await flight.run("run:payload-a", operation)
            result, reused = await flight.run("run:payload-a", operation)
            self.assertEqual(result, {"success": True})
            self.assertFalse(reused)
            await flight.run("run:payload-b", operation)
            self.assertEqual(calls, 3)

        asyncio.run(check())

    def test_cancelled_follower_does_not_stop_owner(self):
        async def check():
            flight = ToolSingleFlight()
            entered = asyncio.Event()
            release = asyncio.Event()

            async def operation():
                entered.set()
                await release.wait()
                return {"success": True}

            owner = asyncio.create_task(flight.run("run:scan", operation))
            await entered.wait()
            follower = asyncio.create_task(flight.run("run:scan", operation))
            await asyncio.sleep(0)
            follower.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await follower
            release.set()
            self.assertEqual(await owner, ({"success": True}, False))

        asyncio.run(check())

    def test_cancelled_owner_releases_key_for_retry(self):
        async def check():
            flight = ToolSingleFlight()
            entered = asyncio.Event()

            async def interrupted():
                entered.set()
                await asyncio.Future()

            owner = asyncio.create_task(flight.run("run:scan", interrupted))
            await entered.wait()
            owner.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await owner

            result, reused = await flight.run(
                "run:scan", lambda: asyncio.sleep(0, result={"success": True}),
            )
            self.assertEqual(result, {"success": True})
            self.assertFalse(reused)

        asyncio.run(check())
