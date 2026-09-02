"""Interaction-first crawl: the pure decision logic (safe to click? in scope?
capture glue?) is what's testable without a live browser — so it's tested."""

import os
import unittest
from pathlib import Path

from agent.browser_crawl import (
    crawl_host,
    in_scope,
    is_destructive,
    make_transaction,
    pick_interactions,
    should_capture,
)


class DestructiveTest(unittest.TestCase):
    def test_flags_dangerous_labels(self):
        for bad in ["Delete", "Sign out", "Log Out", "Pay now", "Deactivate account",
                    "Confirm order", "Cancel subscription"]:
            self.assertTrue(is_destructive(bad), bad)

    def test_allows_safe_labels(self):
        for ok in ["Search", "Open menu", "Next", "View details", "Filter", "Load more"]:
            self.assertFalse(is_destructive(ok), ok)


class ScopeTest(unittest.TestCase):
    def test_host_and_scope(self):
        self.assertEqual(crawl_host("https://app.example.com/x?y=1"), "app.example.com")
        self.assertTrue(in_scope("https://app.example.com/a", "app.example.com"))
        self.assertFalse(in_scope("https://evil.com/a", "app.example.com"))
        self.assertFalse(in_scope("https://api.example.com/a", "example.com"))
        self.assertTrue(in_scope("https://api.example.com/a", "example.com",
                                 include_subdomains=True))


class CaptureFilterTest(unittest.TestCase):
    def test_skips_static_assets(self):
        self.assertFalse(should_capture("image/png"))
        self.assertFalse(should_capture("text/css"))
        self.assertFalse(should_capture("font/woff2"))

    def test_captures_documents_and_api(self):
        self.assertTrue(should_capture("text/html"))
        self.assertTrue(should_capture("application/json"))
        self.assertTrue(should_capture("application/javascript"))


class PickTest(unittest.TestCase):
    def test_dedup_skip_destructive_cap(self):
        els = [
            {"role": "button", "name": "Search"},
            {"role": "button", "name": "Search"},      # dup
            {"role": "link", "name": "Delete"},          # destructive
            {"role": "menuitem", "name": "Settings"},
            {"role": "img", "name": "logo"},             # not clickable role
        ]
        picks = pick_interactions(els, max_clicks=10)
        names = [(p["role"], p["name"]) for p in picks]
        self.assertIn(("button", "Search"), names)
        self.assertIn(("menuitem", "Settings"), names)
        self.assertNotIn(("link", "Delete"), names)
        self.assertEqual(len(picks), 2)

    def test_cap(self):
        els = [{"role": "button", "name": f"b{i}"} for i in range(50)]
        self.assertEqual(len(pick_interactions(els, max_clicks=5)), 5)


class TransactionTest(unittest.TestCase):
    def test_make_transaction(self):
        req, resp = make_transaction(
            "POST", "https://app/x", {"Cookie": "s=1"}, '{"a":1}',
            201, {"Content-Type": "application/json"}, '{"ok":true}')
        self.assertEqual((req.method, req.url, req.body), ("POST", "https://app/x", '{"a":1}'))
        self.assertEqual(resp.status, 201)
        self.assertEqual(resp.headers["Content-Type"], "application/json")


class ToolTest(unittest.TestCase):
    def test_tool_registered(self):
        from agent.tools import ToolRegistry
        import agent.agents  # noqa: registers tools
        self.assertIsNotNone(ToolRegistry().get("browser_crawl"))


if __name__ == "__main__":
    os.chdir(Path(__file__).resolve().parents[1])
    unittest.main()
