"""Integration imports project committed assets without depending on Neo4j."""

import sys
import types
import unittest
from unittest.mock import patch

from app.services.integration_graph_sync import sync_integration_assets_to_graph


class IntegrationGraphSyncTests(unittest.IsolatedAsyncioTestCase):
    async def test_syncs_only_touched_assets_in_stable_order(self):
        calls = []
        graph_module = types.SimpleNamespace(
            sync_organization_background=lambda org, values: calls.append((org, values)) or {"synced": 2}
        )
        with patch.dict(sys.modules, {"app.services.graph_service": graph_module}):
            await sync_integration_assets_to_graph(7, {"b.test", "a.test"})
            await sync_integration_assets_to_graph(7, set())
        self.assertEqual(calls, [(7, ["a.test", "b.test"])])

    async def test_neo4j_failure_does_not_fail_import(self):
        def unavailable(_org, _values):
            raise RuntimeError("Neo4j unavailable")

        graph_module = types.SimpleNamespace(sync_organization_background=unavailable)
        with patch.dict(sys.modules, {"app.services.graph_service": graph_module}):
            await sync_integration_assets_to_graph(7, {"a.test"})
