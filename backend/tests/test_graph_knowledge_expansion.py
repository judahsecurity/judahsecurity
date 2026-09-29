"""Focused checks for graph identities and commit-stamped source ingestion."""

import sys
import types
import unittest

try:
    import neo4j  # noqa: F401
except ModuleNotFoundError:
    # The importer only uses the driver in its CLI; these unit tests use a fake.
    sys.modules["neo4j"] = types.SimpleNamespace(GraphDatabase=None)

from app.services.graph_identity import canonical_script_url, script_key, source_file_key
from app.services.graph_source_ingest import ingest_manifest

try:
    import sqlalchemy  # noqa: F401
except ModuleNotFoundError:
    GraphService = None
else:
    from app.services.graph_service import GraphService
    from app.models.asset import AssetType


class FakeResult:
    def consume(self):
        return None


class FakeSession:
    def __init__(self):
        self.calls = []
        self.records = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def run(self, statement, *args, **params):
        self.calls.append((statement, args[0] if args else params))
        return self.records if self.records is not None else FakeResult()


class FakeDriver:
    def __init__(self):
        self.connection = FakeSession()

    def session(self):
        return self.connection


class GraphKnowledgeTests(unittest.TestCase):
    def test_script_identity_drops_token_bearing_query(self):
        url = canonical_script_url("HTTPS://Example.COM:443/app.js?token=secret#part")
        self.assertEqual(url, "https://example.com/app.js")
        self.assertEqual(script_key(7, url), script_key(7, url))
        self.assertNotEqual(script_key(7, url), script_key(8, url))
        self.assertIsNone(canonical_script_url("file:///etc/passwd"))

    def test_source_manifest_and_verified_mapping(self):
        manifest = {
            "schema_version": 1,
            "organization_id": 7,
            "repository": "judahsecurity/judahsecurity",
            "commit": "a" * 40,
            "files": [
                {"path": "frontend/src/a.ts", "sha256": "1" * 64, "language": "ts",
                 "symbols": [{"name": "Page", "kind": "function", "line": 3}],
                 "routes": [{"path": "/a", "method": "GET"}],
                 "imports": [{"specifier": "./b", "resolved_path": "frontend/src/b.ts"},
                             {"specifier": "react", "package_name": "react", "version": "18.2.0"}]},
                {"path": "frontend/src/b.ts", "sha256": "2" * 64, "language": "ts",
                 "symbols": [], "imports": []},
            ],
        }
        mapping = [{"script_url": "https://app.example/a.js?token=secret",
                    "source_path": "frontend/src/a.ts", "evidence": "source-map"}]
        driver = FakeDriver()
        result = ingest_manifest(driver, manifest, mapping)
        self.assertEqual(result, {"files": 2, "symbols": 1, "routes": 1, "local_imports": 1,
                                  "package_imports": 1, "bundle_mappings": 1})
        calls = driver.connection.calls
        self.assertTrue(any("IMPORTS_FILE" in statement for statement, _ in calls))
        link = next(params for statement, params in calls if "MAPS_TO_SOURCE" in statement)
        self.assertEqual(link["rows"][0]["script_id"],
                         script_key(7, "https://app.example/a.js"))
        self.assertEqual(link["rows"][0]["file_id"],
                         source_file_key(7, manifest["repository"], manifest["commit"],
                                         "frontend/src/a.ts"))

        with self.assertRaises(ValueError):
            ingest_manifest(FakeDriver(), manifest, [{**mapping[0], "evidence": "filename"}])

    @unittest.skipIf(GraphService is None, "backend dependencies not installed")
    def test_agent_lookup_is_scoped_and_parameterized(self):
        graph = GraphService()
        calls = []
        graph.query = lambda statement, params: calls.append((statement, params)) or []
        graph.lookup_for_agent(7, "endpoint", "/admin", 100)
        statement, params = calls[0]
        self.assertIn("organization_id: $org_id", statement)
        self.assertNotIn("/admin", statement)
        self.assertEqual(params["org_id"], 7)
        self.assertEqual(params["limit"], 50)
        with self.assertRaises(ValueError):
            graph.lookup_for_agent(7, "arbitrary_cypher", "MATCH (n) RETURN n")

    @unittest.skipIf(GraphService is None, "backend dependencies not installed")
    def test_asset_relationship_query_scopes_every_hop(self):
        graph = GraphService()
        graph._connected = True
        session = FakeSession()
        session.records = []
        from contextlib import contextmanager

        @contextmanager
        def fake_session():
            yield session

        graph.session = fake_session
        self.assertEqual(graph.get_asset_relationships(42, depth=3, organization_id=7),
                         {"nodes": [], "edges": []})
        statement, params = session.calls[0]
        self.assertIn("center.organization_id = $org_id", statement)
        self.assertIn("all(n IN nodes(path)", statement)
        self.assertIn("n.organization_id = center.organization_id", statement)
        self.assertEqual(params, {"asset_id": 42, "org_id": 7})

    @unittest.skipIf(GraphService is None, "backend dependencies not installed")
    def test_inventory_asset_does_not_claim_canonical_domain_identity(self):
        class FirstWrite(Exception):
            pass

        class CaptureSession:
            statement = ""

            def run(self, statement, _params):
                self.statement = statement
                raise FirstWrite

        asset = types.SimpleNamespace(
            id=42, name="example.test", value="example.test",
            asset_type=AssetType.DOMAIN, first_seen=None, root_domain=None,
        )
        session = CaptureSession()
        with self.assertRaises(FirstWrite):
            GraphService()._sync_asset(session, asset, 7)
        self.assertIn("REMOVE a:Domain:Subdomain:IP:URL:Certificate", session.statement)
        self.assertNotIn("SET a:Domain", session.statement)


if __name__ == "__main__":
    unittest.main()
