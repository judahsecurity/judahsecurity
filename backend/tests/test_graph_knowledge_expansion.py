"""Focused checks for graph identities and commit-stamped source ingestion."""

import sys
import types
import unittest
import re

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
    from app.services.graph_service import GraphService, graph_node_properties
    from app.services.graph_ip_identity import graph_ip_identity
    from app.models.asset import AssetStatus, AssetType


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

    @unittest.skipIf(GraphService is None, "backend dependencies not installed")
    def test_shared_reference_properties_hide_tenant_observations(self):
        class Node(dict):
            labels = {"IP"}

        node = Node(address="203.0.113.10", organization_id=8, is_live=True)
        self.assertEqual(graph_node_properties(node), {"address": "203.0.113.10"})

    @unittest.skipIf(GraphService is None, "backend dependencies not installed")
    def test_overlapping_private_ips_need_the_same_explicit_network_scope(self):
        a = types.SimpleNamespace(id=1, metadata_={})
        b = types.SimpleNamespace(id=2, metadata_={})
        self.assertNotEqual(
            graph_ip_identity("10.0.0.5", 7, a).key,
            graph_ip_identity("10.0.0.5", 8, a).key,
        )
        self.assertNotEqual(
            graph_ip_identity("10.0.0.5", 7, a).key,
            graph_ip_identity("10.0.0.5", 7, b).key,
        )
        a.metadata_["network_scope_id"] = "vpc-123"
        b.metadata_["network_scope_id"] = "vpc-123"
        self.assertEqual(
            graph_ip_identity("10.0.0.5", 7, a).key,
            graph_ip_identity("10.0.0.5", 7, b).key,
        )
        self.assertNotEqual(
            graph_ip_identity("8.8.8.8", 7, a).key,
            graph_ip_identity("8.8.8.8", 8, b).key,
        )
        a.metadata_ = {}
        b.metadata_ = {}
        self.assertEqual(
            graph_ip_identity("8.8.8.8", 7, a).key,
            graph_ip_identity("8.8.8.8", 8, b).key,
        )
        self.assertNotEqual(
            graph_ip_identity("fd00::1", 7, a).key,
            graph_ip_identity("fd00::1", 8, b).key,
        )

    @unittest.skipIf(GraphService is None, "backend dependencies not installed")
    def test_wiz_cloud_context_is_not_a_route(self):
        asset = types.SimpleNamespace(id=42, metadata_={"wiz": {
            "id": "wiz-vm-42", "provider_unique_id": "vm-42",
            "cloud_platform": "AWS", "subscription_external_id": "123456789012",
            "subscription_name": "production", "region": "us-east-1",
            "has_wide_internet_exposure": True,
        }})
        session = FakeSession()
        GraphService()._sync_wiz_cloud_context(session, asset, 7)
        statements = "\n".join(statement for statement, _ in session.calls)
        self.assertIn("IN_CLOUD_SUBSCRIPTION", statements)
        self.assertIn("IN_CLOUD_REGION", statements)
        self.assertNotIn("ROUTES_TO", statements)
        self.assertNotIn("FORWARDS_TO", statements)
        self.assertEqual(session.calls[3][1]["key"], "7|aws|123456789012")

    @unittest.skipIf(GraphService is None, "backend dependencies not installed")
    def test_attack_paths_require_source_backed_reachability(self):
        graph = GraphService()
        graph._connected = True
        graph.query = lambda statement, params: [(statement, params)]
        statement, _ = graph.get_attack_paths(7)[0]
        self.assertIn("forward.vip_asset_id = start.asset_id", statement)
        self.assertIn("forward.member_asset_id = target.asset_id", statement)
        self.assertNotIn("[*1..", statement)

    @unittest.skipIf(GraphService is None, "backend dependencies not installed")
    def test_inactive_f5_asset_retires_forwarding_evidence(self):
        asset = types.SimpleNamespace(
            id=42, status=AssetStatus.INACTIVE,
            metadata_={"f5_integration_id": 9, "f5_pool_members": [
                {"asset_id": 43, "ip": "10.0.0.43"},
            ]}, value="10.0.0.42",
        )
        session = FakeSession()
        GraphService()._sync_f5_forwards_to(session, asset, 7, ["10.0.0.42"])
        self.assertEqual(len(session.calls), 1)
        self.assertIn("DELETE r", session.calls[0][0])

    @unittest.skipIf(GraphService is None, "backend dependencies not installed")
    def test_asset_projection_scopes_shared_observations(self):
        class AssetStub(types.SimpleNamespace):
            def __getattr__(self, _name):
                return None

        asset = AssetStub(
            id=42, name="203.0.113.10", value="203.0.113.10",
            asset_type=AssetType.IP_ADDRESS, status=None, parent_id=None,
            first_seen=None, root_domain=None, ip_addresses=["203.0.113.10"],
            hosting_provider="Example Cloud", hosting_type="cloud", asn="64500",
            technologies=[types.SimpleNamespace(
                name="Example Server", slug="example-server", categories=["server"],
                cpe="cpe:2.3:a:example:server:1", website=None, version="1",
            )],
        )
        session = FakeSession()
        GraphService()._sync_asset(session, asset, 7)
        for statement, params in session.calls:
            missing = set(re.findall(r"\$([a-zA-Z_]\w*)", statement)) - set(params)
            self.assertFalse(missing, (statement, missing))
        ip_write = next(s for s, _ in session.calls if "MERGE (ip:IP {ip_key: $ip_key})" in s and "resolution:RESOLVES_TO" in s)
        self.assertIn("REMOVE ip.organization_id", ip_write)
        self.assertIn("resolution.organization_id = $org_id", ip_write)
        self.assertIn("ip.scope_id = $scope_id", ip_write)
        tech_write = next(s for s, _ in session.calls if "MERGE (t:Technology {name: $name})" in s)
        self.assertIn("observed.version = $version", tech_write)
        self.assertIn("REMOVE t.version, t.cpe", tech_write)

    @unittest.skipIf(GraphService is None, "backend dependencies not installed")
    def test_f5_reachability_uses_asset_evidence_for_overlapping_ip(self):
        asset = types.SimpleNamespace(
            id=10, value="10.0.0.5", asset_type=AssetType.IP_ADDRESS,
            metadata_={"f5_pool_members": [{"ip": "10.0.0.6", "asset_id": 11, "port": 443}]},
        )
        session = FakeSession()
        GraphService()._sync_f5_forwards_to(session, asset, 7, [asset.value])
        statement, params = session.calls[0]
        self.assertIn("vip_asset:Asset {asset_id: $vip_asset_id", statement)
        self.assertIn("member_asset:Asset {asset_id: $member_asset_id", statement)
        self.assertNotIn("MERGE (member:IP", statement)
        self.assertEqual(params["member_asset_id"], 11)

    @unittest.skipIf(GraphService is None, "backend dependencies not installed")
    def test_shared_infrastructure_requires_context_for_ambiguous_private_ip(self):
        graph = GraphService()
        graph._connected = True
        graph.query = lambda _statement, _params: [
            {"asset_id": 10, "scope_id": "org:7:asset:10", "ip_key": "a"},
            {"asset_id": 11, "scope_id": "org:7:asset:11", "ip_key": "b"},
        ]
        result = graph.get_shared_infrastructure("10.0.0.5", 7)
        self.assertTrue(result["ambiguous"])
        self.assertEqual({option["asset_id"] for option in result["scope_options"]}, {10, 11})
        self.assertEqual(result["nodes"], [])


if __name__ == "__main__":
    unittest.main()
