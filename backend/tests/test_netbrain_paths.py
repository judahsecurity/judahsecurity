"""NetBrain route evidence must keep ambiguous addresses and gateways explicit."""

from types import SimpleNamespace
from contextlib import contextmanager

import httpx
import pytest

from app.services.netbrain_path_service import (
    PathSelectionError, _asset_ip, _clean_hops, _gateway,
)
from app.services.netbrain_service import NetBrainClient
from app.services import netbrain_path_service, netbrain_path_graph


class AssetQuery:
    def __init__(self, asset):
        self.asset = asset

    def filter(self, *args):
        return self

    def first(self):
        return self.asset


class AssetDB:
    def __init__(self, asset):
        self.asset = asset

    def query(self, model):
        return AssetQuery(self.asset)


def test_overlapping_private_addresses_need_exact_asset_and_address():
    asset = SimpleNamespace(id=15, value="10.1.1.5", name="router",
                            ip_address="10.1.1.5", ip_addresses=["10.1.1.6"], metadata_={})
    with pytest.raises(PathSelectionError) as error:
        _asset_ip(AssetDB(asset), 3, 15, None)
    assert error.value.status_code == 409
    assert error.value.options == [{"ip": "10.1.1.5"}, {"ip": "10.1.1.6"}]
    assert _asset_ip(AssetDB(asset), 3, 15, "10.1.1.6")[1] == "10.1.1.6"
    with pytest.raises(PathSelectionError):
        _asset_ip(AssetDB(asset), 3, 15, "10.1.1.7")


def test_gateway_must_match_netbrain_choice_exactly():
    choices = [
        {"ip": "10.0.0.1", "devName": "vrf-a", "intfName": "eth0"},
        {"ip": "10.0.0.1", "devName": "vrf-b", "intfName": "eth0"},
    ]
    with pytest.raises(PathSelectionError) as error:
        _gateway(choices, {})
    assert len(error.value.options) == 2
    assert _gateway(choices, {"gateway_ip": "10.0.0.1", "gateway_device": "vrf-b",
                              "gateway_interface": "eth0"}) == ("10.0.0.1", "vrf-b", "eth0")
    with pytest.raises(PathSelectionError):
        _gateway(choices, {"gateway_ip": "10.0.0.1", "gateway_device": "vrf-c",
                           "gateway_interface": "eth0"})


def test_hop_identifiers_and_branching_are_kept():
    assert _clean_hops([
        {"hopId": "a", "srcDeviceName": "r1", "dstDeviceName": "r2", "nextHopIdList": ["b"]},
        {"hopId": "a", "srcDeviceName": "duplicate"},
        {"hopId": "b", "srcDeviceName": "r2", "dstDeviceName": "r3"},
    ]) == [
        {"hop_id": "a", "source_device": "r1", "target_device": "r2", "inbound_interface": "",
         "outbound_interface": "", "next_hop_ids": ["b"]},
        {"hop_id": "b", "source_device": "r2", "target_device": "r3", "inbound_interface": "",
         "outbound_interface": "", "next_hop_ids": []},
    ]


@pytest.mark.asyncio
async def test_documented_netbrain_path_exchange():
    seen = []

    def handler(request: httpx.Request):
        seen.append((request.method, request.url.path, request.url.params, request.content))
        if request.url.path.endswith("/Gateways"):
            return httpx.Response(200, json={"statusCode": 790200, "gatewayList": [
                {"ip": "10.0.0.1", "devName": "r1", "intfName": "eth0"}]})
        if request.url.path.endswith("/Calculation"):
            return httpx.Response(200, json={"statusCode": 790200, "taskId": "task-1"})
        if request.url.path.endswith("/Status"):
            return httpx.Response(200, json={"statusCode": 790200, "result": {"resultCode": 2}})
        if request.url.path.endswith("/Result"):
            return httpx.Response(200, json={"statusCode": 790200, "hopList": [{"hopId": "a"}]})
        raise AssertionError(request.url)

    client = NetBrainClient("https://netbrain.example", "", "", tenant_id="t", domain_id="d")
    client.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client.token = "test-token"
    try:
        assert len(await client.get_path_gateways("10.1.1.5")) == 1
        assert await client.start_path_calculation({"sourceIP": "10.1.1.5"}) == "task-1"
        assert await client.get_path_status("task-1") == 2
        assert await client.get_path_hops("task-1") == [{"hopId": "a"}]
        assert seen[0][2]["ipOrHost"] == "10.1.1.5"
        assert seen[1][0] == "POST"
        assert all(item[1].startswith("/ServicesAPI/API/V1/CMDB/Path/") for item in seen)
    finally:
        await client.client.aclose()


@pytest.mark.asyncio
async def test_calculation_persists_exact_assets_and_source_context(monkeypatch):
    source = SimpleNamespace(id=11, value="10.1.1.5", name="source", ip_address="10.1.1.5",
                             ip_addresses=[], metadata_={"network_scope_id": "vrf-a"})
    target = SimpleNamespace(id=12, value="10.1.1.6", name="target", ip_address="10.1.1.6",
                             ip_addresses=[], metadata_={"network_scope_id": "vrf-b"})

    class DB:
        def __init__(self):
            self.assets = iter([source, target])
            self.path = None

        def query(self, model):
            return AssetQuery(next(self.assets))

        def add(self, path):
            self.path = path

        def commit(self):
            self.path.id = 20

        def refresh(self, path):
            pass

    class Client:
        async def get_path_gateways(self, source_ip):
            assert source_ip == "10.1.1.5"
            return [{"ip": "10.1.1.1", "devName": "gw-a", "intfName": "eth1"}]

        async def start_path_calculation(self, body):
            assert body["sourceIP"] == "10.1.1.5" and body["destIP"] == "10.1.1.6"
            assert body["sourceGwDev"] == "gw-a"
            assert body["pathAnalysisSet"] == 1
            return "task-20"

    class AsyncContext:
        async def __aenter__(self):
            return Client()

        async def __aexit__(self, *args):
            pass

    monkeypatch.setattr(netbrain_path_service, "_client_for", lambda integration: AsyncContext())
    integration = SimpleNamespace(id=4, organization_id=3, tenant_id="t", domain_id="d")
    db = DB()
    path = await netbrain_path_service.start_calculation(db, integration, {
        "source_asset_id": 11, "target_asset_id": 12,
        "protocol": 4, "destination_port": 0, "is_live": False,
    })
    assert path is db.path
    assert path.source_asset_id == 11 and path.target_asset_id == 12
    assert path.source_scope_id == "org:3:network:vrf-a"
    assert path.target_scope_id == "org:3:network:vrf-b"
    assert path.task_id == "task-20"


@pytest.mark.asyncio
async def test_same_ipv4_on_distinct_assets_does_not_start_calculation(monkeypatch):
    assets = iter([
        SimpleNamespace(id=11, value="10.1.1.5", name="source", ip_address="10.1.1.5",
                        ip_addresses=[], metadata_={}),
        SimpleNamespace(id=12, value="10.1.1.5", name="target", ip_address="10.1.1.5",
                        ip_addresses=[], metadata_={}),
    ])

    class DB:
        def query(self, model):
            return AssetQuery(next(assets))

    monkeypatch.setattr(netbrain_path_service, "_client_for",
                        lambda integration: pytest.fail("NetBrain must not be called"))
    integration = SimpleNamespace(id=4, organization_id=3, tenant_id="t", domain_id="d")
    with pytest.raises(PathSelectionError) as error:
        await netbrain_path_service.start_calculation(DB(), integration, {
            "source_asset_id": 11, "target_asset_id": 12,
        })
    assert error.value.status_code == 409


def test_graph_projection_keeps_hops_under_path_identity(monkeypatch):
    calls = []

    class Result:
        def single(self, strict=False):
            return {"key": "path"}

        def consume(self):
            pass

    class Tx:
        def run(self, query, **params):
            calls.append((query, params))
            return Result()

    class Graph:
        _connected = True

        @contextmanager
        def session(self):
            class Session:
                def execute_write(self, fn):
                    fn(Tx())
            yield Session()

    monkeypatch.setattr(netbrain_path_graph, "get_graph_service", lambda: Graph())
    path = SimpleNamespace(
        id=20, organization_id=3, source_integration_id=4, task_id="task-20",
        source_asset_id=11, target_asset_id=12, source_ip="10.1.1.5", target_ip="10.1.1.5",
        source_scope_id="org:3:network:vrf-a", target_scope_id="org:3:network:vrf-b",
        tenant_id="t", domain_id="d", gateway_ip="10.1.1.1", gateway_device="gw-a",
        gateway_interface="eth1", protocol=4, destination_port=0, is_live=False,
        status="succeeded", completed_at=None,
        hop_list=[{"hop_id": "a", "next_hop_ids": ["b"]}, {"hop_id": "b", "next_hop_ids": []}],
    )
    assert netbrain_path_graph.project_netbrain_path(path)
    assert calls[0][1]["props"]["evidence_type"] == "calculated_route"
    assert calls[0][1]["source_id"] == 11 and calls[0][1]["target_id"] == 12
    assert calls[2][1]["edges"] == [{
        "from_key": "org:3:netbrain-path:20:hop:a", "to_key": "org:3:netbrain-path:20:hop:b"}]
    assert "REACHABLE" not in "".join(query for query, _ in calls)
