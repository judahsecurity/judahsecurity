"""External-agent exploit chains: ingest -> agent_detection -> campaign graph."""

from types import SimpleNamespace

from app.schemas.unified_results import ResultType, UnifiedFinding
from app.services.agent.demonstrated_chain import normalize_chain
from app.services.attack_path_campaign import FindingView, build_graph, declared_techniques
from app.services import ingestion_service


class _Query:
    """Enough of a SQLAlchemy query for _apply_agent_detection."""

    def __init__(self, rows):
        self._rows = rows

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return self._rows[0] if self._rows else None

    def __iter__(self):
        return iter(self._rows)


class _DB:
    def __init__(self, by_host, valid_ids):
        self.by_host = by_host
        self.valid_ids = valid_ids
        self.lookups = []

    def query(self, *cols):
        # First call shape: lookup by host; second: validation of claimed ids.
        if self.by_host:
            host, aid = self.by_host.pop(0)
            self.lookups.append(host)
            return _Query([(aid,)] if aid else [])
        return _Query([(i,) for i in self.valid_ids])


def _finding(detection):
    return UnifiedFinding(
        type=ResultType.VULNERABILITY,
        source="aegis-vanguard-chain",
        target="app.example.com",
        host="app.example.com",
        title="[CHAIN] IDOR -> admin",
        severity="critical",
        raw_data={"agent_detection": detection},
    )


def test_step_anchors_survive_normalisation():
    steps = normalize_chain([
        {"summary": "read other user", "tool": "send_http_request", "stdout": "HTTP/1.1 200 OK",
         "asset": "https://api.example.com/users/2", "mitre_id": "t1190", "finding_ref": "IDOR"},
        {"summary": "role set", "asset_id": 7, "mitre_id": "not-a-technique"},
    ])
    assert steps[0]["asset"] == "https://api.example.com/users/2"
    assert steps[0]["mitre_id"] == "T1190"
    assert steps[0]["finding_ref"] == "IDOR"
    assert steps[1]["asset_id"] == 7
    assert "mitre_id" not in steps[1]


def test_apply_agent_detection_resolves_step_assets_and_session():
    asset = SimpleNamespace(id=1, organization_id=10, value="app.example.com")
    vuln = SimpleNamespace(metadata_={})
    detection = {
        "source": "aegis-vanguard",
        "session_id": "run-42",
        "chain": [
            {"summary": "IDOR on users", "asset": "https://api.example.com/users/2", "mitre_id": "T1190"},
            {"summary": "mass assignment", "asset": "app.example.com", "mitre_id": "T1098"},
            {"summary": "unknown host", "asset": "other.example.net"},
        ],
    }
    db = _DB(by_host=[("api.example.com", 2), ("other.example.net", None)], valid_ids=[])

    touched = ingestion_service._apply_agent_detection(db, vuln, asset, _finding(detection))

    stored = vuln.metadata_["agent_detection"]
    assert stored["session_id"] == "run-42"
    assert stored["step_count"] == 3
    chain = stored["chain"]
    assert chain[0]["asset_id"] == 2          # looked up
    assert chain[1]["asset_id"] == 1          # the finding's own asset, no query
    assert "asset_id" not in chain[2]          # unknown host stays unlinked
    assert db.lookups == ["api.example.com", "other.example.net"]
    assert touched == [1, 2]


def test_apply_agent_detection_drops_foreign_asset_ids():
    asset = SimpleNamespace(id=1, organization_id=10, value="app.example.com")
    vuln = SimpleNamespace(metadata_={})
    detection = {"chain": [
        {"summary": "a", "asset_id": 99},
        {"summary": "b", "asset_id": 5},
    ]}
    db = _DB(by_host=[], valid_ids=[5])

    touched = ingestion_service._apply_agent_detection(db, vuln, asset, _finding(detection))

    chain = vuln.metadata_["agent_detection"]["chain"]
    assert "asset_id" not in chain[0]
    assert chain[1]["asset_id"] == 5
    assert touched == [1, 5]


def test_apply_agent_detection_keeps_longer_existing_chain():
    asset = SimpleNamespace(id=1, organization_id=10, value="app.example.com")
    existing = {"source": "agent", "chain": [{"step": i} for i in range(1, 4)], "step_count": 3}
    vuln = SimpleNamespace(metadata_={"agent_detection": existing})
    detection = {"chain": [{"summary": "only one", "asset": "app.example.com"}]}

    ingestion_service._apply_agent_detection(_DB([], []), vuln, asset, _finding(detection))

    assert vuln.metadata_["agent_detection"] is existing


def test_poc_without_chain_still_stored():
    asset = SimpleNamespace(id=1, organization_id=10, value="app.example.com")
    vuln = SimpleNamespace(metadata_=None)
    finding = _finding({})
    finding.raw_data = {"poc": {"payload": "' OR 1=1"}}

    assert ingestion_service._apply_agent_detection(_DB([], []), vuln, asset, finding) == []
    assert vuln.metadata_ == {"poc": {"payload": "' OR 1=1"}}


def test_declared_techniques_drive_campaign_nodes():
    steps = [
        {"step": 1, "summary": "recon", "tool": "send_http_request", "mitre_id": "T1595.002"},
        {"step": 2, "summary": "token forged", "tool": "send_http_request", "mitre_id": "T1550.001"},
    ]
    assert [t["id"] for t in declared_techniques(steps)] == ["T1550.001", "T1595.002"]

    row = FindingView(
        id=7, title="JWT forgery", host="app.example.com", severity="critical",
        has_chain=True, session_id="run-42", chain_steps=steps, detected_by="aegis-vanguard-chain",
    )
    nodes, _, _ = build_graph([row])
    mitre = {n["mitre_id"] for n in nodes if n["kind"] == "technique"}
    assert "T1595.002" in mitre      # declared recon technique wins over tool map
    assert "T1550.001" in mitre      # declared impact technique beats heuristics


def test_graph_projection_links_chain_to_assets():
    from app.services.graph_service import GraphService

    calls = []

    class _Session:
        def run(self, cypher, params=None):
            calls.append((" ".join(cypher.split()), params or {}))

    vuln = SimpleNamespace(id=7, asset_id=1, metadata_={"agent_detection": {
        "source": "aegis-vanguard",
        "session_id": "run-42",
        "chain": [
            {"step": 1, "asset_id": 2, "mitre_id": "T1190"},
            {"step": 2, "mitre_id": "T1098"},       # falls back to the vuln's asset
            {"step": 3, "asset_id": 2},
        ],
    }})

    GraphService.__new__(GraphService)._sync_agent_chain(_Session(), vuln, org_id=10)

    demonstrated = {p["asset_id"]: p for c, p in calls if "DEMONSTRATED_ON" in c}
    assert demonstrated[2]["steps"] == [1, 3]
    assert demonstrated[2]["techniques"] == ["T1190"]
    assert demonstrated[1]["steps"] == [2]
    assert all(p["org_id"] == 10 for p in demonstrated.values())
    assert sorted(p["tech"] for c, p in calls if "AttackTechnique" in c) == ["T1098", "T1190"]
    assert any("AttackChain" in c and p["sid"] == "run-42" for c, p in calls)


def test_graph_projection_ignores_plain_vulns():
    from app.services.graph_service import GraphService

    calls = []

    class _Session:
        def run(self, cypher, params=None):
            calls.append(cypher)

    vuln = SimpleNamespace(id=8, asset_id=1, metadata_={"oracle": {}})
    GraphService.__new__(GraphService)._sync_agent_chain(_Session(), vuln, org_id=10)
    assert calls == []
