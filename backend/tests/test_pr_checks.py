"""PR checks: changed source -> advisory findings, routes, and Prowl handoff."""

import asyncio
import json
from types import SimpleNamespace

import pytest

from app.services.agent.engagement_brain import engagement_brain_from_dict
from app.services.pr_check_service import (
    added_lines_from_patch,
    analyze,
    synthetic_requests_for_routes,
)

FLASK = '''from flask import Flask, request
app = Flask(__name__)

@app.route("/items/<int:item_id>", methods=["GET", "POST"])
def item(item_id):
    sort = request.args.get("sort")
    cur.execute(f"SELECT * FROM items WHERE id={item_id} ORDER BY {sort}")
    return "ok"

@app.post("/search")
def search(q: str, page: int = 1, body: SearchBody = None, db: Session = Depends(get_db)):
    return run(q)
'''

EXPRESS = '''const router = express.Router();
router.get('/users/:userId', async (req, res) => {
  const { tab, filter } = req.query;
  const rows = await db.query(`SELECT * FROM users WHERE id = ${req.params.userId}`);
  res.send(rows);
});
router.post('/comments', (req, res) => {
  el.innerHTML = req.body.text;
});
const API_KEY = "sk_live_9f8e7d6c5b4a3210";
const SAMPLE_KEY = "example_key_123456789";
'''

SPRING = '''@RestController
@RequestMapping("/api/orders")
public class OrderController {
    @GetMapping("/{orderId}")
    public Order get(@PathVariable Long orderId, @RequestParam("view") String view) {
        return repo.executeQuery("SELECT * FROM orders WHERE id = " + orderId);
    }
}
'''


def test_patch_parsing_tracks_added_lines_only():
    patch = "@@ -1,2 +1,3 @@\n line1\n+added2\n line3\n@@ -10,0 +11,2 @@\n+a\n+b\n"
    assert added_lines_from_patch(patch) == {2, 11, 12}


def test_routes_and_inputs_are_extracted_across_frameworks():
    result = analyze([
        {"path": "app/views.py", "content": FLASK},
        {"path": "web/routes.js", "content": EXPRESS},
        {"path": "src/OrderController.java", "content": SPRING},
    ], use_semgrep=False)
    routes = {(r["method"], r["path"]): r for r in result.routes}
    assert ("GET", "/items/{item_id}") in routes and ("POST", "/items/{item_id}") in routes
    assert routes[("GET", "/items/{item_id}")]["parameters"] == [{"location": "query", "name": "sort"}]
    search = routes[("POST", "/search")]
    assert {p["name"] for p in search["parameters"]} == {"q", "page"}  # model + Depends skipped
    users = routes[("GET", "/users/{userId}")]
    assert {p["name"] for p in users["parameters"]} == {"tab", "filter"}
    assert routes[("POST", "/comments")]["parameters"] == [{"location": "body_json", "name": "text"}]
    order = routes[("GET", "/api/orders/{orderId}")]
    assert order["parameters"] == [{"location": "query", "name": "view"}]


def test_rules_are_capped_masked_and_linked_to_routes():
    result = analyze([
        {"path": "app/views.py", "content": FLASK},
        {"path": "web/routes.js", "content": EXPRESS},
        {"path": "src/OrderController.java", "content": SPRING},
    ], use_semgrep=False)
    by_rule = {}
    for finding in result.findings:
        by_rule.setdefault(finding["rule_id"], []).append(finding)
    assert by_rule["py-sql-format"][0]["route"] == {"method": "GET", "path": "/items/{item_id}"}
    assert by_rule["js-sql-template"][0]["route"]["path"] == "/users/{userId}"
    assert by_rule["java-sql-concat"][0]["live_test_class"] == "sqli"
    assert by_rule["js-html-sink"][0]["severity"] == "low"
    secrets = by_rule["hardcoded-secret"]
    assert len(secrets) == 1  # placeholder "example_" value is ignored
    assert "9f8e7d6c5b4a3210" not in secrets[0]["snippet"]
    assert all(f["severity"] in {"info", "low", "medium"} for f in result.findings)
    assert all(f["advisory"] and f["verification_level"] == "source_only" for f in result.findings)
    assert result.conclusion("medium") == "failure"
    assert result.conclusion("high") == "success"


def test_only_added_lines_are_flagged_and_unsafe_paths_skipped():
    patch = "@@ -1,0 +1,1 @@\n+const router = express.Router();\n"
    result = analyze([
        {"path": "web/routes.js", "content": EXPRESS, "patch": patch},
        {"path": "../etc/passwd", "content": "x"},
        {"path": "node_modules/x/index.js", "content": "eval(x)"},
    ], use_semgrep=False)
    assert result.findings == []
    assert set(result.skipped_files) == {"../etc/passwd", "node_modules/x/index.js"}
    assert result.routes  # routes still mapped from the full file


def test_synthetic_requests_are_value_free():
    routes = [{"method": "POST", "path": "/comments/{postId}",
               "parameters": [{"location": "body_json", "name": "text"},
                              {"location": "query", "name": "draft"}]}]
    [request] = synthetic_requests_for_routes(routes, "https://app.example.test")
    assert request["url"] == "https://app.example.test/comments/1?draft=test"
    assert request["body"] == {"text": "test"}


# ---------------------------------------------------------------------------
# API + agent handoff (stub DB)
# ---------------------------------------------------------------------------

class _Query:
    def __init__(self, rows):
        self.rows = rows

    def filter(self, *_a, **_k):
        return self

    def order_by(self, *_a):
        return self

    def limit(self, *_a):
        return self

    def first(self):
        return self.rows[0] if self.rows else None

    def all(self):
        return self.rows


class _DB:
    def __init__(self, tables):
        self.tables, self.added, self.commits = tables, [], 0

    def query(self, model):
        return _Query(self.tables.get(model.__name__, []))

    def add(self, row):
        self.added.append(row)

    def commit(self):
        self.commits += 1

    def close(self):
        pass


def test_scope_is_required_even_when_key_scopes_are_empty():
    from app.api.routes.pr_checks import require_pr_check_key
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as denied:
        require_pr_check_key(SimpleNamespace(scopes=[]))
    assert denied.value.status_code == 403
    key = SimpleNamespace(scopes=["pr:check"])
    assert require_pr_check_key(key) is key


def test_create_pr_check_persists_and_concludes():
    from app.api.routes.pr_checks import ChangedFileIn, PrCheckRequest, create_pr_check

    asset = SimpleNamespace(id=42, value="app.example.test", organization_id=3)
    db = _DB({"Asset": [asset]})
    key = SimpleNamespace(organization_id=3, key_id="k" * 32, scopes=["pr:check"])
    body = create_pr_check(PrCheckRequest(
        repository="acme/app", pull_request=7, head_sha="h", base_sha="b", asset_id=42,
        files=[ChangedFileIn(path="web/routes.js", content=EXPRESS)],
    ), agent_key=key, db=db)
    assert body["conclusion"] == "failure" and db.commits == 1
    stored = db.added[0]
    assert stored.organization_id == 3 and stored.asset_id == 42
    assert "import_source_routes" in body["next_step"]


def test_agent_tool_imports_routes_for_matching_target(monkeypatch):
    from app.db import database
    from app.models.pr_check import PrCheck
    from app.services.agent import tools as tools_module
    from app.services.agent.tools import ASMToolsManager

    result = analyze([{"path": "web/routes.js", "content": EXPRESS}], use_semgrep=False)
    check = PrCheck(id="c" * 32, organization_id=3, asset_id=42,
                    routes=result.routes, findings=result.findings)
    asset = SimpleNamespace(id=42, value="app.example.test", organization_id=3)
    monkeypatch.setattr(database, "SessionLocal", lambda: _DB({"PrCheck": [check], "Asset": [asset]}))
    monkeypatch.setattr(tools_module, "get_tenant_context", lambda: (1, 3))

    manager = ASMToolsManager.__new__(ASMToolsManager)
    origin = "https://app.example.test"
    manager._engagement_brain = {"target": origin}
    manager._capability_map = {"target": origin, "scope": origin}
    out = json.loads(asyncio.run(manager.import_source_routes()))
    assert out["operations_added"] == 2
    assert any(lead["live_test_class"] == "sqli" for lead in out["source_leads"])
    brain = engagement_brain_from_dict(manager._engagement_brain)
    assert {s for op in brain.application_operations for s in op["sources"]} == {"source_code"}
    assert "query:tab" in {c.get("parameter") for c in brain.coverage_cells}

    other = SimpleNamespace(id=42, value="other.example.test", organization_id=3)
    monkeypatch.setattr(database, "SessionLocal", lambda: _DB({"PrCheck": [check], "Asset": [other, asset]}))
    with pytest.raises(ValueError):
        asyncio.run(manager.import_source_routes(check_id="c" * 32))
