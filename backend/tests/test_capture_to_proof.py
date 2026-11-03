"""Live local HTTP fixtures: capture → policy → proof → independent publication.

The fixture implements authorization decisions independently of the proof engine.
Patched variants include deceptive success responses and empty inventories.
"""

import json
import threading
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest
from app.services.agent.assessment_scope import register_scope
from app.services.agent.engagement_brain import engagement_brain_from_dict
from app.services.agent.evidence_store import VerificationRun, verification_run
from app.services.agent.independent_verify import (
    apply_verdict,
    check_verify_receipt,
    submit_candidate,
)
from app.services.agent.request_capture import RequestCaptureStore
from app.services.agent.tools import ASMToolsManager, current_session_id


@pytest.fixture
def crud_app():
    state = {
        "objects": {},
        "sequence": 0,
        "vulnerable": True,
        "calls": [],
        "mode": "normal",
    }
    tenants = {"a": "tenant1", "b": "tenant1", "c": "tenant2"}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def handle_request(self):
            cookie = self.headers.get("Cookie", "")
            auth = self.headers.get("X-Api-Key", "")
            who = next(
                (name for name in tenants if f"sid={name}" in cookie), "anonymous"
            )
            # A leftover owner API key would grant owner access even with B's cookie.
            if auth == "owner-key":
                who = "a"
            content = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            body = (
                {key: values[0] for key, values in parse_qs(content.decode(), keep_blank_values=True).items()}
                if "application/x-www-form-urlencoded" in self.headers.get("Content-Type", "")
                else json.loads(content) if content else {}
            )
            state["calls"].append(
                {
                    "method": self.command,
                    "path": self.path,
                    "identity": who,
                    "cookie": cookie,
                    "api_key": auth,
                    "body": body,
                }
            )
            status, result = 200, {}
            if self.path == "/me":
                result = {
                    "principal": "expired"
                    if state["mode"] == "owner_expired"
                    and state.get("attacked")
                    and who == "a"
                    else who
                }
                if (
                    state["mode"] == "attacker_expired"
                    and state.get("attacked")
                    and who == "b"
                ):
                    result = {"principal": "expired"}
            elif self.path == "/objects" and self.command == "POST":
                state["sequence"] += 1
                obj = {
                    "id": str(state["sequence"]),
                    "owner": who,
                    "tenant": tenants.get(who),
                    "marker": "before",
                    "enabled": False,
                    "quota": 1,
                }
                obj.update(body)
                state["objects"][obj["id"]] = obj
                status, result = 201, obj
            elif self.path == "/objects" and self.command == "GET":
                result = {
                    "items": [
                        dict(o) for o in state["objects"].values() if o["owner"] == who
                    ]
                }
                if state["mode"] == "empty_inventory" and state.get("attacked"):
                    result = {"items": []}
            elif self.path in ("/lookup-form", "/lookup-json", "/graphql") and self.command == "POST":
                if self.path == "/lookup-form":
                    oid = body.get("record", "")
                elif self.path == "/lookup-json":
                    oid = body.get("input", {}).get("record", "")
                else:
                    oid = body.get("variables", {}).get("input", {}).get("record", "")
                obj = state["objects"].get(str(oid))
                if obj is None:
                    status, result = 404, {"error": "missing"}
                elif who != obj["owner"] and not state["vulnerable"]:
                    status, result = 403, {"error": "denied"}
                else:
                    is_mutation = (
                        self.path == "/graphql" and body["query"].startswith("mutation")
                    ) or (
                        self.path != "/graphql"
                        and ("marker" in body or "marker" in body.get("input", {}))
                    )
                    if is_mutation:
                        obj["marker"] = (
                            body["variables"]["input"]["marker"]
                            if self.path == "/graphql"
                            else body.get("marker", body.get("input", {}).get("marker"))
                        )
                        state["attacked"] = who != obj["owner"]
                    result = {"data": {"item" if not is_mutation else "update": dict(obj)}} if self.path == "/graphql" else dict(obj)
            elif urlsplit(self.path).path == "/lookup" and self.command in (
                "GET", "PATCH", "DELETE"
            ):
                oid = parse_qs(urlsplit(self.path).query).get("record", [""])[0]
                obj = state["objects"].get(oid)
                if obj is None:
                    status, result = 404, {"error": "missing"}
                else:
                    allowed = who == obj["owner"] or state["vulnerable"]
                    if self.command != "GET" and who != obj["owner"]:
                        state["attacked"] = True
                    if self.command == "DELETE":
                        if allowed:
                            del state["objects"][oid]
                        status, result = 204, None
                    elif not allowed:
                        status, result = 403, {"error": "denied"}
                    else:
                        if self.command == "PATCH":
                            obj.update(body)
                        result = dict(obj)
            elif self.path.startswith("/objects/"):
                oid = self.path.rsplit("/", 1)[1]
                obj = state["objects"].get(oid)
                if obj is None:
                    status, result = 404, {"error": "missing"}
                else:
                    allowed = who == obj["owner"] or state["vulnerable"]
                    if who != obj["owner"] and self.command != "GET":
                        state["attacked"] = True
                    if self.command in ("PATCH", "PUT"):
                        if allowed and state["mode"] != "echo_only":
                            obj.update(body)
                            if state["mode"] == "coerce_bool":
                                obj["enabled"] = 1
                        result = dict(obj) if allowed else {"ok": True}
                        if state["mode"] == "echo_only":
                            result = dict(body)
                    elif self.command == "DELETE":
                        if state["mode"] == "cleanup_failure" and who == obj["owner"]:
                            status, result = 500, {"error": "cleanup unavailable"}
                        else:
                            if allowed:
                                del state["objects"][oid]
                            # Both patched and vulnerable delete return empty 204.
                            status, result = 204, None
                    else:
                        result = dict(obj) if allowed else {"ok": True}
            elif self.path == "/":
                # Browser fixture discovers a real REST request under its identity.
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><script>fetch('/objects/1')</script></html>")
                return
            else:
                status, result = 404, {"error": "unknown"}
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            if result is not None:
                self.wfile.write(json.dumps(result).encode())

        do_GET = do_POST = do_PATCH = do_PUT = do_DELETE = handle_request

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", state
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


async def prepare(
    base,
    strategy,
    attacker="b",
    value_path="/marker",
    attack_value=None,
    m=None,
    capture=None,
    query_object=False,
):
    m = m or ASMToolsManager()
    register_scope(m, base)
    for name in ("a", "b", "c"):
        await m.register_test_identity(
            name,
            base,
            cookies={"sid": name},
            headers={"X-Api-Key": "owner-key"} if name == "a" else {},
            tenant="tenant2" if name == "c" else "tenant1",
            role="user",
        )
        await m.check_test_identity(name, base + "/me", "principal", name)
    if capture is None:
        obj = await m._http_exchange(
            "POST", base + "/objects", identity="a", body={"marker": "seed"}
        )
        oid = json.loads(obj["_body_text"])["id"]
        method = (
            "GET"
            if strategy == "captured_read"
            else "DELETE"
            if strategy == "captured_delete"
            else "PATCH"
        )
        body = (
            {value_path[1:]: "seed" if value_path == "/marker" else attack_value}
            if method == "PATCH"
            else None
        )
        captured_url = (
            base + "/lookup?record=" + oid + "&view=full"
            if query_object
            else base + "/objects/" + oid
        )
        response = await m._http_exchange(method, captured_url, identity="a", body=body)
        capture = response["capture"]
        assert capture
        # Remove the discovery fixture. Proof runs must provision fresh objects.
        await m._http_exchange("DELETE", base + "/objects/" + oid, identity="a")
    else:
        oid = capture["url"].rsplit("/", 1)[1]
    parameter = (
        "query:record"
        if query_object
        else "body:" + value_path[1:]
        if strategy in ("captured_mutation", "captured_property")
        else ""
    )
    await m.generate_authorization_matrix(
        [
            {
                "operation_id": capture["operation_id"],
                "identity": attacker,
                "parameter": parameter,
                "expected": "deny",
            }
        ],
        operation_ids=[capture["operation_id"]],
        identity_names=[attacker],
    )
    cell = next(
        row
        for row in m._engagement_brain["authorization_matrix"]
        if row["operation_id"] == capture["operation_id"]
        and row["parameter"] == parameter
    )
    config = {
        "strategy": strategy,
        "object_parameter": "query:record" if query_object else "path",
        "value_path": value_path,
        "attack_value": attack_value,
        "setup": {
            "method": "POST",
            "url": base + "/objects",
            "body": {"enabled": False, "quota": 1},
        },
        "verify": {
            "url": base
            + (
                "/objects"
                if strategy == "captured_delete"
                else "/lookup?record={{object_id}}&view=full"
                if query_object
                else "/objects/{{object_id}}"
            )
        },
        "cleanup": {"url": base + "/objects/{{object_id}}"},
    }
    await m.prepare_captured_authorization_proof(
        cell["hypothesis_id"], capture["id"], "a", "" if query_object else oid, config
    )
    return m, cell, capture, config


@pytest.mark.asyncio
@pytest.mark.parametrize("attacker", ["b", "c"])
@pytest.mark.parametrize("vulnerable", [True, False])
@pytest.mark.parametrize(
    "strategy,path,value",
    [
        ("captured_read", "/marker", None),
        ("captured_mutation", "/marker", None),
        ("captured_property", "/enabled", True),
        ("captured_property", "/quota", 17),
        ("captured_delete", "/marker", None),
    ],
)
async def test_detection_matrix_with_fresh_independent_verification(
    crud_app, attacker, vulnerable, strategy, path, value
):
    base, state = crud_app
    state["vulnerable"] = vulnerable
    m, cell, capture, _ = await prepare(base, strategy, attacker, path, value)
    hunter = json.loads(await m.run_authorization_proof(cell["hypothesis_id"]))[
        "receipt"
    ]
    expected = (
        "confirmed"
        if vulnerable
        else "inconclusive"
        if strategy == "captured_read"
        else "refuted"
    )
    assert hunter["verdict"] == expected, hunter
    assert hunter["capture_id"] == capture["id"]
    assert hunter["cleanup_status"] == "attempted"
    assert not state["objects"]
    assert not m._verify_receipts  # Hunter success cannot publish.
    if vulnerable:
        brain = engagement_brain_from_dict(m._engagement_brain)
        candidate = submit_candidate(
            brain,
            title="Controlled unauthorized operation",
            target=capture["url"],
            hypothesis_id=cell["hypothesis_id"],
        )
        m._engagement_brain = brain.to_dict()
        token = verification_run.set(
            VerificationRun(
                "independent", candidate.id, candidate.revision, candidate.nonce
            )
        )
        try:
            denied = apply_verdict(
                m,
                candidate_id=candidate.id,
                verdict="confirmed",
                evidence="hunter proof",
                evidence_ids=hunter["evidence_ids"],
                proof={"kind": "workflow", "run_id": hunter["run_id"]},
            )
            assert denied.status == "inconclusive"
            fresh = json.loads(await m.run_authorization_proof(cell["hypothesis_id"]))[
                "receipt"
            ]
            assert fresh["verdict"] == "confirmed", fresh
            accepted = apply_verdict(
                m,
                candidate_id=candidate.id,
                verdict="confirmed",
                evidence="fresh controlled impact",
                evidence_ids=fresh["evidence_ids"],
                proof={"kind": "workflow", "run_id": fresh["run_id"]},
            )
            assert accepted.status == "confirmed", accepted
        finally:
            verification_run.reset(token)
        assert check_verify_receipt(
            m._verify_receipts,
            title=candidate.title,
            target=candidate.target,
            tools_manager=m,
        )[0]
    # Identity substitution must discard A's cookie AND API key.
    attacks = [c for c in state["calls"] if c["identity"] == attacker]
    assert attacks and all(
        c["api_key"] == "" and "sid=a" not in c["cookie"] for c in attacks
    )
    assert not state["objects"]


@pytest.mark.asyncio
@pytest.mark.parametrize("vulnerable", [True, False])
@pytest.mark.parametrize("strategy", ["captured_read", "captured_mutation", "captured_delete"])
async def test_query_object_id_is_captured_and_proved_with_two_identities(
    crud_app, vulnerable, strategy
):
    base, state = crud_app
    state["vulnerable"] = vulnerable
    m, cell, capture, _ = await prepare(base, strategy, query_object=True)
    assert capture["url"] == base + "/lookup"
    assert capture["query_fields"] == ["record", "view"]
    handoff = json.loads(await m.list_authorization_leads(capture["operation_id"]))
    lead = next(row for row in handoff["leads"] if row["reference"] == "query:record")
    assert lead["capture_id"] == capture["id"]
    assert lead["status"] == "proof_prepared"
    assert handoff["summary"]["proof_prepared"] >= 1
    assert handoff["summary"]["eligible_captures"] >= 1
    assert isinstance(handoff["summary"]["capture_rejections_session"], dict)
    coverage_before = json.loads(await m.get_assessment_coverage())
    assert coverage_before["authorization_handoff"]["candidates"] >= 1
    assert any(
        row["capture_id"] == capture["id"]
        and row["test_type"] == "authz"
        and row["parameter"] == "query:record"
        for row in m._engagement_brain["coverage_cells"]
    )
    assert not any(
        row["source"] == "authorization_capture"
        and row["parameter"] == "query:view"
        for row in m._engagement_brain["coverage_cells"]
    )
    private = m._capture_requests().get(capture["id"])
    assert private["request"]["url"].endswith("?record=1&view=full")
    receipt = json.loads(await m.run_authorization_proof(cell["hypothesis_id"]))[
        "receipt"
    ]
    expected = (
        "confirmed" if vulnerable else "inconclusive"
        if strategy == "captured_read" else "refuted"
    )
    assert receipt["verdict"] == expected
    after = json.loads(await m.list_authorization_leads(capture["operation_id"]))
    assert next(row for row in after["leads"] if row["reference"] == "query:record")["status"] == "proof_attempted"
    assert receipt["cleanup_status"] == "attempted"
    assert not state["objects"]
    assert any(
        c["identity"] == "b"
        and c["path"].startswith("/lookup?record=")
        and c["path"].endswith("&view=full")
        for c in state["calls"]
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("vulnerable", [True, False])
@pytest.mark.parametrize("kind", ["form_read", "json_read", "graphql_read", "form_write", "json_write", "graphql_write"])
async def test_post_body_and_graphql_reference_proof(crud_app, vulnerable, kind):
    base, state = crud_app
    state["vulnerable"] = vulnerable
    m = ASMToolsManager()
    register_scope(m, base)
    for name in ("a", "b"):
        await m.register_test_identity(name, base, cookies={"sid": name}, role="user")
        await m.check_test_identity(name, base + "/me", "principal", name)
    created = await m._http_exchange("POST", base + "/objects", identity="a", body={"marker": "seed"})
    oid = json.loads(created["_body_text"])["id"]
    family, action = kind.split("_")
    is_write = action == "write"
    if family == "form":
        url = base + "/lookup-form"
        body = f"view=full&record={oid}" + ("&marker=seed" if is_write else "")
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        selector, parameter = "form:record", "body:record"
        attack_value_path = "form:marker"
    elif family == "json":
        url = base + "/lookup-json"
        body = {"input": {"record": oid, "view": "full", **({"marker": "seed"} if is_write else {})}}
        headers = {"Content-Type": "application/json"}
        selector, parameter = "body:/input/record", "body:input"
        attack_value_path = "/input/marker"
    else:
        url = base + "/graphql"
        body = {
            "query": (
                "mutation Update($input: ItemInput!) { update(input: $input) { id marker } }"
                if is_write else
                "query Read($input: ItemInput!) { item(input: $input) { id marker } }"
            ),
            "variables": {"input": {"record": oid, "view": "full", **({"marker": "seed"} if is_write else {})}},
        }
        headers = {"Content-Type": "application/json"}
        selector, parameter = "variable:/input/record", "variable:input"
        attack_value_path = "/variables/input/marker"
    observed = await m._http_exchange("POST", url, identity="a", body=body, headers=headers)
    capture = observed["capture"]
    assert capture and capture["protocol"] == ("graphql" if family == "graphql" else "rest")
    assert any(row["reference"] == selector for row in capture["authorization_references"])
    await m._http_exchange("DELETE", base + "/objects/" + oid, identity="a")
    await m.generate_authorization_matrix(
        [{"operation_id": capture["operation_id"], "identity": "b", "parameter": parameter, "expected": "deny"}],
        operation_ids=[capture["operation_id"]], identity_names=["b"],
    )
    cell = next(row for row in m._engagement_brain["authorization_matrix"]
                if row["operation_id"] == capture["operation_id"] and row["parameter"] == parameter)
    config = {
        "strategy": "captured_mutation" if is_write else "captured_read",
        "object_parameter": selector,
        "post_read_only": not is_write,
        "attack_value_path": attack_value_path,
        "setup": {"url": base + "/objects", "body": {}},
        "verify": {"url": base + "/objects/{{object_id}}"},
        "cleanup": {"url": base + "/objects/{{object_id}}"},
    }
    if family == "graphql":
        config.update(attack_object_path="/data/item/id", attack_canary_path="/data/item/marker")
    await m.prepare_captured_authorization_proof(cell["hypothesis_id"], capture["id"], "a", oid, config)
    receipt = json.loads(await m.run_authorization_proof(cell["hypothesis_id"]))["receipt"]
    assert receipt["verdict"] == ("confirmed" if vulnerable else "refuted" if is_write else "inconclusive"), receipt
    assert receipt["cleanup_status"] == "attempted"
    attacks = [call for call in state["calls"] if call["identity"] == "b" and call["path"] == url.removeprefix(base)]
    assert len(attacks) == 1
    preserved = (
        attacks[0]["body"]["view"] if family == "form"
        else attacks[0]["body"]["input"]["view"] if family == "json"
        else attacks[0]["body"]["variables"]["input"]["view"]
    )
    assert preserved == "full"
    if vulnerable and kind == "graphql_write":
        brain = engagement_brain_from_dict(m._engagement_brain)
        candidate = submit_candidate(
            brain, title="Unauthorized GraphQL variable mutation",
            target=capture["url"], hypothesis_id=cell["hypothesis_id"],
        )
        m._engagement_brain = brain.to_dict()
        token = verification_run.set(
            VerificationRun("independent", candidate.id, candidate.revision, candidate.nonce)
        )
        try:
            fresh = json.loads(await m.run_authorization_proof(cell["hypothesis_id"]))["receipt"]
            assert fresh["verdict"] == "confirmed"
            accepted = apply_verdict(
                m, candidate_id=candidate.id, verdict="confirmed",
                evidence="fresh variable-bound owner readback",
                evidence_ids=fresh["evidence_ids"],
                proof={"kind": "workflow", "run_id": fresh["run_id"]},
            )
            assert accepted.status == "confirmed", accepted
        finally:
            verification_run.reset(token)
    assert not state["objects"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mode,strategy,path,value,expected",
    [
        ("echo_only", "captured_mutation", "/marker", None, "refuted"),
        ("coerce_bool", "captured_property", "/enabled", True, "inconclusive"),
        ("empty_inventory", "captured_delete", "/marker", None, "inconclusive"),
        ("owner_expired", "captured_mutation", "/marker", None, "inconclusive"),
        ("attacker_expired", "captured_mutation", "/marker", None, "inconclusive"),
    ],
)
async def test_deceptive_successes_do_not_confirm(
    crud_app, mode, strategy, path, value, expected
):
    base, state = crud_app
    m, cell, _, _ = await prepare(base, strategy, value_path=path, attack_value=value)
    state["mode"] = mode
    result = json.loads(await m.run_authorization_proof(cell["hypothesis_id"]))[
        "receipt"
    ]
    assert result["verdict"] == expected, result
    assert not m._verify_receipts
    assert not state["objects"]


@pytest.mark.asyncio
async def test_cleanup_failure_is_visible_without_erasing_valid_impact(crud_app):
    base, state = crud_app
    m, cell, _, _ = await prepare(base, "captured_mutation")
    state["mode"] = "cleanup_failure"
    result = json.loads(await m.run_authorization_proof(cell["hypothesis_id"]))[
        "receipt"
    ]
    assert result["verdict"] == "confirmed"
    assert result["cleanup_status"] == "needs_follow_up"
    assert result["cleanup_evidence_ids"]
    coverage = json.loads(await m.get_assessment_coverage())
    assert (
        next(
            r for r in coverage["rows"] if r["hypothesis_id"] == cell["hypothesis_id"]
        )["cleanup_status"]
        == "needs_follow_up"
    )


@pytest.mark.asyncio
async def test_imported_hints_and_changed_plans_cannot_mint_capture_authority(crud_app):
    base, _ = crud_app
    m, cell, capture, config = await prepare(base, "captured_mutation")
    with pytest.raises(ValueError, match="Unknown or expired"):
        await m.prepare_captured_authorization_proof(
            cell["hypothesis_id"], "fabricated", "a", "1", config
        )
    changed = deepcopy(m._proof_plans[cell["hypothesis_id"]])
    changed["attack"]["headers"]["Authorization"] = "owner-token"
    with pytest.raises(ValueError, match="registered plans"):
        await m.run_authorization_proof(cell["hypothesis_id"], changed)
    token = current_session_id.set("other-assessment")
    try:
        assert json.loads(await m.list_proof_captures())["captures"] == []
        with pytest.raises(ValueError):
            m._capture_requests().get(capture["id"])
    finally:
        current_session_id.reset(token)


def test_capture_store_bounds_redaction_and_immutability():
    store = RequestCaptureStore(limit=2)
    request = {
        "method": "PATCH",
        "url": "https://app.test/items/1",
        "body": {"enabled": False},
        "headers": {
            "Authorization": "secret",
            "Cookie": "sid=a",
            "X-Api-Key": "secret",
            "Content-Type": "application/json",
        },
    }
    first = store.record(request, identity="a", source="browser")
    assert "secret" not in json.dumps(store.get(first["id"]))
    copy = store.get(first["id"])
    copy["request"]["body"]["enabled"] = True
    assert store.get(first["id"])["request"]["body"]["enabled"] is False
    for body in (
        {"accessToken": "abc"},
        {"password": "abc"},
        {"data": "{{nonce}}"},
        "not-json",
        {"x": "x" * 70000},
    ):
        assert (
            store.record({**request, "body": body}, identity="a", source="browser")
            is None
        )
    assert (
        store.record(
            {**request, "url": request["url"] + "?token=abc"},
            identity="a",
            source="browser",
        )
        is None
    )
    query_capture = store.record(
        {**request, "url": request["url"] + "?record=1&view=full"},
        identity="a",
        source="browser",
    )
    assert query_capture["url"] == request["url"]
    assert query_capture["query_fields"] == ["record", "view"]
    assert "record=1" not in json.dumps(query_capture)
    assert store.get(query_capture["id"])["request"]["url"].endswith(
        "?record=1&view=full"
    )
    for _ in range(2):
        store.record(request, identity="a", source="browser")
    with pytest.raises(ValueError, match="expired"):
        store.get(first["id"])


def test_query_object_binding_requires_one_exact_value_and_preserves_other_fields():
    from app.services.agent.captured_proof import bind_captured_object_url

    url = "https://app.test/lookup?view=full&record=a%2Bb&sort=asc"
    bound, location = bind_captured_object_url(url, "a+b")
    assert location == "query:record"
    assert bound == "https://app.test/lookup?view=full&record={{object_id}}&sort=asc"
    assert bind_captured_object_url(url, "", "query:record") == (bound, location)
    with pytest.raises(ValueError, match="exactly one"):
        bind_captured_object_url("https://app.test/lookup?first=1&second=1", "1")
    with pytest.raises(ValueError, match="exactly one"):
        bind_captured_object_url(
            "https://app.test/lookup?record=1&record=2", "", "query:record"
        )
    with pytest.raises(ValueError, match="exactly one"):
        bind_captured_object_url(url, "b")


def test_new_tools_registered_and_guided():
    from app.services.agent.prompts import (
        APPLICATION_ASSESSMENT_GUIDANCE,
        is_tool_allowed_in_phase,
    )

    m = ASMToolsManager()
    for name in (
        "list_proof_captures", "list_authorization_leads",
        "prepare_captured_authorization_proof",
    ):
        assert name in m.tools and is_tool_allowed_in_phase(name, "exploitation")
        assert name in APPLICATION_ASSESSMENT_GUIDANCE


@pytest.mark.asyncio
async def test_patch_between_discovery_and_verification_prevents_publication(crud_app):
    base, state = crud_app
    m, cell, capture, _ = await prepare(base, "captured_delete")
    assert (
        json.loads(await m.run_authorization_proof(cell["hypothesis_id"]))["receipt"][
            "verdict"
        ]
        == "confirmed"
    )
    brain = engagement_brain_from_dict(m._engagement_brain)
    candidate = submit_candidate(
        brain,
        title="Unauthorized delete",
        target=capture["url"],
        hypothesis_id=cell["hypothesis_id"],
    )
    m._engagement_brain = brain.to_dict()
    state["vulnerable"] = False
    token = verification_run.set(
        VerificationRun("patched", candidate.id, candidate.revision, candidate.nonce)
    )
    try:
        result = json.loads(await m.run_authorization_proof(cell["hypothesis_id"]))[
            "receipt"
        ]
        assert result["verdict"] == "refuted"
        verdict = apply_verdict(
            m,
            candidate_id=candidate.id,
            verdict="confirmed",
            evidence="incorrect model claim",
            evidence_ids=result["evidence_ids"],
            proof={"kind": "workflow", "run_id": result["run_id"]},
        )
        assert verdict.status == "inconclusive"
    finally:
        verification_run.reset(token)
    assert not check_verify_receipt(
        m._verify_receipts,
        title=candidate.title,
        target=candidate.target,
        tools_manager=m,
    )[0]


@pytest.mark.asyncio
async def test_actionful_failure_does_not_repeat_mutation_and_attempts_cleanup(
    crud_app,
):
    base, state = crud_app
    m, cell, _, _ = await prepare(base, "captured_mutation")
    original = m._http_exchange

    async def lose_response(*args, **kwargs):
        response = await original(*args, **kwargs)
        if kwargs.get("method") == "PATCH" and kwargs.get("identity") == "b":
            raise TimeoutError("connection lost after application processed mutation")
        return response

    m._http_exchange = lose_response
    receipt = json.loads(await m.run_authorization_proof(cell["hypothesis_id"]))[
        "receipt"
    ]
    assert receipt["verdict"] == "inconclusive"
    assert (
        len(
            [
                c
                for c in state["calls"]
                if c["method"] == "PATCH" and c["identity"] == "b"
            ]
        )
        == 1
    )
    assert receipt["cleanup_status"] == "attempted"
    assert not state["objects"]


@pytest.mark.asyncio
async def test_unidentified_setup_failure_leaves_cleanup_followup(crud_app):
    base, state = crud_app
    m, cell, _, _ = await prepare(base, "captured_delete")
    original = m._http_exchange

    async def lose_response(*args, **kwargs):
        response = await original(*args, **kwargs)
        if kwargs.get("method") == "POST":
            raise TimeoutError("object created but identifier response lost")
        return response

    m._http_exchange = lose_response
    receipt = json.loads(await m.run_authorization_proof(cell["hypothesis_id"]))[
        "receipt"
    ]
    assert receipt["verdict"] == "inconclusive"
    assert receipt["cleanup_status"] == "needs_follow_up"
    assert len(state["objects"]) == 1
