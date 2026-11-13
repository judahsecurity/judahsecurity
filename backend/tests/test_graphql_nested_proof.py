"""GraphQL owner data must survive the same-query cross-identity replay."""

import json
from types import SimpleNamespace

from app.services.agent.proof_policy import validate_proof


def _record(identity, principal, body, response):
    return {
        "kind": "http_exchange", "identity": identity,
        "payload": {
            "request": {
                "url": "https://app.test/graphql", "method": "POST",
                "body": body, "identity_verified": True, "principal_id": principal,
            },
            "response": {"status": 200, "body": json.dumps(response)},
        },
    }


def test_nested_owner_field_requires_same_graphql_object_and_distinct_principals():
    query = '{"query":"query($id: ID!) { node(id: $id) { ownerId } }", "variables":{"id":"1"}}'
    owner = _record("owner", "user-1", query, {"data": {"node": {"ownerId": "user-1"}}})
    attacker = _record("attacker", "user-2", query, {"data": {"node": {"ownerId": "user-1"}}})
    control = _record("anonymous", "", query, {"data": {"node": None}, "errors": [{"message": "forbidden"}]})
    store = SimpleNamespace(records={"owner": owner, "attacker": attacker, "control": control})
    proof = {"kind": "authorization", "baseline_id": "owner", "mutant_id": "attacker",
             "field": "data.node.ownerId", "control_id": "control"}
    ids = ["owner", "attacker", "control"]
    candidate = SimpleNamespace(title="GraphQL authorization bypass", description="foreign node")
    assert validate_proof(store, candidate, proof, ids)[0]

    attacker["payload"]["request"]["body"] = query.replace('"1"', '"2"')
    assert not validate_proof(store, candidate, proof, ids)[0]
    attacker["payload"]["request"]["body"] = query
    attacker["payload"]["response"]["body"] = json.dumps({"data": {"node": None}})
    assert not validate_proof(store, candidate, proof, ids)[0]


def test_cross_user_access_needs_a_denied_anonymous_control():
    query = '{"query":"query($id: ID!) { node(id: $id) { ownerId } }", "variables":{"id":"1"}}'
    node = {"data": {"node": {"ownerId": "user-1"}}}
    owner = _record("owner", "user-1", query, node)
    attacker = _record("attacker", "user-2", query, node)
    public = _record("anonymous", "", query, node)
    store = SimpleNamespace(records={"owner": owner, "attacker": attacker, "control": public})
    candidate = SimpleNamespace(title="GraphQL authorization bypass", description="foreign node")
    base = {"kind": "authorization", "baseline_id": "owner", "mutant_id": "attacker",
            "field": "data.node.ownerId"}
    ok, why = validate_proof(store, candidate, base, ["owner", "attacker"])
    assert not ok and "control_id" in why
    # Anonymous gets the same object: it is public, not an authorization failure.
    ok, why = validate_proof(store, candidate, {**base, "control_id": "control"},
                             ["owner", "attacker", "control"])
    assert not ok and "public" in why
