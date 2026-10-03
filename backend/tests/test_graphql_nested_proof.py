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
    store = SimpleNamespace(records={"owner": owner, "attacker": attacker})
    proof = {"kind": "authorization", "baseline_id": "owner", "mutant_id": "attacker",
             "field": "data.node.ownerId"}
    candidate = SimpleNamespace(title="GraphQL authorization bypass", description="foreign node")
    assert validate_proof(store, candidate, proof, ["owner", "attacker"])[0]

    attacker["payload"]["request"]["body"] = query.replace('"1"', '"2"')
    assert not validate_proof(store, candidate, proof, ["owner", "attacker"])[0]
    attacker["payload"]["request"]["body"] = query
    attacker["payload"]["response"]["body"] = json.dumps({"data": {"node": None}})
    assert not validate_proof(store, candidate, proof, ["owner", "attacker"])[0]
