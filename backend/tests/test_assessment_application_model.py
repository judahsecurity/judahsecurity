import json

from app.services.agent.engagement_brain import (
    EngagementBrain,
    engagement_brain_from_dict,
)
from app.services.agent.runtime_mapper import ingest_operations, normalize_request
from app.services.agent.authorization_engine import generate_matrix, coverage_report


def test_runtime_protocols_and_graphql_operations_remain_distinct():
    brain = EngagementBrain()
    requests = [
        {"url": "https://app.test/orders?token=secret&id=1"},
        {
            "url": "https://app.test/graphql",
            "method": "POST",
            "body": [
                {
                    "query": "query Orders { orders { id } }",
                    "variables": {"owner": "private"},
                },
                {"query": "mutation Rename { rename { id } }"},
            ],
        },
        {"url": "wss://app.test/events?token=secret"},
        {
            "url": "https://app.test/p.Service/Read",
            "headers": {"Content-Type": "application/grpc-web+proto"},
        },
        {
            "url": "https://app.test/soap",
            "headers": {"Content-Type": "application/soap+xml"},
            "body": "<Envelope><Body><GetOrder><id>1</id></GetOrder></Body></Envelope>",
        },
    ]
    ingest_operations(brain, requests, identity="user_a")
    assert len(brain.application_operations) == 6
    assert {op["protocol"] for op in brain.application_operations} == {
        "rest",
        "graphql",
        "websocket",
        "grpc-web",
        "soap",
    }
    assert len(brain.hypotheses) == 6
    assert len(brain.task_graph["nodes"]) == 6
    serialized = json.dumps(brain.to_dict())
    assert "private" not in serialized and "=secret" not in serialized
    ingest_operations(brain, requests, identity="user_b")
    assert len(brain.application_operations) == 6
    assert all(
        op["identities"] == ["user_a", "user_b"] for op in brain.application_operations
    )
    restored = engagement_brain_from_dict(brain.to_dict())
    assert restored.application_operations == brain.application_operations


def test_matrix_coverage_denominator_keeps_untested_and_blocked_cells():
    brain = EngagementBrain()
    ingest_operations(brain, [{"url": "https://app.test/items?id=1"}])
    op = brain.application_operations[0]
    identities = [
        dict(name="user_b", tenant="b", authenticated=True),
        dict(name="anonymous"),
    ]
    expected = [dict(operation_id=op["id"], identity="user_b", expected="deny")]
    rows = generate_matrix(brain, [op], identities, expected)
    assert len(rows) == 4
    assert coverage_report(brain)["counts"] == {"untested": 1, "blocked": 3}
    generate_matrix(brain, [op], identities, expected)
    assert len(brain.authorization_matrix) == 4
    assert len({h.id for h in brain.hypotheses}) == len(brain.hypotheses)


def test_invalid_urls_and_xml_entities_are_not_executed():
    assert normalize_request({"url": "file:///etc/passwd"}) == []
    assert normalize_request({"url": "https://user:secret@app.test"}) == []
    assert normalize_request({"url": "https://app.test:bad"}) == []
    row = normalize_request(
        {
            "url": "https://app.test/soap",
            "headers": {"soapaction": "Read"},
            "body": '<!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]><Envelope>&x;</Envelope>',
        }
    )[0]
    assert row["protocol"] == "soap" and row["parameters"] == []
