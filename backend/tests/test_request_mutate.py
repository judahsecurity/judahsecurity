"""Captured-request one-field mutate."""

from app.services.agent.request_mutate import apply_one_mutation, coerce_request_body, summarize_samples


def test_mutate_query_one_field():
    sample = {
        "method": "POST",
        "url": "https://app.example.com/api/v1/actions/execute?foo=1",
        "headers": {"content-type": "application/json"},
        "body": '{"datasource": "https://internal"}',
    }
    baseline, mutant = apply_one_mutation(
        sample,
        location="body_json",
        field="url",
        value="https://abc.oast.fun/ssrf",
    )
    assert baseline["url"] == sample["url"]
    assert '"url": "https://abc.oast.fun/ssrf"' in mutant["body"]
    assert "internal" in (baseline["body"] or "")
    assert mutant["url"] == baseline["url"]


def test_mutate_query_param():
    sample = {"method": "GET", "url": "https://app.example.com/proxy?dest=https://ok"}
    _, mutant = apply_one_mutation(
        sample, location="query", field="dest", value="https://x.interact.sh/"
    )
    assert "dest=https%3A%2F%2Fx.interact.sh%2F" in mutant["url"] or "x.interact.sh" in mutant["url"]
    assert "foo=" not in mutant["url"]


def test_summarize_indexes():
    rows = summarize_samples([
        {"method": "GET", "url": "https://app.example.com/api/users?id=1", "body": ""},
        {"method": "POST", "url": "https://app.example.com/api/v1/actions/execute",
         "body": '{"requestUrl":"https://x"}'},
    ])
    assert rows[0]["index"] == 0
    assert "id" in rows[0]["fields"]
    assert rows[1]["has_body"] is True


def test_coerce_json_alias_sets_content_type():
    raw, hdrs = coerce_request_body(
        {"json": {"settings": [{"key": "aegis-verify-key", "value": "x"}]}}
    )
    assert raw is not None
    assert "aegis-verify-key" in raw
    assert hdrs["Content-Type"] == "application/json"


def test_coerce_dict_body_does_not_clobber_existing_content_type():
    raw, hdrs = coerce_request_body(
        {"body": {"a": 1}, "headers": {"Content-Type": "application/merge-patch+json"}}
    )
    assert raw == '{"a":1}'
    assert hdrs["Content-Type"] == "application/merge-patch+json"
