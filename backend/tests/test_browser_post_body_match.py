"""Captured POST replay keeps current rotating tokens and rejects changed inputs."""

import json
from urllib.parse import parse_qs

import pytest

from app.services.agent.scoped_assessment.body_probe import (
    captured_volatile_post_fields, match_browser_post_body,
)


PAYLOAD = '<img src=x onerror=alert("__PROWL_NONCE__")>'


@pytest.mark.parametrize("mime,baseline,live,parameter,token", [
    ("application/json", b'{"message":"hello","csrf_token":"old-token"}',
     b'{"message":"hello","csrf_token":"new-token"}', "/message", "new-token"),
    ("application/x-www-form-urlencoded", b"message=hello&csrf_token=old-token",
     b"message=hello&csrf_token=new-token", "message", "new-token"),
])
def test_rotating_token_is_preserved_from_live_request(mime, baseline, live, parameter, token):
    planned = match_browser_post_body(
        baseline, live, mime=mime, parameter=parameter, payload=PAYLOAD,
    )
    assert planned is not None
    changed, mode, fields = planned
    assert mode == "volatile_fields" and fields == ["csrf_token"]
    if mime == "application/json":
        parsed = json.loads(changed)
        assert parsed["csrf_token"] == token
        assert parsed["message"] == "hello" + PAYLOAD
    else:
        parsed = parse_qs(changed.decode())
        assert parsed["csrf_token"] == [token]
        assert parsed["message"] == ["hello" + PAYLOAD]


def test_exact_request_keeps_existing_replay_path():
    body = b'{"message":"hello","page":2}'
    planned = match_browser_post_body(
        body, body, mime="application/json", parameter="/message", payload=PAYLOAD,
    )
    assert planned is not None
    assert planned[1:] == ("exact", [])
    assert json.loads(planned[0])["page"] == 2


@pytest.mark.parametrize("baseline,live,parameter", [
    (b'{"message":"hello","csrf_token":"old"}',
     b'{"message":"changed","csrf_token":"new"}', "/message"),
    (b'{"message":"hello","page":2,"csrf_token":"old"}',
     b'{"message":"hello","page":3,"csrf_token":"new"}', "/message"),
    (b'{"message":"hello","csrf_token":"old"}',
     b'{"message":"hello","csrf_token":"new","extra":1}', "/message"),
    (b'{"message":"hello","csrf_token":"old"}',
     b'{"message":"hello","csrf_token":"new","csrf_token":"duplicate"}', "/message"),
    (b'{"message":"hello","csrf_token":"old"}',
     b'{"message":"hello","csrf_token":123}', "/message"),
    (b'{"message":"hello","token":"old"}',
     b'{"message":"hello","token":"new"}', "/message"),
    (b'{"csrf_token":"old","message":"hello"}',
     b'{"csrf_token":"new","message":"hello"}', "/csrf_token"),
])
def test_json_match_rejects_other_changes(baseline, live, parameter):
    assert match_browser_post_body(
        baseline, live, mime="application/json", parameter=parameter, payload=PAYLOAD,
    ) is None


@pytest.mark.parametrize("baseline,live", [
    (b"message=hello&csrf_token=old", b"message=changed&csrf_token=new"),
    (b"message=hello&page=2&csrf_token=old", b"message=hello&page=3&csrf_token=new"),
    (b"message=hello&csrf_token=old", b"message=hello&csrf_token=new&extra=1"),
    (b"message=hello&csrf_token=old", b"message=hello&csrf_token=new&csrf_token=again"),
])
def test_form_match_rejects_other_changes(baseline, live):
    assert match_browser_post_body(
        baseline, live, mime="application/x-www-form-urlencoded",
        parameter="message", payload=PAYLOAD,
    ) is None


def test_more_than_three_rotating_fields_are_not_replayed():
    baseline = b'{"message":"hello","csrf":"a","nonce":"b","timestamp":"1","request_id":"c"}'
    live = b'{"message":"hello","csrf":"d","nonce":"e","timestamp":"2","request_id":"f"}'
    assert match_browser_post_body(
        baseline, live, mime="application/json", parameter="/message", payload=PAYLOAD,
    ) is None


@pytest.mark.parametrize("mime,body,expected", [
    ("application/x-www-form-urlencoded", b"template=botox&csrf_token=old", ["csrf_token"]),
    ("application/json", b'{"filter":{"template":"botox","request_id":"old"}}', ["request_id"]),
    ("application/json", b'{"template":"botox","page":2}', []),
])
def test_token_field_detection_selects_fresh_browser_replay(mime, body, expected):
    assert captured_volatile_post_fields(body, mime) == expected


@pytest.mark.parametrize("mime,baseline,live,parameter", [
    ("application/x-www-form-urlencoded", b"template=botox&csrf_token=old",
     b"template=botox&csrf_token=fresh", "template"),
    ("application/json", b'{"template":"botox","csrf_token":"old"}',
     b'{"template":"botox","csrf_token":"fresh"}', "/template"),
])
def test_sql_suffix_is_encoded_into_live_body(mime, baseline, live, parameter):
    baseline_match = match_browser_post_body(
        baseline, live, mime=mime, parameter=parameter, payload="",
        require_nonce=False,
    )
    assert baseline_match is not None and baseline_match[0] == live
    suffix = "' OR '12345'='12345'-- "
    matched = match_browser_post_body(
        baseline, live, mime=mime, parameter=parameter, payload=suffix,
        require_nonce=False,
    )
    assert matched is not None
    changed = matched[0]
    if mime == "application/json":
        document = json.loads(changed)
        assert document == {"template": "botox" + suffix, "csrf_token": "fresh"}
    else:
        assert parse_qs(changed.decode()) == {
            "template": ["botox" + suffix], "csrf_token": ["fresh"],
        }
        assert b"%27" in changed and b"%20" in changed
