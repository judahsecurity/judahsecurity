import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent.identities import identity_summary, load_identities


def test_loads_multi_tenant_identity_pool_without_leaking_secrets(tmp_path):
    path = tmp_path / "identities.json"
    path.write_text(json.dumps({"identities": [
        {"label": "owner", "username": "alice", "password": "secret-a",
         "role": "user", "tenant": "a"},
        {"label": "other", "headers": {"Authorization": "Bearer token-b"},
         "role": "user", "tenant": "b"},
    ]}))
    identities = load_identities(str(path))
    assert [item["label"] for item in identities] == ["owner", "other"]
    summary = identity_summary(identities)
    assert "secret-a" not in str(summary)
    assert "token-b" not in str(summary)


def test_legacy_login_becomes_default_identity():
    identities = load_identities(username="alice", password="secret")
    assert identities[0]["label"] == "default"
    assert identities[0]["password"] == "secret"


def test_duplicate_labels_are_rejected(tmp_path):
    path = tmp_path / "identities.json"
    path.write_text(json.dumps([
        {"label": "same", "username": "a"},
        {"label": "same", "username": "b"},
    ]))
    with pytest.raises(ValueError, match="unique"):
        load_identities(str(path))


def test_login_configuration_is_normalized_without_entering_summary(tmp_path):
    path = tmp_path / "identities.json"
    path.write_text(json.dumps([{
        "label": "member",
        "username": "alice",
        "password": "secret",
        "login": {
            "url": "https://example.test/login",
            "username_field": "email",
            "password_field": "passwd",
            "extra_fields": {"realm": "staff"},
            "success_marker": "Welcome",
        },
    }]))

    identity = load_identities(str(path))[0]
    summary = identity_summary([identity])[0]

    assert identity["login"]["username_field"] == "email"
    assert identity["login"]["extra_fields"] == {"realm": "staff"}
    assert summary["login_configured"] == "true"
    assert "secret" not in str(summary)
    assert "Welcome" not in str(summary)
