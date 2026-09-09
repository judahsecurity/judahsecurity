"""Restart snapshots preserve task state without persisting credentials."""

import json
import stat

from app.services.agent import run_snapshot


def test_snapshot_is_atomic_redacted_and_restart_safe(tmp_path, monkeypatch):
    monkeypatch.setattr(run_snapshot, "_DIR", tmp_path / "sessions")
    state = {
        "engagement_brain": {
            "task_graph": {
                "nodes": {
                    "h1": {
                        "id": "h1",
                        "status": "running",
                        "lease_id": "lease-1",
                        "lease_deadline": 123.0,
                    }
                }
            },
            "credentials": [
                {"username": "owner", "secret": "owner-secret", "secret_type": "password"}
            ],
            "notes": [],
        },
        "capability_map": {
            "target": "https://app.test",
            "headers": {"Authorization": "Bearer live-token"},
        },
        "auth_session": {"cookies": {"sessionid": "live-cookie"}},
        "current_phase": "attack",
    }

    run_snapshot.save_run_snapshot(42, "assessment", state)
    restored = run_snapshot.load_run_snapshot(42, "assessment")
    path = run_snapshot._path(42, "assessment")
    raw = path.read_text()

    assert restored["schema_version"] == 2
    assert restored["engagement_brain"]["task_graph"]["nodes"]["h1"]["lease_id"] == "lease-1"
    assert restored["engagement_brain"]["credentials"] == []
    assert restored["reauthentication_required"] is True
    assert "auth_session" not in restored
    assert "owner-secret" not in raw
    assert "live-token" not in raw
    assert "live-cookie" not in raw
    assert json.loads(raw)["capability_map"]["headers"]["Authorization"] == "[redacted]"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert not list(path.parent.glob("*.tmp"))


def test_oversized_snapshot_retains_last_valid_checkpoint(tmp_path, monkeypatch):
    monkeypatch.setattr(run_snapshot, "_DIR", tmp_path / "sessions")
    good = {"engagement_brain": {"task_graph": {"nodes": {"h1": {"status": "ready"}}}}}
    run_snapshot.save_run_snapshot(42, "assessment", good)
    before = run_snapshot._path(42, "assessment").read_bytes()

    huge = {
        "engagement_brain": {"task_graph": {"nodes": {}}, "notes": ["x" * 2_100_000]}
    }
    run_snapshot.save_run_snapshot(42, "assessment", huge)

    assert run_snapshot._path(42, "assessment").read_bytes() == before


def test_legacy_snapshot_credentials_do_not_regain_authority(tmp_path, monkeypatch):
    monkeypatch.setattr(run_snapshot, "_DIR", tmp_path / "sessions")
    run_snapshot._DIR.mkdir()
    path = run_snapshot._path(42, "legacy")
    path.write_text(
        json.dumps(
            {
                "engagement_brain": {
                    "credentials": [
                        {"username": "owner", "secret": "old-secret"}
                    ]
                },
                "auth_session": {"cookies": {"sessionid": "old-cookie"}},
            }
        )
    )

    restored = run_snapshot.load_run_snapshot(42, "legacy")
    assert restored["engagement_brain"]["credentials"] == []
    assert "auth_session" not in restored
    assert restored["reauthentication_required"] is True
