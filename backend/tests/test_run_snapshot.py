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
            "coverage_cells": [
                {
                    "id": "cell-1",
                    "status": "leased",
                    "lease_id": "coverage-lease",
                    "lease_owner": "api_authz",
                    "lease_deadline": 9999999999.0,
                    "task_lease_id": "lease-1",
                }
            ],
            "candidates": [
                {"id": "candidate-1", "status": "pending"},
                {
                    "id": "candidate-without-receipt",
                    "status": "confirmed",
                    "revision": 1,
                    "nonce": "nonce-missing",
                    "verifier_run_id": "verify-missing",
                    "verified_at": "2026-09-23T00:00:00+00:00",
                },
            ],
            "proof_escalations": [
                {
                    "id": "proof-1",
                    "status": "verifying",
                    "candidate_id": "candidate-1",
                }
            ],
            "verification_receipts": {
                "iv:test": {"candidate_id": "confirmed-1", "run_id": "verify-1"}
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

    assert restored["schema_version"] == 3
    task = restored["engagement_brain"]["task_graph"]["nodes"]["h1"]
    assert task["status"] == "blocked"
    assert task["recovery_required"] is True
    assert task["lease_id"] == ""
    cell = restored["engagement_brain"]["coverage_cells"][0]
    assert cell["status"] == "inconclusive"
    assert cell["lease_id"] == ""
    assert restored["engagement_brain"]["proof_escalations"][0]["status"] == "pending"
    assert restored["engagement_brain"]["verification_receipts"]["iv:test"]["run_id"] == "verify-1"
    recovered_candidate = next(
        row
        for row in restored["engagement_brain"]["candidates"]
        if row["id"] == "candidate-without-receipt"
    )
    assert recovered_candidate["status"] == "pending"
    assert recovered_candidate["verifier_run_id"] == ""
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
