from app.services import roe_service


def accepted_roe(**overrides):
    return {
        "enabled": True,
        "document_hash": "accepted",
        "scope_in": ["example.com"],
        "scope_out": [],
        "allowed_scan_types": [],
        "restricted_scan_types": [],
        **overrides,
    }


def test_bulk_roe_check_loads_configuration_once(monkeypatch):
    calls = 0

    def load_once(_db, _organization_id):
        nonlocal calls
        calls += 1
        return accepted_roe()

    monkeypatch.setattr(roe_service, "load_roe", load_once)

    allowed, reason, rejected = roe_service.check_targets(
        object(), 1, ["example.com", "api.example.com"], scan_type="vulnerability"
    )

    assert allowed is True
    assert reason is None
    assert rejected == []
    assert calls == 1


def test_empty_target_scan_still_enforces_scan_type(monkeypatch):
    monkeypatch.setattr(
        roe_service,
        "load_roe",
        lambda _db, _organization_id: accepted_roe(
            restricted_scan_types=["themis_cspm"]
        ),
    )

    allowed, reason, rejected = roe_service.check_targets(
        object(), 1, [], scan_type="themis_cspm"
    )

    assert allowed is False
    assert "restricted" in reason
    assert rejected == []
