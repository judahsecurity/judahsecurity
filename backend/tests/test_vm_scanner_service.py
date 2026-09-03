"""Tests for the VM scanner integration service (pure normalization helpers)."""

from app.models.asset import AssetType
from app.models.vulnerability import Severity
from app.services.vm_scanner_service import (
    _QUALYS_SEVERITY,
    _TENABLE_SEVERITY,
    DISCOVERY_SOURCES,
    PROVIDERS,
    infer_asset_type,
    map_severity,
    validate_config,
)


def test_providers_registry_is_complete():
    assert set(PROVIDERS) == {"tenable", "qualys", "rapid7", "nessus"}
    assert set(DISCOVERY_SOURCES) == set(PROVIDERS)
    for meta in PROVIDERS.values():
        assert meta["label"]
        assert meta["credential_fields"]


def test_map_severity_tenable_scale():
    assert map_severity(4, _TENABLE_SEVERITY) == Severity.CRITICAL
    assert map_severity("3", _TENABLE_SEVERITY) == Severity.HIGH
    assert map_severity(0, _TENABLE_SEVERITY) == Severity.INFO


def test_map_severity_qualys_scale():
    assert map_severity("5", _QUALYS_SEVERITY) == Severity.CRITICAL
    assert map_severity(1, _QUALYS_SEVERITY) == Severity.INFO


def test_map_severity_named_and_unknown():
    assert map_severity("Severe") == Severity.HIGH
    assert map_severity("critical") == Severity.CRITICAL
    assert map_severity(None) == Severity.MEDIUM
    assert map_severity("bogus") == Severity.MEDIUM
    assert map_severity(99) == Severity.MEDIUM


def test_infer_asset_type():
    assert infer_asset_type("10.0.0.5") == AssetType.IP_ADDRESS
    assert infer_asset_type("2001:db8::1") == AssetType.IP_ADDRESS
    assert infer_asset_type("example.com") == AssetType.DOMAIN
    assert infer_asset_type("www.example.com") == AssetType.SUBDOMAIN
    assert infer_asset_type("WIN-DC01") == AssetType.OTHER


def test_validate_config_unknown_provider():
    assert "Unknown provider" in validate_config("openvas", None, {})


def test_validate_config_requires_base_url_for_self_hosted():
    error = validate_config("nessus", "", {"access_key": "a", "secret_key": "b"})
    assert "base URL" in error
    assert validate_config("nessus", "https://scanner:8834", {"access_key": "a", "secret_key": "b"}) is None


def test_validate_config_cloud_default_base_url():
    assert validate_config("tenable", None, {"access_key": "a", "secret_key": "b"}) is None
    assert validate_config("rapid7", None, {"api_key": "k"}) is None


def test_validate_config_missing_credentials():
    error = validate_config("qualys", "https://qualysapi.qualys.com", {"username": "u"})
    assert "Password" in error
