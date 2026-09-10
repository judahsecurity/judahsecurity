import pytest

from app.models.scan import ScanType
from app.models.scan_schedule import CONTINUOUS_SCAN_TYPES
from app.models.scan_profile import ScanProfile
from app.services.scan_profiles import profile_config
from app.services.scan_registry import job_type_for_scan_type, resolve_scan_type
from app.api.routes.scans import get_available_scan_types


def test_every_adhoc_catalog_type_has_an_explicit_resolution():
    for scan_type_id in CONTINUOUS_SCAN_TYPES:
        if scan_type_id == "tester_process":
            continue
        resolved = resolve_scan_type(scan_type_id)
        assert job_type_for_scan_type(resolved)


def test_full_scan_uses_the_same_recon_pipeline_for_every_queue_backend():
    assert resolve_scan_type("full") is ScanType.FULL
    assert job_type_for_scan_type(ScanType.FULL) == "RECON_PIPELINE"


def test_unknown_and_unimplemented_types_fail_closed():
    with pytest.raises(ValueError):
        resolve_scan_type("not-a-real-scan")
    with pytest.raises(ValueError):
        job_type_for_scan_type(ScanType.CERTIFICATE)
    with pytest.raises(ValueError):
        job_type_for_scan_type(ScanType.PENTEST)


def test_tester_process_remains_schedule_only():
    with pytest.raises(ValueError, match="only run through a schedule"):
        resolve_scan_type("tester_process")


def test_manual_launcher_catalog_only_exposes_launchable_scan_types():
    catalog = get_available_scan_types()

    assert "tester_process" not in catalog
    assert "cleanup" not in catalog
    assert catalog["nuclei"]["launch_endpoint"] == "adhoc"
    assert catalog["llm_red_team"]["launch_endpoint"] == "direct"
    assert catalog["llm_red_team"]["requires_targets"] is True
    assert catalog["themis_cspm"]["requires_targets"] is False


def test_profile_settings_translate_to_worker_config():
    profile = ScanProfile(
        id=7,
        name="Targeted",
        nuclei_severity=["critical"],
        nuclei_tags=["cve"],
        nuclei_rate_limit=25,
        nuclei_bulk_size=4,
        nuclei_concurrency=3,
        nuclei_timeout=8,
        port_scan_custom=[22, 443],
    )

    config = profile_config(profile)

    assert config["profile_id"] == 7
    assert config["severity"] == ["critical"]
    assert config["rate_limit"] == 25
    assert config["bulk_size"] == 4
    assert config["concurrency"] == 3
    assert config["timeout"] == 8
    assert config["ports"] == "22,443"
