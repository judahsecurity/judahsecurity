from types import SimpleNamespace

from app.models.scan_schedule import CONTINUOUS_SCAN_TYPES
from app.services.ics_screenshot_service import (
    _requested_scope,
    asset_has_ics_evidence,
    asset_or_services_have_ics_evidence,
    service_has_ics_evidence,
    service_is_web,
    service_url,
)
from app.services.port_scanner_service import PortScannerService


def _asset(**overrides):
    values = {
        "value": "192.0.2.10",
        "system_type": None,
        "device_class": None,
        "device_subclass": None,
        "tags": [],
        "metadata_": {},
        "description": None,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _service(**overrides):
    values = {
        "port": 8088,
        "service_name": "http",
        "service_product": None,
        "service_version": None,
        "service_extra_info": None,
        "banner": None,
        "tags": [],
        "metadata_": {},
        "is_ssl": False,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_ics_screenshot_profile_is_registered_and_conservative():
    profile = CONTINUOUS_SCAN_TYPES["ics_hmi_screenshot"]
    assert profile["default_config"]["ics_only"] is True
    assert profile["default_config"]["capture_category"] == "ICS/OT"
    assert profile["default_config"]["max_hosts"] == 100


def test_ics_evidence_requires_asset_or_service_marker():
    assert asset_has_ics_evidence(_asset(device_class="Industrial HMI")) is True
    assert asset_has_ics_evidence(_asset(device_class="Web server")) is False
    assert service_has_ics_evidence(_service(service_product="Inductive Automation Ignition")) is True
    assert service_has_ics_evidence(_service(service_product="nginx")) is False
    assert service_has_ics_evidence(_service(metadata_={"protocol": "http"})) is False
    assert asset_has_ics_evidence(_asset(tags=["analytics"])) is False

    host = _asset(port_services=[
        _service(port=502, service_name="modbus"),
        _service(port=80, service_name="http"),
    ])
    assert asset_or_services_have_ics_evidence(host) is True


def test_web_service_url_preserves_observed_port_and_tls():
    asset = _asset(value="2001:db8::10")
    service = _service(port=8443, is_ssl=True)
    assert service_is_web(service, {80, 443, 8088, 8443}) is True
    assert service_url(asset, service) == "https://[2001:db8::10]:8443"


def test_requested_scope_accepts_bare_ipv6_and_cidr():
    hosts, networks = _requested_scope(["2001:db8::10", "192.0.2.0/24"])
    assert hosts == {"2001:db8::10"}
    assert str(networks[0]) == "192.0.2.0/24"


def test_nmap_parser_preserves_ics_nse_evidence(tmp_path):
    xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.0.2.10" addrtype="ipv4" />
    <ports>
      <port protocol="tcp" portid="502">
        <state state="open" reason="syn-ack" />
        <service name="modbus" product="Example PLC" version="1.2" />
        <script id="modbus-discover" output="device identification: Example PLC" />
      </port>
    </ports>
  </host>
</nmaprun>
"""
    path = tmp_path / "nmap.xml"
    path.write_text(xml, encoding="utf-8")

    results = PortScannerService()._parse_nmap_xml(str(path))

    assert len(results) == 1
    assert results[0].service_name == "modbus"
    assert results[0].script_results == {
        "modbus-discover": "device identification: Example PLC"
    }
    assert results[0].to_port_service_dict(7)["metadata_"]["scanner_scripts"] == results[0].script_results
