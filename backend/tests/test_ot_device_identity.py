"""Tests for OT/ICS device-identity parsing and its propagation into results.

Uses the real device from the operator's nmap trace: a Rockwell Automation
1769-L36ERM (CompactLogix) PLC fingerprinted over EtherNet/IP and SNMP.
"""

from types import SimpleNamespace

from app.services.ot_device_identity import parse_ot_identity, parse_script_identity


# enip-info output for the 1769-L36ERM (matches the CIP List Identity reply
# decoded in the operator's nmap --script-trace run).
ENIP_INFO = """
| enip-info:
|   Vendor: Rockwell Automation/Allen-Bradley (1)
|   Product Name: 1769-L36ERM/A LOGIX5336ERM
|   Serial Number: 0x00583aec
|   Device Type: Programmable Logic Controller (14)
|   Product Code: 158
|_  Revision: 28.11
"""

SNMP_SYSDESCR = "Rockwell Automation 1769-L36ERM"

S7_INFO = """
| s7-info:
|   Module: 6ES7 315-2EH14-0AB0
|   Basic Hardware: 6ES7 315-2EH14-0AB0
|   Version: 3.2.6
|   Module Type: CPU 315-2 PN/DP
|_  Serial Number: S C-X4U330922013
"""

MODBUS_DISCOVER = """
| modbus-discover:
|   sid 0x1:
|_    Device identification: Schneider Electric BMX P34 2020 v2.6
"""


def test_enip_identifies_rockwell_compactlogix():
    ident = parse_ot_identity(port=44818, scripts={"enip-info": ENIP_INFO})
    assert ident is not None
    assert ident.vendor == "Rockwell Automation"
    assert "1769-L36ERM" in ident.product
    assert ident.device_type == "Programmable Logic Controller"
    assert ident.revision == "28.11"
    assert ident.serial == "0x00583aec"
    assert ident.product_code == "158"
    assert ident.family == "CompactLogix PLC"
    assert ident.confidence >= 90
    # The whole point: an operator can see the actual device.
    name = ident.display_name()
    assert "Rockwell Automation" in name
    assert "1769-L36ERM" in name
    assert "CompactLogix" in name


def test_enip_service_fields_and_tags():
    ident = parse_ot_identity(port=44818, scripts={"enip-info": ENIP_INFO})
    product, version, extra = ident.to_service_fields()
    assert "Rockwell Automation" in product and "1769-L36ERM" in product
    assert version == "28.11"
    assert "Programmable Logic Controller" in extra
    tags = ident.tags()
    assert "ot-device" in tags
    assert "protocol:ethernet-ip" in tags
    assert "vendor:rockwell-automation" in tags
    assert any(t.startswith("model:1769-l36erm") for t in tags)
    assert "plc" in tags


def test_snmp_sysdescr_confirms_vendor():
    ident = parse_ot_identity(port=161, scripts={"snmp-sysdescr": SNMP_SYSDESCR})
    assert ident is not None
    assert ident.vendor == "Rockwell Automation"
    assert ident.protocol == "snmp"


def test_s7_identifies_siemens():
    ident = parse_script_identity("s7-info", S7_INFO, port=102)
    assert ident is not None
    assert ident.vendor == "Siemens"
    assert "6ES7" in ident.product
    assert ident.protocol == "s7comm"


def test_modbus_identifies_schneider():
    ident = parse_script_identity("modbus-discover", MODBUS_DISCOVER, port=502)
    assert ident is not None
    assert ident.vendor == "Schneider Electric"
    assert "BMX" in (ident.product or "")


def test_non_ot_script_returns_none():
    assert parse_script_identity("http-title", "Did not follow redirect", port=80) is None
    assert parse_ot_identity(port=80, scripts={"http-title": "Site title"}) is None


def test_service_fallback_on_ot_port():
    # No NSE scripts, but -sV product text names the vendor on a known OT port.
    ident = parse_ot_identity(
        port=44818,
        scripts={},
        service_product="Rockwell Automation EtherNet/IP",
    )
    assert ident is not None
    assert ident.vendor == "Rockwell Automation"
    assert ident.confidence == 60


def test_port_result_carries_identity_into_service_dict():
    from app.services.port_scanner_service import PortResult

    ident = parse_ot_identity(port=44818, scripts={"enip-info": ENIP_INFO})
    data = ident.to_dict()
    data["tags"] = ident.tags()
    pr = PortResult(host="h", ip="10.88.58.236", port=44818, protocol="tcp",
                    state="open", scanner="nmap", ot_identity=data)
    d = pr.to_port_service_dict(asset_id=1)
    assert "1769-L36ERM" in d["service_product"]
    assert d["service_version"] == "28.11"
    assert d["metadata_"]["ot_device"]["vendor"] == "Rockwell Automation"
    assert "ot-device" in d["tags"]


def test_device_inference_promotes_ot_identity():
    from app.models.port_service import PortState
    from app.services.device_inference_service import DeviceInferenceService

    ident = parse_ot_identity(port=44818, scripts={"enip-info": ENIP_INFO})
    ot_dict = ident.to_dict()
    port = SimpleNamespace(
        state=PortState.OPEN,
        port=44818,
        service_name="EtherNet/IP",
        banner=None,
        service_product=None,
        service_extra_info=None,
        metadata_={"ot_device": ot_dict},
    )
    asset = SimpleNamespace(port_services=[port])

    inference = DeviceInferenceService().infer_from_asset(asset)
    assert inference.device_class == "Industrial/SCADA"
    assert "Rockwell Automation" in (inference.system_type or "")
    assert "1769-L36ERM" in (inference.system_type or "")
    assert inference.confidence >= 90
