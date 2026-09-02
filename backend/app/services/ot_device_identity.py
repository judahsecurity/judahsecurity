"""
OT / ICS device-identity parsing.

Nmap's OT NSE scripts (``enip-info``, ``s7-info``, ``modbus-discover``,
``bacnet-info``, ``snmp-sysdescr``/``snmp-info``, ``omron-info``, ``fox-info``)
return rich device identity — vendor, model, firmware/revision, serial and
device type — inside their ``<script>`` output. The port scanner historically
kept only the ``<service>`` attributes, so that identity was thrown away and
every OT finding stayed generic ("EtherNet/IP Protocol Exposed").

This module turns that script output into a normalized :class:`OTDeviceIdentity`
so the platform can show, for example, that a host is running a
**Rockwell Automation 1769-L36ERM (CompactLogix PLC)** rather than merely that
port 44818 is open.

The parser is intentionally pure (no DB, no I/O) so it can be unit-tested with
raw script text and reused by the scanner, device inference and findings layers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Vendor normalization
# ---------------------------------------------------------------------------
# Maps a case-insensitive keyword (as it appears in NSE output / SNMP sysDescr /
# banners) to a canonical display vendor name. Order matters only in that the
# first keyword found in a text wins for free-text detection.
_VENDOR_KEYWORDS: List[Tuple[str, str]] = [
    ("rockwell", "Rockwell Automation"),
    ("allen-bradley", "Rockwell Automation"),
    ("allen bradley", "Rockwell Automation"),
    ("siemens", "Siemens"),
    ("simatic", "Siemens"),
    ("schneider", "Schneider Electric"),
    ("modicon", "Schneider Electric"),
    ("telemecanique", "Schneider Electric"),
    ("mitsubishi", "Mitsubishi Electric"),
    ("melsec", "Mitsubishi Electric"),
    ("omron", "Omron"),
    ("general electric", "GE"),
    ("ge intelligent", "GE"),
    ("ge fanuc", "GE"),
    ("emerson", "Emerson"),
    ("yokogawa", "Yokogawa"),
    ("honeywell", "Honeywell"),
    ("abb", "ABB"),
    ("wago", "WAGO"),
    ("beckhoff", "Beckhoff"),
    ("phoenix contact", "Phoenix Contact"),
    ("moxa", "Moxa"),
    ("hirschmann", "Hirschmann"),
    ("red lion", "Red Lion"),
    ("tridium", "Tridium"),
    ("niagara", "Tridium"),
    ("codesys", "CODESYS"),
    ("delta electronics", "Delta"),
    ("bosch rexroth", "Bosch Rexroth"),
    ("festo", "Festo"),
    ("pilz", "Pilz"),
]

# Rockwell (and a few common) product-family hints keyed by a regex over the
# product/model string. Used only to add a friendly parenthetical, e.g.
# "1769-L36ERM" -> "CompactLogix PLC".
_PRODUCT_FAMILY_HINTS: List[Tuple[str, str]] = [
    (r"1769-L3\d", "CompactLogix PLC"),
    (r"5069-L\d", "CompactLogix 5380 PLC"),
    (r"176[89]-L\d", "CompactLogix PLC"),
    (r"1756-L\d", "ControlLogix PLC"),
    (r"1766-L\d", "MicroLogix PLC"),
    (r"1763-L\d", "MicroLogix PLC"),
    (r"micrologix", "MicroLogix PLC"),
    (r"compactlogix", "CompactLogix PLC"),
    (r"controllogix", "ControlLogix PLC"),
    (r"powerflex", "PowerFlex Drive"),
    (r"1794-", "FLEX I/O"),
    (r"s7-?1500", "SIMATIC S7-1500 PLC"),
    (r"s7-?1200", "SIMATIC S7-1200 PLC"),
    (r"s7-?300", "SIMATIC S7-300 PLC"),
    (r"s7-?400", "SIMATIC S7-400 PLC"),
    (r"cpu\s?31\d", "SIMATIC S7-300 PLC"),
    (r"bmx\s?p34", "Modicon M340 PLC"),
    (r"tm221|tm241", "Modicon M2xx PLC"),
]

# Protocol label per OT port (used for tagging / display).
_OT_PORT_PROTOCOL: Dict[int, str] = {
    102: "s7comm",
    502: "modbus",
    2222: "ethernet-ip",
    44818: "ethernet-ip",
    20000: "dnp3",
    2404: "iec-104",
    47808: "bacnet",
    1911: "niagara-fox",
    1962: "niagara-fox",
    789: "crimson",
    9600: "omron-fins",
    5007: "melsec",
    4840: "opc-ua",
    161: "snmp",
}


@dataclass
class OTDeviceIdentity:
    """Normalized identity for an industrial control-system device."""

    protocol: Optional[str] = None
    vendor: Optional[str] = None
    product: Optional[str] = None       # model / product name
    device_type: Optional[str] = None   # e.g. "Programmable Logic Controller"
    revision: Optional[str] = None      # firmware / hardware revision
    serial: Optional[str] = None
    product_code: Optional[str] = None
    family: Optional[str] = None        # e.g. "CompactLogix PLC"
    source: Optional[str] = None        # NSE script id that produced this
    confidence: int = 0                 # 0-100
    raw: Dict[str, str] = field(default_factory=dict)

    def is_useful(self) -> bool:
        """True when we learned at least a vendor or a product."""
        return bool(self.vendor or self.product)

    def display_name(self) -> str:
        """Human label, e.g. 'Rockwell Automation 1769-L36ERM (CompactLogix PLC)'."""
        parts = [p for p in (self.vendor, self.product) if p]
        name = " ".join(parts).strip()
        if not name:
            name = self.device_type or "Industrial device"
        if self.family and self.family.lower() not in name.lower():
            name = f"{name} ({self.family})"
        return name

    def to_service_fields(self) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """(service_product, service_version, service_extra_info) for PortService."""
        product = " ".join(p for p in (self.vendor, self.product) if p).strip() or None
        version = self.revision
        extra_bits = []
        if self.device_type:
            extra_bits.append(self.device_type)
        if self.serial:
            extra_bits.append(f"S/N {self.serial}")
        if self.product_code:
            extra_bits.append(f"code {self.product_code}")
        extra = "; ".join(extra_bits)[:500] or None
        return product, version, extra

    def tags(self) -> List[str]:
        out = ["ot-device", "ics"]
        if self.protocol:
            out.append(f"protocol:{self.protocol}")
        if self.vendor:
            out.append(f"vendor:{_slug(self.vendor)}")
        if self.product:
            out.append(f"model:{_slug(self.product)}")
        if self.device_type and "controller" in self.device_type.lower():
            out.append("plc")
        return out

    def to_dict(self) -> Dict[str, object]:
        return {
            "protocol": self.protocol,
            "vendor": self.vendor,
            "product": self.product,
            "device_type": self.device_type,
            "revision": self.revision,
            "serial": self.serial,
            "product_code": self.product_code,
            "family": self.family,
            "source": self.source,
            "confidence": self.confidence,
            "display_name": self.display_name(),
            "raw": self.raw,
        }


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def _normalize_vendor(text: str) -> Optional[str]:
    """Return a canonical vendor name if any known keyword appears in *text*."""
    if not text:
        return None
    low = text.lower()
    for keyword, canonical in _VENDOR_KEYWORDS:
        if keyword in low:
            return canonical
    return None


def _family_for(*texts: Optional[str]) -> Optional[str]:
    blob = " ".join(t for t in texts if t).lower()
    if not blob:
        return None
    for pattern, family in _PRODUCT_FAMILY_HINTS:
        if re.search(pattern, blob, re.IGNORECASE):
            return family
    return None


def _parse_kv(text: str) -> Dict[str, str]:
    """Parse an NSE script body of ``Key: Value`` lines into a dict.

    Tolerates the leading ``|``/``|_`` pipe decoration Nmap prints in normal
    output as well as the clean text found in XML ``output`` attributes.
    """
    result: Dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        line = re.sub(r"^\|_?\s*", "", line)  # strip leading pipe decoration
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if key and value and key not in result:
            result[key] = value
    return result


def _clean(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    # Drop a trailing "(<n>)" enumeration Nmap appends, e.g. "Vendor (1)".
    value = re.sub(r"\s*\(\d+\)\s*$", "", value).strip()
    return value or None


def _first(d: Dict[str, str], *keys: str) -> Optional[str]:
    for key in keys:
        for actual, value in d.items():
            if actual.lower() == key.lower():
                return value
    return None


def _parse_enip(text: str) -> OTDeviceIdentity:
    kv = _parse_kv(text)
    vendor_raw = _first(kv, "Vendor")
    product = _clean(_first(kv, "Product Name", "Product"))
    ident = OTDeviceIdentity(
        protocol="ethernet-ip",
        vendor=_normalize_vendor(vendor_raw or "") or _clean(vendor_raw),
        product=product,
        device_type=_clean(_first(kv, "Device Type")),
        revision=_clean(_first(kv, "Revision", "Product Revision")),
        serial=_clean(_first(kv, "Serial Number")),
        product_code=_clean(_first(kv, "Product Code")),
        source="enip-info",
        raw=kv,
    )
    ident.confidence = 95 if ident.is_useful() else 0
    return ident


def _parse_s7(text: str) -> OTDeviceIdentity:
    kv = _parse_kv(text)
    module = _clean(_first(kv, "Module", "Module Type", "Basic Hardware"))
    ident = OTDeviceIdentity(
        protocol="s7comm",
        vendor="Siemens",
        product=module,
        device_type=_clean(_first(kv, "Module Type")),
        revision=_clean(_first(kv, "Version", "Basic Firmware")),
        serial=_clean(_first(kv, "Serial Number")),
        source="s7-info",
        raw=kv,
    )
    ident.confidence = 95 if ident.is_useful() else 80
    return ident


def _parse_modbus(text: str) -> OTDeviceIdentity:
    kv = _parse_kv(text)
    # modbus-discover reports free-text "Device identification: <vendor> <model>".
    device_ident = _first(kv, "Device identification", "Device Identification")
    vendor = _normalize_vendor(device_ident or text)
    product = None
    if device_ident:
        product = device_ident
        if vendor:
            # Strip the leading vendor words from the model string when possible.
            product = re.sub(re.escape(vendor.split()[0]), "", device_ident, flags=re.IGNORECASE).strip()
            product = product.lstrip("/-, ").strip() or device_ident
    ident = OTDeviceIdentity(
        protocol="modbus",
        vendor=vendor,
        product=_clean(product),
        source="modbus-discover",
        raw=kv or {"raw": text.strip()[:500]},
    )
    ident.confidence = 90 if ident.is_useful() else 40
    return ident


def _parse_bacnet(text: str) -> OTDeviceIdentity:
    kv = _parse_kv(text)
    vendor_raw = _first(kv, "Vendor Name", "Vendor Id", "Vendor ID", "Vendor")
    ident = OTDeviceIdentity(
        protocol="bacnet",
        vendor=_normalize_vendor(vendor_raw or "") or _clean(vendor_raw),
        product=_clean(_first(kv, "Model Name", "Model", "Object Name", "Object-name")),
        revision=_clean(_first(kv, "Firmware", "Application Software", "Firmware Revision")),
        device_type="Building Automation Controller",
        source="bacnet-info",
        raw=kv,
    )
    ident.confidence = 90 if ident.is_useful() else 40
    return ident


def _parse_snmp_sysdescr(text: str) -> OTDeviceIdentity:
    # snmp-sysdescr output is essentially the free-text sysDescr, optionally
    # followed by a "System uptime" line.
    body = text
    kv = _parse_kv(text)
    sys_descr = _first(kv, "snmp-sysdescr") or body
    sys_descr = re.sub(r"(?is)system uptime.*$", "", sys_descr).strip()
    vendor = _normalize_vendor(sys_descr)
    ident = OTDeviceIdentity(
        protocol="snmp",
        vendor=vendor,
        product=_clean(sys_descr) if vendor else None,
        source="snmp-sysdescr",
        raw={"sysDescr": sys_descr[:500]},
    )
    ident.confidence = 85 if vendor else 0
    return ident


def _parse_generic(text: str, script_id: str, protocol: Optional[str]) -> OTDeviceIdentity:
    kv = _parse_kv(text)
    vendor_raw = _first(kv, "Vendor", "Vendor Name", "Manufacturer")
    vendor = _normalize_vendor(f"{vendor_raw or ''} {text}")
    ident = OTDeviceIdentity(
        protocol=protocol,
        vendor=vendor or _clean(vendor_raw),
        product=_clean(_first(kv, "Product", "Product Name", "Model", "Model Name", "Device")),
        revision=_clean(_first(kv, "Version", "Firmware", "Revision")),
        serial=_clean(_first(kv, "Serial Number")),
        source=script_id,
        raw=kv,
    )
    ident.confidence = 70 if ident.is_useful() else 0
    return ident


# Maps NSE script id -> dedicated parser.
_SCRIPT_PARSERS = {
    "enip-info": _parse_enip,
    "s7-info": _parse_s7,
    "modbus-discover": _parse_modbus,
    "bacnet-info": _parse_bacnet,
    "snmp-sysdescr": _parse_snmp_sysdescr,
}


def parse_script_identity(script_id: str, output: str, port: Optional[int] = None) -> Optional[OTDeviceIdentity]:
    """Parse a single NSE script's output into an :class:`OTDeviceIdentity`."""
    if not output:
        return None
    script_id = (script_id or "").strip().lower()
    protocol = _OT_PORT_PROTOCOL.get(port or 0)

    parser = _SCRIPT_PARSERS.get(script_id)
    if parser is not None:
        ident = parser(output)
    elif script_id in ("snmp-info", "snmp-brute"):
        ident = _parse_snmp_sysdescr(output)
    elif script_id.endswith("-info") or script_id.endswith("-discover") or script_id.endswith("-identify"):
        ident = _parse_generic(output, script_id, protocol)
    else:
        return None

    if ident is None or not ident.is_useful():
        return None

    if protocol and not ident.protocol:
        ident.protocol = protocol
    ident.family = ident.family or _family_for(ident.product, ident.device_type)
    return ident


def parse_ot_identity(
    port: int,
    scripts: Optional[Dict[str, str]] = None,
    service_product: Optional[str] = None,
    service_extra_info: Optional[str] = None,
    banner: Optional[str] = None,
) -> Optional[OTDeviceIdentity]:
    """Best OT identity for a scanned port.

    Considers every NSE script that ran on the port, then falls back to the
    ``-sV`` service/banner text for a vendor-only guess on a known OT port.
    Returns the highest-confidence useful identity, or ``None``.
    """
    candidates: List[OTDeviceIdentity] = []

    for script_id, output in (scripts or {}).items():
        ident = parse_script_identity(script_id, output, port=port)
        if ident is not None:
            candidates.append(ident)

    if not candidates:
        # Fall back to service/banner text on a recognised OT port.
        protocol = _OT_PORT_PROTOCOL.get(port)
        blob = " ".join(t for t in (service_product, service_extra_info, banner) if t)
        vendor = _normalize_vendor(blob)
        if protocol and vendor:
            ident = OTDeviceIdentity(
                protocol=protocol,
                vendor=vendor,
                product=_clean(service_product),
                source="service-detection",
                confidence=60,
                raw={"service": blob[:300]},
            )
            ident.family = _family_for(ident.product)
            candidates.append(ident)

    if not candidates:
        return None

    candidates.sort(key=lambda c: c.confidence, reverse=True)
    return candidates[0]
