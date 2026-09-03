"""Unit tests for the firewall integration address-object parsers.

Covers the pure parsing logic of the firewall integrations (FortiGate,
Check Point, Cisco FMC, SonicWall, pfSense) — the mapping from vendor network
objects to ASM asset (value, type, kind) tuples — without any network or
database access.
"""

from app.models.asset import AssetType
from app.services import (
    checkpoint_service,
    cisco_fmc_service,
    fortigate_service,
    pfsense_service,
    sonicwall_service,
)


# ── FortiGate ────────────────────────────────────────────────────────────────


def test_fortigate_parse_subnet_space_form():
    assert fortigate_service._parse_subnet("10.0.0.0 255.255.255.0") == ("10.0.0.0", 24)


def test_fortigate_parse_subnet_cidr_form():
    assert fortigate_service._parse_subnet("192.168.1.0/24") == ("192.168.1.0", 24)


def test_fortigate_parse_subnet_host():
    assert fortigate_service._parse_subnet("10.0.0.5/32") == ("10.0.0.5", 32)


def test_fortigate_parse_subnet_invalid():
    assert fortigate_service._parse_subnet("not-a-subnet") is None


def test_fortigate_ipmask_host_is_ip_asset():
    entry = {"name": "h", "type": "ipmask", "subnet": "1.2.3.4 255.255.255.255"}
    assert fortigate_service.parse_address_object(entry) == ("1.2.3.4", AssetType.IP_ADDRESS, "ip")


def test_fortigate_ipmask_subnet_is_cidr_asset():
    entry = {"name": "n", "type": "ipmask", "subnet": "10.0.0.0 255.255.255.0"}
    assert fortigate_service.parse_address_object(entry) == ("10.0.0.0/24", AssetType.IP_RANGE, "cidr")


def test_fortigate_fqdn_subdomain():
    entry = {"name": "f", "type": "fqdn", "fqdn": "www.example.com"}
    assert fortigate_service.parse_address_object(entry) == ("www.example.com", AssetType.SUBDOMAIN, "fqdn")


def test_fortigate_fqdn_apex_domain():
    entry = {"name": "d", "type": "fqdn", "fqdn": "example.com"}
    assert fortigate_service.parse_address_object(entry) == ("example.com", AssetType.DOMAIN, "fqdn")


def test_fortigate_wildcard_fqdn_skipped():
    entry = {"name": "w", "type": "fqdn", "fqdn": "*.example.com"}
    assert fortigate_service.parse_address_object(entry) is None


def test_fortigate_iprange_seeds_first_ip():
    entry = {"name": "r", "type": "iprange", "start-ip": "10.0.0.1", "end-ip": "10.0.0.9"}
    assert fortigate_service.parse_address_object(entry) == ("10.0.0.1", AssetType.IP_ADDRESS, "range")


def test_fortigate_geography_skipped():
    assert fortigate_service.parse_address_object({"name": "g", "type": "geography", "country": "US"}) is None


def test_fortigate_type_omitted_defaults_to_subnet():
    entry = {"name": "x", "subnet": "8.8.8.8 255.255.255.255"}
    assert fortigate_service.parse_address_object(entry) == ("8.8.8.8", AssetType.IP_ADDRESS, "ip")


def test_fortigate_group_membership_index():
    groups = [{"name": "grp", "member": [{"name": "h"}, {"name": "n"}]}]
    assert fortigate_service._group_membership_index(groups) == {"h": ["grp"], "n": ["grp"]}


# ── Check Point ──────────────────────────────────────────────────────────────


def test_checkpoint_host():
    entry = {"name": "h", "ipv4-address": "1.2.3.4"}
    assert checkpoint_service.parse_host(entry) == ("1.2.3.4", AssetType.IP_ADDRESS, "ip")


def test_checkpoint_host_invalid_ip():
    assert checkpoint_service.parse_host({"name": "h", "ipv4-address": "nope"}) is None


def test_checkpoint_network_cidr():
    entry = {"name": "n", "subnet4": "10.0.0.0", "mask-length4": 24}
    assert checkpoint_service.parse_network(entry) == ("10.0.0.0/24", AssetType.IP_RANGE, "cidr")


def test_checkpoint_network_host_mask():
    entry = {"name": "n", "subnet4": "10.0.0.5", "mask-length4": 32}
    assert checkpoint_service.parse_network(entry) == ("10.0.0.5", AssetType.IP_ADDRESS, "ip")


def test_checkpoint_network_invalid_mask():
    entry = {"name": "n", "subnet4": "10.0.0.0", "mask-length4": "bad"}
    assert checkpoint_service.parse_network(entry) is None


def test_checkpoint_address_range_seeds_first_ip():
    entry = {"name": "r", "ipv4-address-first": "10.0.0.1", "ipv4-address-last": "10.0.0.9"}
    assert checkpoint_service.parse_address_range(entry) == ("10.0.0.1", AssetType.IP_ADDRESS, "range")


# ── Cisco FMC ────────────────────────────────────────────────────────────────


def test_cisco_fmc_host():
    assert cisco_fmc_service.parse_host({"name": "h", "value": "1.2.3.4"}) == ("1.2.3.4", AssetType.IP_ADDRESS, "ip")


def test_cisco_fmc_host_invalid():
    assert cisco_fmc_service.parse_host({"name": "h", "value": "nope"}) is None


def test_cisco_fmc_network_cidr():
    assert cisco_fmc_service.parse_network({"name": "n", "value": "10.0.0.0/24"}) == ("10.0.0.0/24", AssetType.IP_RANGE, "cidr")


def test_cisco_fmc_network_host_mask():
    assert cisco_fmc_service.parse_network({"name": "n", "value": "10.0.0.5/32"}) == ("10.0.0.5", AssetType.IP_ADDRESS, "ip")


def test_cisco_fmc_range_seeds_first_ip():
    assert cisco_fmc_service.parse_range({"name": "r", "value": "10.0.0.1-10.0.0.9"}) == ("10.0.0.1", AssetType.IP_ADDRESS, "range")


def test_cisco_fmc_fqdn_subdomain():
    assert cisco_fmc_service.parse_fqdn({"name": "f", "value": "www.example.com"}) == ("www.example.com", AssetType.SUBDOMAIN, "fqdn")


def test_cisco_fmc_fqdn_apex():
    assert cisco_fmc_service.parse_fqdn({"name": "f", "value": "example.com"}) == ("example.com", AssetType.DOMAIN, "fqdn")


# ── SonicWall ────────────────────────────────────────────────────────────────


def test_sonicwall_host():
    entry = {"ipv4": {"name": "h", "host": {"ip": "1.2.3.4"}}}
    assert sonicwall_service.parse_ipv4_object(entry) == ("1.2.3.4", AssetType.IP_ADDRESS, "ip")


def test_sonicwall_network():
    entry = {"ipv4": {"name": "n", "network": {"subnet": "10.0.0.0", "mask": "255.255.255.0"}}}
    assert sonicwall_service.parse_ipv4_object(entry) == ("10.0.0.0/24", AssetType.IP_RANGE, "cidr")


def test_sonicwall_range_seeds_first_ip():
    entry = {"ipv4": {"name": "r", "range": {"begin": "10.0.0.1", "end": "10.0.0.9"}}}
    assert sonicwall_service.parse_ipv4_object(entry) == ("10.0.0.1", AssetType.IP_ADDRESS, "range")


def test_sonicwall_empty_object():
    assert sonicwall_service.parse_ipv4_object({"ipv4": {"name": "x"}}) is None


def test_sonicwall_fqdn():
    entry = {"fqdn": {"name": "f", "domain": "api.example.com"}}
    assert sonicwall_service.parse_fqdn_object(entry) == ("api.example.com", AssetType.SUBDOMAIN, "fqdn")


# ── pfSense ──────────────────────────────────────────────────────────────────


def test_pfsense_entry_ip():
    assert pfsense_service.classify_alias_entry("1.2.3.4") == ("1.2.3.4", AssetType.IP_ADDRESS, "ip")


def test_pfsense_entry_cidr():
    assert pfsense_service.classify_alias_entry("10.0.0.0/24") == ("10.0.0.0/24", AssetType.IP_RANGE, "cidr")


def test_pfsense_entry_host_cidr():
    assert pfsense_service.classify_alias_entry("10.0.0.5/32") == ("10.0.0.5", AssetType.IP_ADDRESS, "ip")


def test_pfsense_entry_fqdn():
    assert pfsense_service.classify_alias_entry("www.example.com") == ("www.example.com", AssetType.SUBDOMAIN, "fqdn")


def test_pfsense_entry_apex_fqdn():
    assert pfsense_service.classify_alias_entry("example.com") == ("example.com", AssetType.DOMAIN, "fqdn")


def test_pfsense_entry_port_ignored():
    assert pfsense_service.classify_alias_entry("443") is None
    assert pfsense_service.classify_alias_entry("80:443") is None


def test_pfsense_alias_addresses_list():
    assert pfsense_service._alias_addresses({"address": ["1.1.1.1", "2.2.2.2"]}) == ["1.1.1.1", "2.2.2.2"]


def test_pfsense_alias_addresses_string():
    assert pfsense_service._alias_addresses({"address": "1.1.1.1 2.2.2.2"}) == ["1.1.1.1", "2.2.2.2"]
