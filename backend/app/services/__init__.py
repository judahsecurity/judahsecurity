"""Service exports, loaded lazily so standalone workers stay lightweight."""

from importlib import import_module

_LAZY_IMPORTS = {
    "DNSService": ("app.services.dns_service", "DNSService"),
    "SubdomainService": ("app.services.subdomain_service", "SubdomainService"),
    "WappalyzerService": ("app.services.wappalyzer_service", "WappalyzerService"),
    "WhatRunsService": ("app.services.whatruns_service", "WhatRunsService"),
    "get_whatruns_service": ("app.services.whatruns_service", "get_whatruns_service"),
    "DiscoveryService": ("app.services.discovery_service", "DiscoveryService"),
    "HTTPService": ("app.services.http_service", "HTTPService"),
    "NucleiService": ("app.services.nuclei_service", "NucleiService"),
    "NucleiFindingsService": ("app.services.nuclei_findings_service", "NucleiFindingsService"),
    "ProjectDiscoveryService": ("app.services.projectdiscovery_service", "ProjectDiscoveryService"),
    "PortScannerService": ("app.services.port_scanner_service", "PortScannerService"),
    "ScannerType": ("app.services.port_scanner_service", "ScannerType"),
    "PortResult": ("app.services.port_scanner_service", "PortResult"),
    "ScanResult": ("app.services.port_scanner_service", "ScanResult"),
    "PortFindingsService": ("app.services.port_findings_service", "PortFindingsService"),
    "PORT_FINDING_RULES": ("app.services.port_findings_service", "PORT_FINDING_RULES"),
    "DataNormalizerService": ("app.services.data_normalizer_service", "DataNormalizerService"),
    "normalize_tool_output": ("app.services.data_normalizer_service", "normalize_tool_output"),
    "get_supported_sources": ("app.services.data_normalizer_service", "get_supported_sources"),
    "get_source_info": ("app.services.data_normalizer_service", "get_source_info"),
}

__all__ = list(_LAZY_IMPORTS)


def __getattr__(name: str):
    target = _LAZY_IMPORTS.get(name)
    if target is None:
        raise AttributeError(name)
    module_name, attribute = target
    value = getattr(import_module(module_name), attribute)
    globals()[name] = value
    return value
