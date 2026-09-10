"""Geo-location and network-intelligence service for IP address lookups.

Supports multiple providers:
- ip-api.com (free, 45 requests/minute, no API key)
- ipinfo.io (country/ASN, detailed geo, network flags, and optional hosted domains)
- WhoisXML API (paid, requires API key)
"""

import ipaddress
import logging
import os
import socket
import asyncio
from typing import Optional, Dict, Any
from enum import Enum
import httpx

logger = logging.getLogger(__name__)


class GeoProvider(str, Enum):
    """Supported geolocation providers."""
    IP_API = "ip-api"  # Free, no key required
    IPINFO = "ipinfo"  # Free tier available, optional token
    WHOISXML = "whoisxml"  # Requires API key


class GeoLocationService:
    """Service for looking up geo-location data for IP addresses.
    
    Supports multiple providers with automatic fallback.
    """
    
    # Provider API URLs
    IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,lat,lon,isp,as,query"
    IPINFO_LOOKUP_URL = "https://api.ipinfo.io/lookup/{ip}"
    IPINFO_LITE_URL = "https://api.ipinfo.io/lite/{ip}"
    IPINFO_LEGACY_URL = "https://ipinfo.io/{ip}/json"
    IPINFO_DOMAINS_URL = "https://ipinfo.io/domains/{ip}"
    WHOISXML_URL = "https://ip-geolocation.whoisxmlapi.com/api/v1"
    
    def __init__(
        self,
        ipinfo_token: Optional[str] = None,
        whoisxml_api_key: Optional[str] = None,
        preferred_provider: Optional[GeoProvider] = None
    ):
        """Initialize the geolocation service.
        
        Args:
            ipinfo_token: Optional token for ipinfo.io
            whoisxml_api_key: Optional API key for WhoisXML API
            preferred_provider: Which provider to try first
        """
        self._cache: Dict[tuple[str, str], Dict[str, Any]] = {}
        self._hosted_domains_cache: Dict[str, Dict[str, Any]] = {}
        self.ipinfo_token = ipinfo_token or os.getenv("IPINFO_TOKEN")
        self.whoisxml_api_key = whoisxml_api_key or os.getenv("WHOISXML_API_KEY")
        configured_provider = os.getenv("GEOLOCATION_PROVIDER", "").strip().lower()
        try:
            env_provider = GeoProvider(configured_provider) if configured_provider else None
        except ValueError:
            logger.warning("Ignoring unsupported GEOLOCATION_PROVIDER=%s", configured_provider)
            env_provider = None
        # Prefer IPinfo automatically when a token is configured; otherwise retain
        # the existing no-key provider as the default.
        self.preferred_provider = (
            preferred_provider
            or env_provider
            or (GeoProvider.IPINFO if self.ipinfo_token else GeoProvider.IP_API)
        )
    
    def set_api_keys(
        self,
        ipinfo_token: Optional[str] = None,
        whoisxml_api_key: Optional[str] = None
    ):
        """Update API keys at runtime."""
        if ipinfo_token:
            self.ipinfo_token = ipinfo_token
        if whoisxml_api_key:
            self.whoisxml_api_key = whoisxml_api_key
    
    async def resolve_hostname(self, hostname: str) -> Optional[str]:
        """Resolve hostname to IP address."""
        try:
            # Run DNS resolution in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None, 
                lambda: socket.gethostbyname(hostname)
            )
            return result
        except socket.gaierror as e:
            logger.debug(f"Failed to resolve {hostname}: {e}")
            return None
        except Exception as e:
            logger.warning(f"Error resolving {hostname}: {e}")
            return None
    
    async def lookup_ip(
        self,
        ip_address: str,
        provider: Optional[GeoProvider] = None,
        include_hosted_domains: bool = False,
    ) -> Optional[Dict[str, Any]]:
        """Look up geo-location data for an IP address.
        
        Args:
            ip_address: The IP to look up
            provider: Specific provider to use, or None for preferred with fallback
        """
        normalized_ip = self._normalize_public_ip(ip_address)
        if not normalized_ip:
            return None

        cache_key = (normalized_ip, provider.value if provider else "auto")
        if cache_key in self._cache:
            result = dict(self._cache[cache_key])
            if include_hosted_domains:
                self._attach_hosted_domains(
                    result,
                    await self.lookup_hosted_domains(normalized_ip),
                )
            return result
        
        # Determine which providers to try
        providers_to_try = []
        if provider:
            providers_to_try = [provider]
        else:
            # Try preferred provider first, then fallback to others
            providers_to_try = [self.preferred_provider]
            for p in [GeoProvider.IP_API, GeoProvider.IPINFO, GeoProvider.WHOISXML]:
                if p != self.preferred_provider and p not in providers_to_try:
                    providers_to_try.append(p)
        
        # Try each provider until one succeeds
        for prov in providers_to_try:
            try:
                result = None
                if prov == GeoProvider.IP_API:
                    result = await self._lookup_ip_api(normalized_ip)
                elif prov == GeoProvider.IPINFO:
                    result = await self._lookup_ipinfo(normalized_ip)
                elif prov == GeoProvider.WHOISXML:
                    result = await self._lookup_whoisxml(normalized_ip)
                
                if result:
                    result["provider"] = prov.value
                    self._cache[cache_key] = dict(result)
                    if include_hosted_domains:
                        self._attach_hosted_domains(
                            result,
                            await self.lookup_hosted_domains(normalized_ip),
                        )
                    return result
                    
            except Exception as e:
                logger.debug(f"Provider {prov.value} failed for {ip_address}: {e}")
                continue
        
        return None
    
    async def _lookup_ip_api(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Look up using ip-api.com (free, no key required)."""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(self.IP_API_URL.format(ip=ip_address))
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if data.get("status") == "success":
                        return {
                            "ip_address": data.get("query", ip_address),
                            "latitude": str(data.get("lat", "")),
                            "longitude": str(data.get("lon", "")),
                            "city": data.get("city", ""),
                            "country": data.get("country", ""),
                            "country_code": data.get("countryCode", ""),
                            "isp": data.get("isp", ""),
                            "asn": data.get("as", ""),
                        }
        except Exception as e:
            logger.debug(f"ip-api.com lookup failed for {ip_address}: {e}")
        return None
    
    async def _lookup_ipinfo(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Look up an IP using IPinfo's current API (or legacy no-token API)."""
        try:
            headers = {}
            if self.ipinfo_token:
                headers["Authorization"] = f"Bearer {self.ipinfo_token}"

            url = (
                self.IPINFO_LOOKUP_URL.format(ip=ip_address)
                if self.ipinfo_token
                else self.IPINFO_LEGACY_URL.format(ip=ip_address)
            )
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(url, headers=headers)
                if self.ipinfo_token and response.status_code in (401, 403):
                    # Lite tokens do not have access to /lookup, but can still
                    # contribute country and ASN intelligence.
                    response = await client.get(
                        self.IPINFO_LITE_URL.format(ip=ip_address),
                        headers=headers,
                    )

                if response.status_code == 200:
                    data = response.json()
                    return self._normalize_ipinfo_response(ip_address, data)
                if response.status_code == 429:
                    logger.warning("IPinfo rate limit reached")
        except Exception as e:
            logger.debug(f"ipinfo.io lookup failed for {ip_address}: {e}")
        return None

    @staticmethod
    def _normalize_ipinfo_response(ip_address: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize current nested and legacy flat IPinfo responses."""
        if isinstance(data.get("geo"), dict) or isinstance(data.get("as"), dict):
            geo = data.get("geo") or {}
            as_info = data.get("as") or {}
            return {
                "ip_address": data.get("ip", ip_address),
                "latitude": str(geo.get("latitude", "")),
                "longitude": str(geo.get("longitude", "")),
                "city": geo.get("city", ""),
                "country": geo.get("country", ""),
                "country_code": geo.get("country_code", ""),
                "geo_region": geo.get("region", ""),
                "region_code": geo.get("region_code", ""),
                "timezone": geo.get("timezone", ""),
                "postal": geo.get("postal_code", ""),
                "accuracy_radius": geo.get("radius"),
                "isp": as_info.get("name", ""),
                "asn": as_info.get("asn", ""),
                "as_name": as_info.get("name", ""),
                "as_domain": as_info.get("domain", ""),
                "as_type": as_info.get("type", ""),
                "is_anonymous": bool(data.get("is_anonymous", False)),
                "is_anycast": bool(data.get("is_anycast", False)),
                "is_hosting": bool(data.get("is_hosting", False)),
                "is_mobile": bool(data.get("is_mobile", False)),
                "is_satellite": bool(data.get("is_satellite", False)),
            }

        if data.get("asn") or data.get("as_name"):
            return {
                "ip_address": data.get("ip", ip_address),
                "country": data.get("country", ""),
                "country_code": data.get("country_code", ""),
                "continent": data.get("continent", ""),
                "continent_code": data.get("continent_code", ""),
                "isp": data.get("as_name", ""),
                "asn": data.get("asn", ""),
                "as_name": data.get("as_name", ""),
                "as_domain": data.get("as_domain", ""),
            }

        lat, lon = "", ""
        if data.get("loc"):
            parts = str(data["loc"]).split(",", 1)
            if len(parts) == 2:
                lat, lon = parts
        org = str(data.get("org", ""))
        return {
            "ip_address": data.get("ip", ip_address),
            "latitude": lat,
            "longitude": lon,
            "city": data.get("city", ""),
            "country": data.get("country_name", data.get("country", "")),
            "country_code": data.get("country", ""),
            "geo_region": data.get("region", ""),
            "timezone": data.get("timezone", ""),
            "postal": data.get("postal", ""),
            "isp": org.partition(" ")[2] or org,
            "asn": org.split(" ")[0] if org else "",
        }

    async def lookup_hosted_domains(
        self,
        ip_address: str,
        limit: int = 50,
    ) -> Optional[Dict[str, Any]]:
        """Return domains observed on an IP when the IPinfo plan permits it.

        These are co-hosted domain candidates, not proof of organizational
        ownership. IPinfo exposes this dataset only on eligible paid plans.
        """
        normalized_ip = self._normalize_public_ip(ip_address)
        if not normalized_ip or not self.ipinfo_token:
            return None
        if normalized_ip in self._hosted_domains_cache:
            return dict(self._hosted_domains_cache[normalized_ip])

        try:
            headers = {"Authorization": f"Bearer {self.ipinfo_token}"}
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    self.IPINFO_DOMAINS_URL.format(ip=normalized_ip),
                    headers=headers,
                )
            if response.status_code != 200:
                return None
            data = response.json()
            domains = [
                domain.strip().lower()
                for domain in data.get("domains", [])
                if isinstance(domain, str) and domain.strip()
            ]
            result = {
                "domains": domains[: max(0, min(limit, 500))],
                "total": int(data.get("total", len(domains)) or 0),
                "attribution": "co-hosted_only",
            }
            self._hosted_domains_cache[normalized_ip] = dict(result)
            return result
        except Exception as e:
            logger.debug("IPinfo hosted-domain lookup failed for %s: %s", normalized_ip, e)
            return None

    @staticmethod
    def _attach_hosted_domains(
        result: Dict[str, Any],
        hosted_domains: Optional[Dict[str, Any]],
    ) -> None:
        if hosted_domains:
            result["hosted_domains"] = hosted_domains.get("domains", [])
            result["hosted_domain_count"] = hosted_domains.get("total", 0)
            result["hosted_domains_attribution"] = hosted_domains.get("attribution")
    
    async def _lookup_whoisxml(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Look up using WhoisXML API."""
        if not self.whoisxml_api_key:
            logger.debug("WhoisXML API key not configured")
            return None
        
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    self.WHOISXML_URL,
                    params={
                        "apiKey": self.whoisxml_api_key,
                        "ipAddress": ip_address
                    }
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    location = data.get("location", {})
                    as_info = data.get("as", {})
                    
                    return {
                        "ip_address": data.get("ip", ip_address),
                        "latitude": str(location.get("lat", "")),
                        "longitude": str(location.get("lng", "")),
                        "city": location.get("city", ""),
                        "country": location.get("country", ""),
                        "country_code": location.get("country", ""),
                        "region": location.get("region", ""),
                        "isp": data.get("isp", ""),
                        "asn": f"AS{as_info.get('asn', '')}" if as_info.get("asn") else "",
                        "as_name": as_info.get("name", ""),
                        "as_domain": as_info.get("domain", ""),
                        "timezone": location.get("timezone", ""),
                        "postal": location.get("postalCode", ""),
                        "connection_type": data.get("connectionType", ""),
                    }
        except Exception as e:
            logger.debug(f"WhoisXML API lookup failed for {ip_address}: {e}")
        return None
    
    async def lookup_hostname(
        self,
        hostname: str,
        provider: Optional[GeoProvider] = None,
        include_hosted_domains: bool = False,
    ) -> Optional[Dict[str, Any]]:
        """Resolve hostname and look up geo-location."""
        # First resolve the hostname to an IP
        ip_address = await self.resolve_hostname(hostname)
        
        if not ip_address:
            return None
        
        # Then look up the IP
        result = await self.lookup_ip(
            ip_address,
            provider,
            include_hosted_domains=include_hosted_domains,
        )
        
        if result:
            result["ip_address"] = ip_address
            
        return result
    
    @staticmethod
    def _normalize_public_ip(value: str) -> Optional[str]:
        """Return a canonical public IPv4/IPv6 address, or None."""
        try:
            parsed = ipaddress.ip_address(value.strip())
            return str(parsed) if parsed.is_global else None
        except (AttributeError, ValueError):
            return None
    
    async def batch_lookup(
        self,
        hostnames: list[str],
        max_concurrent: int = 10,
        provider: Optional[GeoProvider] = None,
        include_hosted_domains: bool = False,
    ) -> Dict[str, Dict[str, Any]]:
        """Look up geo-location for multiple hostnames concurrently."""
        results = {}
        
        # Create semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def lookup_with_limit(hostname: str):
            async with semaphore:
                # Add small delay to respect rate limits
                await asyncio.sleep(0.1)
                result = await self.lookup_hostname(
                    hostname,
                    provider,
                    include_hosted_domains=include_hosted_domains,
                )
                if result:
                    results[hostname] = result
        
        # Run lookups concurrently
        tasks = [lookup_with_limit(h) for h in hostnames]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        return results
    
    def clear_cache(self):
        """Clear the lookup cache."""
        self._cache.clear()
    
    def get_cache_stats(self) -> Dict[str, int]:
        """Get cache statistics."""
        return {
            "cached_ips": len(self._cache),
        }


# Singleton instance
_geo_service: Optional[GeoLocationService] = None


def get_geolocation_service() -> GeoLocationService:
    """Get or create the geo-location service singleton."""
    global _geo_service
    if _geo_service is None:
        _geo_service = GeoLocationService()
    return _geo_service


def configure_geolocation_service(
    ipinfo_token: Optional[str] = None,
    whoisxml_api_key: Optional[str] = None,
    preferred_provider: Optional[GeoProvider] = None,
) -> GeoLocationService:
    """Configure and return the geolocation service."""
    global _geo_service
    _geo_service = GeoLocationService(
        ipinfo_token=ipinfo_token,
        whoisxml_api_key=whoisxml_api_key,
        preferred_provider=preferred_provider
    )
    return _geo_service


# =============================================================================
# Region Mapping
# =============================================================================

# Standard geographic regions
REGIONS = {
    "NORTH_AMERICA": "North America",
    "SOUTH_AMERICA": "South America",
    "EUROPE": "Europe",
    "EMEA": "EMEA",  # Europe, Middle East, Africa
    "APAC": "APAC",  # Asia-Pacific
    "ASIA": "Asia",
    "AFRICA": "Africa",
    "OCEANIA": "Oceania",
    "MIDDLE_EAST": "Middle East",
}

# Country code to region mapping (ISO 3166-1 alpha-2)
COUNTRY_TO_REGION: Dict[str, str] = {
    # North America
    "US": "North America", "CA": "North America", "MX": "North America",
    "GT": "North America", "BZ": "North America", "HN": "North America",
    "SV": "North America", "NI": "North America", "CR": "North America",
    "PA": "North America", "JM": "North America", "HT": "North America",
    "DO": "North America", "CU": "North America", "BS": "North America",
    "TT": "North America", "BB": "North America", "PR": "North America",
    
    # South America
    "BR": "South America", "AR": "South America", "CO": "South America",
    "PE": "South America", "VE": "South America", "CL": "South America",
    "EC": "South America", "BO": "South America", "PY": "South America",
    "UY": "South America", "GY": "South America", "SR": "South America",
    "GF": "South America",
    
    # Europe
    "GB": "Europe", "DE": "Europe", "FR": "Europe", "IT": "Europe",
    "ES": "Europe", "PT": "Europe", "NL": "Europe", "BE": "Europe",
    "AT": "Europe", "CH": "Europe", "PL": "Europe", "CZ": "Europe",
    "SK": "Europe", "HU": "Europe", "RO": "Europe", "BG": "Europe",
    "GR": "Europe", "SE": "Europe", "NO": "Europe", "DK": "Europe",
    "FI": "Europe", "IE": "Europe", "LU": "Europe", "EE": "Europe",
    "LV": "Europe", "LT": "Europe", "SI": "Europe", "HR": "Europe",
    "RS": "Europe", "BA": "Europe", "MK": "Europe", "AL": "Europe",
    "ME": "Europe", "XK": "Europe", "UA": "Europe", "BY": "Europe",
    "MD": "Europe", "MT": "Europe", "CY": "Europe", "IS": "Europe",
    
    # Middle East
    "SA": "Middle East", "AE": "Middle East", "QA": "Middle East",
    "KW": "Middle East", "BH": "Middle East", "OM": "Middle East",
    "YE": "Middle East", "IQ": "Middle East", "IR": "Middle East",
    "SY": "Middle East", "JO": "Middle East", "LB": "Middle East",
    "IL": "Middle East", "PS": "Middle East", "TR": "Middle East",
    
    # Africa
    "ZA": "Africa", "EG": "Africa", "NG": "Africa", "KE": "Africa",
    "MA": "Africa", "DZ": "Africa", "TN": "Africa", "GH": "Africa",
    "ET": "Africa", "TZ": "Africa", "UG": "Africa", "RW": "Africa",
    "SN": "Africa", "CI": "Africa", "CM": "Africa", "AO": "Africa",
    "MZ": "Africa", "ZW": "Africa", "ZM": "Africa", "BW": "Africa",
    "NA": "Africa", "MU": "Africa", "LY": "Africa", "SD": "Africa",
    
    # Asia (excluding Middle East)
    "CN": "Asia", "JP": "Asia", "KR": "Asia", "IN": "Asia",
    "PK": "Asia", "BD": "Asia", "TH": "Asia", "VN": "Asia",
    "MY": "Asia", "SG": "Asia", "ID": "Asia", "PH": "Asia",
    "TW": "Asia", "HK": "Asia", "MO": "Asia", "MM": "Asia",
    "KH": "Asia", "LA": "Asia", "NP": "Asia", "LK": "Asia",
    "MN": "Asia", "KZ": "Asia", "UZ": "Asia", "KG": "Asia",
    "TJ": "Asia", "TM": "Asia", "AF": "Asia", "BT": "Asia",
    "MV": "Asia", "BN": "Asia",
    
    # Oceania
    "AU": "Oceania", "NZ": "Oceania", "FJ": "Oceania", "PG": "Oceania",
    "NC": "Oceania", "VU": "Oceania", "WS": "Oceania", "TO": "Oceania",
    "GU": "Oceania", "PF": "Oceania",
    
    # Russia (spans Europe/Asia - commonly grouped with Europe for business)
    "RU": "Europe",
}


def get_region_from_country(country_code: Optional[str]) -> Optional[str]:
    """
    Get the geographic region for a country code.
    
    Args:
        country_code: ISO 3166-1 alpha-2 country code (e.g., "US", "GB", "JP")
    
    Returns:
        Region name or None if country not found
    """
    if not country_code:
        return None
    return COUNTRY_TO_REGION.get(country_code.upper())


def get_emea_region(country_code: Optional[str]) -> Optional[str]:
    """
    Get EMEA grouping (common in enterprise).
    Returns "EMEA" for Europe, Middle East, and Africa.
    Returns "Americas" for North/South America.
    Returns "APAC" for Asia-Pacific.
    """
    if not country_code:
        return None
    
    region = get_region_from_country(country_code)
    if not region:
        return None
    
    if region in ["Europe", "Middle East", "Africa"]:
        return "EMEA"
    elif region in ["North America", "South America"]:
        return "Americas"
    elif region in ["Asia", "Oceania"]:
        return "APAC"
    
    return region


def get_all_regions() -> list[str]:
    """Get list of all available regions."""
    return sorted(list(set(COUNTRY_TO_REGION.values())))
