from unittest.mock import patch

import pytest

from fastapi import HTTPException

from app.services.geolocation_service import (
    GeoLocationService,
    GeoProvider,
    get_geolocation_service_for_org,
)
from app.api.routes.assets import _apply_ip_enrichment, _org_geo_service
from app.models.asset import Asset, AssetType


class _Response:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload


class _Client:
    responses = []
    requests = []

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url, **kwargs):
        self.__class__.requests.append((url, kwargs))
        return self.__class__.responses.pop(0)


@pytest.fixture(autouse=True)
def _reset_client(monkeypatch):
    _Client.responses = []
    _Client.requests = []
    monkeypatch.delenv("GEOLOCATION_PROVIDER", raising=False)
    monkeypatch.delenv("IPINFO_TOKEN", raising=False)


@pytest.mark.asyncio
async def test_ipinfo_current_api_is_normalized():
    _Client.responses = [
        _Response(
            {
                "ip": "99.153.3.178",
                "geo": {
                    "city": "Chicago",
                    "region": "Illinois",
                    "region_code": "IL",
                    "country": "United States",
                    "country_code": "US",
                    "latitude": 41.88,
                    "longitude": -87.63,
                    "timezone": "America/Chicago",
                    "postal_code": "60601",
                    "radius": 25,
                },
                "as": {
                    "asn": "AS7018",
                    "name": "AT&T Enterprises, LLC",
                    "domain": "att.com",
                    "type": "isp",
                },
                "is_anonymous": False,
                "is_anycast": False,
                "is_hosting": False,
                "is_mobile": False,
                "is_satellite": False,
            }
        )
    ]

    with patch("app.services.geolocation_service.httpx.AsyncClient", _Client):
        result = await GeoLocationService(ipinfo_token="secret").lookup_ip(
            "99.153.3.178",
            GeoProvider.IPINFO,
        )

    assert result["country_code"] == "US"
    assert result["asn"] == "AS7018"
    assert result["as_name"] == "AT&T Enterprises, LLC"
    assert result["accuracy_radius"] == 25
    assert result["provider"] == "ipinfo"
    assert _Client.requests == [
        (
            "https://api.ipinfo.io/lookup/99.153.3.178",
            {"headers": {"Authorization": "Bearer secret"}},
        )
    ]


@pytest.mark.asyncio
async def test_hosted_domains_are_optional_and_marked_cohosted():
    _Client.responses = [
        _Response(
            {
                "ip": "99.153.3.178",
                "geo": {"country": "United States", "country_code": "US"},
                "as": {"asn": "AS7018", "name": "AT&T Enterprises, LLC"},
            }
        ),
        _Response(
            {
                "ip": "99.153.3.178",
                "total": 2,
                "domains": ["Example.COM", "shared-host.example"],
            }
        ),
    ]

    with patch("app.services.geolocation_service.httpx.AsyncClient", _Client):
        result = await GeoLocationService(ipinfo_token="secret").lookup_ip(
            "99.153.3.178",
            GeoProvider.IPINFO,
            include_hosted_domains=True,
        )

    assert result["hosted_domains"] == ["example.com", "shared-host.example"]
    assert result["hosted_domain_count"] == 2
    assert result["hosted_domains_attribution"] == "co-hosted_only"
    assert _Client.requests[1][0] == "https://ipinfo.io/domains/99.153.3.178"


@pytest.mark.asyncio
async def test_no_token_uses_valid_legacy_url():
    _Client.responses = [
        _Response(
            {
                "ip": "8.8.8.8",
                "city": "Mountain View",
                "region": "California",
                "country": "US",
                "loc": "37.4056,-122.0775",
                "org": "AS15169 Google LLC",
            }
        )
    ]

    with patch("app.services.geolocation_service.httpx.AsyncClient", _Client):
        result = await GeoLocationService().lookup_ip("8.8.8.8", GeoProvider.IPINFO)

    assert result["asn"] == "AS15169"
    assert result["isp"] == "Google LLC"
    assert _Client.requests[0][0] == "https://ipinfo.io/8.8.8.8/json"


@pytest.mark.asyncio
async def test_lite_token_falls_back_to_country_and_asn_endpoint():
    _Client.responses = [
        _Response({"error": "plan does not include lookup"}, status_code=403),
        _Response(
            {
                "ip": "8.8.8.8",
                "asn": "AS15169",
                "as_name": "Google LLC",
                "as_domain": "google.com",
                "country_code": "US",
                "country": "United States",
                "continent_code": "NA",
                "continent": "North America",
            }
        ),
    ]

    with patch("app.services.geolocation_service.httpx.AsyncClient", _Client):
        result = await GeoLocationService(ipinfo_token="lite-secret").lookup_ip(
            "8.8.8.8",
            GeoProvider.IPINFO,
        )

    assert result["country"] == "United States"
    assert result["asn"] == "AS15169"
    assert result["as_domain"] == "google.com"
    assert _Client.requests[1][0] == "https://api.ipinfo.io/lite/8.8.8.8"


@pytest.mark.asyncio
async def test_non_public_addresses_are_not_sent_to_providers():
    service = GeoLocationService(ipinfo_token="secret")

    with patch("app.services.geolocation_service.httpx.AsyncClient", _Client):
        assert await service.lookup_ip("127.0.0.1", GeoProvider.IPINFO) is None
        assert await service.lookup_ip("10.0.0.1", GeoProvider.IPINFO) is None
        assert await service.lookup_ip("not-an-ip", GeoProvider.IPINFO) is None

    assert _Client.requests == []


def test_token_makes_ipinfo_the_default_provider():
    assert GeoLocationService(ipinfo_token="secret").preferred_provider == GeoProvider.IPINFO
    assert GeoLocationService().preferred_provider == GeoProvider.IP_API


def test_asset_persistence_keeps_rich_intelligence_and_attribution_warning():
    asset = Asset(
        name="99.153.3.178",
        value="99.153.3.178",
        asset_type=AssetType.IP_ADDRESS,
        organization_id=1,
        metadata_={"existing": True},
        ip_addresses=[],
        ip_history=[],
    )

    _apply_ip_enrichment(
        asset,
        {
            "provider": "ipinfo",
            "ip_address": "99.153.3.178",
            "country": "United States",
            "country_code": "US",
            "asn": "AS7018",
            "as_name": "AT&T Enterprises, LLC",
            "is_hosting": False,
            "hosted_domains": ["example.com"],
            "hosted_domain_count": 1,
            "hosted_domains_attribution": "co-hosted_only",
        },
    )

    intel = asset.metadata_["ip_intelligence"]
    assert asset.ip_address == "99.153.3.178"
    assert asset.country_code == "US"
    assert asset.asn == "AS7018"
    assert asset.metadata_["existing"] is True
    assert intel["as_name"] == "AT&T Enterprises, LLC"
    assert intel["hosted_domains"] == ["example.com"]
    assert intel["hosted_domains_attribution"] == "co-hosted_only"
    assert intel["fetched_at"].endswith("Z")


def test_org_services_use_isolated_encrypted_ipinfo_keys():
    def resolve_key(_db, service, organization_id):
        if service == "ipinfo":
            return f"org-{organization_id}-token"
        return None

    with patch("app.models.api_config.resolve_api_key", side_effect=resolve_key):
        first = get_geolocation_service_for_org(object(), 11)
        second = get_geolocation_service_for_org(object(), 22)

    assert first.ipinfo_token == "org-11-token"
    assert second.ipinfo_token == "org-22-token"
    assert first is not second
    assert first.preferred_provider == GeoProvider.IPINFO


def test_explicit_ipinfo_enrichment_requires_an_org_key():
    with patch("app.models.api_config.resolve_api_key", return_value=None):
        with pytest.raises(HTTPException) as exc:
            _org_geo_service(object(), 11, GeoProvider.IPINFO)

    assert exc.value.status_code == 400
    assert "Settings" in exc.value.detail
