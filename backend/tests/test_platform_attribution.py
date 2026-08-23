"""Tests for shared-PaaS ownership attribution."""

from app.services.platform_attribution import (
    build_attribution_tokens,
    filter_attributed_hostnames,
    hostname_attributed_to_org,
    is_shared_paas_hostname,
)


def _rockwell_tokens():
    return build_attribution_tokens(
        org_name="Rockwell Automation",
        primary_domain="rockwellautomation.com",
        keywords=["factorytalk", "allen-bradley", "rockwell"],
    )


def test_tokens_include_brand_not_generics():
    tokens = _rockwell_tokens()
    assert "rockwell" in tokens
    assert "rockwellautomation" in tokens
    assert "factorytalk" in tokens
    assert "allenbradley" in tokens
    assert "allen" not in tokens
    assert "bradley" not in tokens
    assert "automation" not in tokens  # too generic alone
    assert "dev" not in tokens
    assert "azure" not in tokens


def test_rejects_random_azure_app_service():
    decision = hostname_attributed_to_org(
        "spi4-develop-dje3d5hzdsamave9.canadacentral-01.azurewebsites.net",
        _rockwell_tokens(),
        owned_domains=["rockwellautomation.com"],
    )
    assert decision.accept is False
    assert decision.paas_suffix == "azurewebsites.net"


def test_accepts_rockwell_named_azure_app():
    decision = hostname_attributed_to_org(
        "rockwellsync-gygzanbba7ehfnec.canadacentral-01.azurewebsites.net",
        _rockwell_tokens(),
        owned_domains=["rockwellautomation.com"],
    )
    assert decision.accept is True


def test_accepts_factorytalk_azure_app():
    decision = hostname_attributed_to_org(
        "factorytalk-portal-abc123.azurewebsites.net",
        _rockwell_tokens(),
    )
    assert decision.accept is True


def test_rejects_platform_wildcard():
    decision = hostname_attributed_to_org(
        "*.canadacentral-01.azurewebsites.net",
        _rockwell_tokens(),
    )
    assert decision.accept is False


def test_corporate_subdomains_unaffected():
    decision = hostname_attributed_to_org(
        "vpn.rockwellautomation.com",
        _rockwell_tokens(),
        owned_domains=["rockwellautomation.com"],
    )
    assert decision.accept is True
    assert not is_shared_paas_hostname("vpn.rockwellautomation.com")


def test_owned_domain_allows_non_brand_hostname_under_corp():
    # Custom hostname under owned corporate domain is attributable even without
    # a brand token in the left-most label.
    decision = hostname_attributed_to_org(
        "obscure-app.rockwellautomation.com",
        _rockwell_tokens(),
        owned_domains=["rockwellautomation.com"],
    )
    assert decision.accept is True


def test_filter_batch_drops_noise_keeps_brand():
    accepted, rejected = filter_attributed_hostnames(
        [
            "spi4-develop-dje3d5hzdsamave9.canadacentral-01.azurewebsites.net",
            "rockwell-ops-abc.azurewebsites.net",
            "www.rockwellautomation.com",
            "*.azurewebsites.net",
        ],
        _rockwell_tokens(),
        owned_domains=["rockwellautomation.com"],
    )
    values = set(accepted)
    assert "rockwell-ops-abc.azurewebsites.net" in values
    assert "www.rockwellautomation.com" in values
    assert all("spi4" not in h for h in accepted)
    assert any("spi4" in h for h, _ in rejected)


def test_accepts_brand_named_azurecr():
    decision = hostname_attributed_to_org(
        "rockwelldev.azurecr.io",
        _rockwell_tokens(),
    )
    assert decision.accept is True
    assert is_shared_paas_hostname("rockwelldev.azurecr.io")


def test_rejects_unrelated_azurecr():
    decision = hostname_attributed_to_org(
        "unrelatedregistry.azurecr.io",
        _rockwell_tokens(),
    )
    assert decision.accept is False
    assert decision.paas_suffix == "azurecr.io"


def test_without_brand_tokens_shared_paas_is_rejected():
    decision = hostname_attributed_to_org(
        "anything.azurewebsites.net",
        [],
    )
    assert decision.accept is False
