"""Replay samples retain distinct request shapes without duplicate traffic."""

from app.services.deep_crawl_service import _api_sample_family


def test_api_sample_family_ignores_values_but_keeps_distinct_inputs():
    base = {
        "method": "POST",
        "url": "https://example.test/catalog/product/stock?productId=1",
        "headers": {"content-type": "application/x-www-form-urlencoded; charset=UTF-8"},
        "body": "productId=1&storeId=2",
    }
    same_shape = {**base, "url": "https://example.test/catalog/product/stock?productId=2",
                  "body": "productId=2&storeId=4"}
    other_shape = {**base, "body": "productId=2&warehouseId=4"}
    assert _api_sample_family(base) == _api_sample_family(same_shape)
    assert _api_sample_family(base) != _api_sample_family(other_shape)


def test_api_sample_family_keeps_json_and_xml_body_shapes():
    json_request = {
        "method": "POST", "url": "https://example.test/api/stock",
        "headers": {"content-type": "application/json"},
        "body": '{"productId":1,"storeId":2}',
    }
    xml_request = {
        **json_request,
        "headers": {"content-type": "application/xml"},
        "body": "<stockCheck><productId>1</productId></stockCheck>",
    }
    assert _api_sample_family(json_request) != _api_sample_family(xml_request)
    assert _api_sample_family(xml_request)[-1] == ("stockCheck",)
