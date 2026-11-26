"""Crawl stops once pages stop revealing new functionality."""

from types import SimpleNamespace

from app.services.agent.crawl_novelty import (
    CrawlNoveltyTracker, _route_shape, surface_fingerprint,
)


def _result(pages=None, links=None, forms=None, api_calls=None):
    return SimpleNamespace(
        pages_visited=pages or [], discovered_links=links or [],
        forms=forms or [], api_calls=api_calls or {}, api_samples=[],
    )


def test_route_shape_collapses_ids():
    assert _route_shape("https://s.test/product/1") == "/product/{id}"
    assert _route_shape("https://s.test/u/deadbeefcafe1234") == "/u/{id}"
    assert _route_shape("https://s.test/catalog") == "/catalog"
    # Two product pages share a shape; the catalog is distinct.
    assert _route_shape("https://s.test/product/2") == _route_shape("https://s.test/product/1")


def test_fingerprint_counts_distinct_surfaces_not_pages():
    result = _result(
        pages=["https://s.test/product/1", "https://s.test/product/2"],
        links=[{"url": "https://s.test/catalog", "query_keys": ["category"]}],
        forms=[{"action": "https://s.test/search", "method": "get",
                "fields": [{"name": "q"}]}],
        api_calls={"s.test": ["POST /login"]},
    )
    marks = surface_fingerprint(result)
    # Both product pages collapse to one route mark.
    assert sum(1 for m in marks if m.startswith("route:")) == 1
    assert "param:/catalog?category" in marks
    assert "form:get:/search:q" in marks
    assert "api:POST:s.test:/login" in marks


def test_stops_after_patience_pages_without_new_surface():
    t = CrawlNoveltyTracker(patience=3, min_pages=2)
    # Each product page is new only by id, so they share one route shape.
    base_links = [{"url": "https://s.test/catalog", "query_keys": ["category"]}]
    # Page 1: catalog + a form -> new.
    assert not t.record(_result(pages=["https://s.test/"], links=base_links,
                                forms=[{"action": "https://s.test/search", "method": "get",
                                        "fields": [{"name": "q"}]}]))
    # Page 2: first product -> new route.
    assert not t.record(_result(pages=["https://s.test/", "https://s.test/product/1"],
                                links=base_links))
    # Pages 3-5: more products, same shape, nothing new.
    r = _result(pages=["https://s.test/", "https://s.test/product/1",
                       "https://s.test/product/2"], links=base_links)
    assert not t.record(r)  # stale 1
    assert not t.record(r)  # stale 2
    assert t.record(r)      # stale 3 -> stop
    assert "no new functionality in 3 pages" in t.reason()


def test_min_pages_floor_prevents_an_early_stop():
    t = CrawlNoveltyTracker(patience=1, min_pages=4)
    r = _result(pages=["https://s.test/"])
    # Same page repeated adds nothing, but the floor keeps the crawl going.
    assert not t.record(r)
    assert not t.record(r)
    assert not t.record(r)
    # Fourth page reaches the floor; still nothing new -> stop.
    assert t.record(r)


def test_a_new_surface_resets_the_streak():
    t = CrawlNoveltyTracker(patience=2, min_pages=1)
    r1 = _result(pages=["https://s.test/a"])
    assert not t.record(r1)
    assert not t.record(r1)              # stale 1 (patience=2, no stop yet)
    r2 = _result(pages=["https://s.test/a", "https://s.test/b"])
    assert not t.record(r2)              # new route resets streak
    assert t.stale_streak == 0 and t.last_new == 1
    assert not t.record(r2)              # stale 1
    assert t.record(r2)                  # stale 2 -> stop
