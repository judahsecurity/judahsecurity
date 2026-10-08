from app.services.crawl_priority import next_crawl_index, route_family


def test_crawl_visits_blog_before_eighteen_more_product_ids():
    queue = [
        (-65, 1, "https://example.test/catalog/product?productId=2"),
        (-65, 1, "https://example.test/catalog/product?productId=3"),
        (-25, 1, "https://example.test/blog"),
    ]
    assert next_crawl_index(queue, {}) == 0
    visited = {route_family("https://example.test/catalog/product?productId=1"): 1}
    assert next_crawl_index(queue, visited) == 2


def test_distinct_query_features_have_distinct_families():
    assert route_family("https://example.test/catalog?category=A") != route_family(
        "https://example.test/catalog?searchTerm=A"
    )
