from app.services.crawl_priority import (
    next_crawl_index, next_crawl_url_index, route_family, route_visit_allowed,
)


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

def test_crawl_reserves_remaining_slots_for_distinct_route_families():
    queue = [
        (-65, 1, f"https://example.test/catalog/product?productId={product_id}")
        for product_id in range(2, 20)
    ]
    queue.extend([
        (-25, 1, "https://example.test/blog"),
        (-15, 1, "https://example.test/catalog?category=Gifts"),
        (-5, 1, "https://example.test/catalog?searchTerm=gin"),
    ])
    visited = {route_family("https://example.test/catalog/product?productId=1"): 1}
    chosen = []
    for _ in range(3):
        index = next_crawl_index(queue, visited)
        _, _, url = queue.pop(index)
        chosen.append(url)
        family = route_family(url)
        visited[family] = visited.get(family, 0) + 1
    assert {route_family(url) for url in chosen} == {
        route_family("https://example.test/blog"),
        route_family("https://example.test/catalog?category=Gifts"),
        route_family("https://example.test/catalog?searchTerm=gin"),
    }


def test_browser_link_queue_visits_new_route_before_sibling_queries():
    queue = [
        "https://example.test/items?id=2",
        "https://example.test/items?id=3",
        "https://example.test/articles",
    ]
    visited = {route_family("https://example.test/items?id=1"): 1}
    assert next_crawl_url_index(queue, visited) == 2


def test_route_sample_limit_keeps_other_query_features_eligible():
    visited = {route_family("https://example.test/items?id=1"): 2}
    assert not route_visit_allowed("https://example.test/items?id=3", visited, 2)
    assert route_visit_allowed("https://example.test/items?search=book", visited, 2)
    assert route_visit_allowed("https://example.test/articles", visited, 2)
