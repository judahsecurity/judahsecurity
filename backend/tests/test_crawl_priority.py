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
