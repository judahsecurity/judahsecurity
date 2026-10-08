"""Prefer distinct application routes before repeating a URL template."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from urllib.parse import parse_qsl, urlsplit


def route_family(url: str) -> tuple[str, tuple[str, ...]]:
    """Group product IDs while keeping distinct query-driven features separate."""
    parts = urlsplit(url)
    names = tuple(sorted({name for name, _ in parse_qsl(parts.query, keep_blank_values=True)}))
    return (parts.path or "/", names)


def next_crawl_index(
    queue: Sequence[tuple[int, int, str]],
    visited_families: Mapping[tuple[str, tuple[str, ...]], int],
) -> int:
    """Choose the best unvisited route family without discarding siblings."""
    if not queue:
        raise ValueError("Crawl queue is empty")
    return min(
        range(len(queue)),
        key=lambda index: (
            queue[index][0] + 45 * min(
                visited_families.get(route_family(queue[index][2]), 0), 3,
            ),
            queue[index][1],
            index,
        ),
    )
