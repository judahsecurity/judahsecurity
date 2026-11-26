"""Stop crawling once pages stop revealing new functionality.

Crawl depth and page count are poor budgets: twelve product pages are the
same page with a different id, so visiting more spends requests without
mapping anything new. What matters for testing is distinct functionality:
route shapes, forms, parameters and API calls, each with a normal response.

``CrawlNoveltyTracker`` fingerprints the application surface a crawl has
collected so far. After each page it records whether the surface grew. When
``patience`` pages in a row add nothing new (after a ``min_pages`` floor), the
crawl has learned what it is going to learn and the loop stops early. Nothing
here sends traffic; it only reads the CrawlResult the loop already fills.

Gated by ``AGENT_CRAWL_NOVELTY_STOP``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Set
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

DEFAULT_PATIENCE = 3
DEFAULT_MIN_PAGES = 4


def _route_shape(url: str) -> str:
    """A path with numeric and long-hex segments collapsed, so /p/1 ≡ /p/2."""
    path = urlsplit(url).path or "/"
    parts = []
    for seg in path.split("/"):
        if not seg:
            continue
        low = seg.lower()
        if seg.isdigit() or (len(seg) >= 8 and all(c in "0123456789abcdef" for c in low)):
            parts.append("{id}")
        else:
            parts.append(low)
    return "/" + "/".join(parts)


def surface_fingerprint(result: Any) -> Set[str]:
    """Distinct testable surfaces in a CrawlResult: routes, forms, params, APIs."""
    marks: Set[str] = set()
    for url in getattr(result, "pages_visited", None) or []:
        marks.add("route:" + _route_shape(str(url)))
    for link in getattr(result, "discovered_links", None) or []:
        if not isinstance(link, dict):
            continue
        shape = _route_shape(str(link.get("url") or ""))
        for key in link.get("query_keys") or []:
            marks.add(f"param:{shape}?{key}")
    for form in getattr(result, "forms", None) or []:
        if not isinstance(form, dict):
            continue
        action = _route_shape(str(form.get("action") or form.get("page") or ""))
        method = str(form.get("method") or "get").lower()
        fields = ",".join(sorted(
            str(f.get("name") or "") for f in form.get("fields") or [] if isinstance(f, dict)
        )) or ",".join(sorted(str(x) for x in form.get("fields") or [] if isinstance(x, str)))
        marks.add(f"form:{method}:{action}:{fields}")
    api_calls = getattr(result, "api_calls", None) or {}
    if isinstance(api_calls, dict):
        for host, calls in api_calls.items():
            for call in calls or []:
                method, _, path = str(call).partition(" ")
                marks.add(f"api:{method}:{host}:{_route_shape(path)}")
    for sample in getattr(result, "api_samples", None) or []:
        if isinstance(sample, dict) and sample.get("url"):
            marks.add(f"api:{str(sample.get('method') or 'GET').upper()}:"
                      f"{_route_shape(str(sample['url']))}")
    return marks


@dataclass
class CrawlNoveltyTracker:
    patience: int = DEFAULT_PATIENCE
    min_pages: int = DEFAULT_MIN_PAGES
    seen: Set[str] = field(default_factory=set)
    pages: int = 0
    stale_streak: int = 0
    last_new: int = 0

    def record(self, result: Any) -> bool:
        """Note one visited page; return True when the crawl should stop early."""
        self.pages += 1
        marks = surface_fingerprint(result)
        new = marks - self.seen
        if new:
            self.seen |= new
            self.last_new = len(new)
            self.stale_streak = 0
        else:
            self.last_new = 0
            self.stale_streak += 1
        if self.pages < self.min_pages:
            return False
        return self.stale_streak >= self.patience

    def reason(self) -> str:
        return (f"no new functionality in {self.stale_streak} pages "
                f"({len(self.seen)} distinct surfaces mapped over {self.pages} pages)")


def novelty_stop_enabled() -> bool:
    from app.core.config import settings

    return bool(getattr(settings, "AGENT_CRAWL_NOVELTY_STOP", False))


def make_tracker() -> CrawlNoveltyTracker:
    from app.core.config import settings

    return CrawlNoveltyTracker(
        patience=max(1, int(getattr(settings, "AGENT_CRAWL_NOVELTY_PATIENCE", DEFAULT_PATIENCE))),
        min_pages=max(1, int(getattr(settings, "AGENT_CRAWL_NOVELTY_MIN_PAGES", DEFAULT_MIN_PAGES))),
    )
