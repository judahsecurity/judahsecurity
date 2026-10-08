import asyncio
import time
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

from app.services.agent.capability_map import build_capability_map_from_crawl, merge_capability_maps
from app.services.agent.reflection_probe import probe_reflections, reflection_candidates
from app.services.deep_crawl_service import CrawlResult


def _row(path, name, *, host="example.test", source="observed_form", testable=True):
    return {"method": "GET", "location": "query", "path": path, "name": name,
            "host": host, "source": source, "testable": testable}


def test_reflection_candidates_restrict_to_observed_safe_same_origin_get():
    rows = [
        _row("/catalog", "searchTerm"),
        _row("/catalog", "searchTerm"),
        _row("/checkout", "searchTerm"),
        _row("/catalog", "token", testable=False),
        _row("/catalog", "category", host="other.test"),
        _row("/catalog", "q", source="archive_paramspider"),
        {**_row("/catalog", "name"), "method": "POST"},
    ]
    assert [(row["path"], row["parameter"]) for row in
            reflection_candidates("https://example.test", rows)] == [("/catalog", "searchTerm")]


def test_probe_records_reflection_without_claiming_execution():
    calls = []

    class Response:
        status = 200
        headers = {"content-type": "text/html; charset=utf-8"}

        def __init__(self, body):
            self._body = body

        async def body(self):
            return self._body

    class Request:
        async def get(self, url, **kwargs):
            calls.append((url, kwargs))
            marker = parse_qs(urlsplit(url).query)["searchTerm"][0]
            return Response(f"<p>{marker}</p>".encode())

    context = SimpleNamespace(request=Request())
    found = asyncio.run(probe_reflections(context, "https://example.test", [
        _row("/catalog", "searchTerm"),
    ], deadline=time.monotonic() + 10))
    assert len(found) == 1
    assert found[0]["reflected"] is True
    assert found[0]["browser_execution_verified"] is False
    assert found[0]["reflection_location"] == "html_response_source"
    assert urlsplit(calls[0][0]).netloc == "example.test"
    assert calls[0][1]["max_redirects"] == 0


def test_crawl_reflections_survive_capability_map_merge_as_leads():
    crawl = CrawlResult(target="https://example.test", scope="example.test")
    crawl.reflection_observations = [{
        "path": "/catalog", "parameter": "searchTerm", "reflected": True,
        "browser_execution_verified": False,
    }]
    mapped = build_capability_map_from_crawl(crawl).to_dict()
    merged = merge_capability_maps(None, mapped)
    assert merged["reflection_observations"] == crawl.reflection_observations
