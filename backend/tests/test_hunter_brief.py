"""Notes-only hunter brief — no scan dumps."""

from types import SimpleNamespace

from app.services.agent.hunter_brief import format_hunter_brief


def test_brief_is_notes_not_dump():
    directive = SimpleNamespace(
        target="https://app.example.com/api/v1/actions/execute",
        goal="SSRF via action execute URL fetch",
        assumption="server fetches requestUrl",
        test="plant interactsh in requestUrl",
        rewrite_note="",
        hypothesis_ids=["h-ssrf"],
    )
    cmap = {
        "api_samples": [
            {"method": "POST", "url": "https://app.example.com/api/v1/actions/execute"},
        ]
    }
    palace = "Joshua — huge dump\n" + ("httpx output " * 200)
    brief = format_hunter_brief(
        specialist="injection",
        directive=directive,
        cmap=cmap,
        palace_snippet=palace,
    )
    assert "https://app.example.com/api/v1/actions/execute" in brief
    assert "interactsh" in brief.lower() or "OOB" in brief or "SSRF" in brief
    assert "mutate_captured_request" in brief
    assert "169.254" in brief
    assert len(brief) < 1600
    assert "httpx output" * 10 not in brief
