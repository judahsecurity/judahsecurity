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
    assert "poll" in brief.lower()
    assert "mutate_captured_request" in brief
    assert "169.254" in brief
    assert len(brief) < 1600
    assert "httpx output" * 10 not in brief
    assert "LIVE Interactsh" not in brief


def test_brief_does_not_provision_interactsh_by_default(monkeypatch):
    def boom():
        raise AssertionError("unit tests must not spawn interactsh-client")

    monkeypatch.setattr("app.services.interactsh_service.ensure_session", boom)
    brief = format_hunter_brief(specialist="ssrf")
    assert "execute_interactsh" in brief
    assert "poll" in brief.lower()
    assert "169.254" in brief


def test_brief_provisions_live_interactsh_session(monkeypatch):
    monkeypatch.setattr(
        "app.services.interactsh_service.ensure_session",
        lambda: {
            "success": True,
            "session_id": "live1",
            "payload_url": "https://abc.oast.fun",
            "payload_email": "aegis@abc.oast.fun",
        },
    )
    brief = format_hunter_brief(specialist="ssrf", provision_oob=True)
    assert "session_id=live1" in brief
    assert "https://abc.oast.fun" in brief
    assert "aegis@abc.oast.fun" in brief
    assert "poll live1" in brief
    assert "Canarytokens" in brief
    assert "169.254" in brief
    assert len(brief) < 1600
