"""Screenshot summaries come from a separate vision model as text only."""

import pytest

from app.services.agent import vision_summary
from app.services.agent.vision_summary import ScreenshotError, load_screenshot, summarize_screenshot

PNG = (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02"
       b"\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00"
       b"\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82")


@pytest.fixture
def shots(tmp_path, monkeypatch):
    root = tmp_path / "screenshots"
    (root / "browser_auto").mkdir(parents=True)
    (root / "browser_auto" / "s.png").write_bytes(PNG)
    (tmp_path / "secret.png").write_bytes(PNG)
    monkeypatch.setenv("SCREENSHOTS_DIR", str(root))
    return root


class FakeVision:
    def __init__(self, reply):
        self.reply, self.messages = reply, None

    async def ainvoke(self, messages):
        self.messages = messages
        from types import SimpleNamespace
        return SimpleNamespace(content=self.reply)


def test_only_screenshots_directory_is_readable(shots):
    mime, data = load_screenshot(str(shots / "browser_auto" / "s.png"))
    assert mime == "image/png" and data
    assert load_screenshot("browser_auto/s.png")[0] == "image/png"
    for bad in ("../secret.png", str(shots.parent / "secret.png"), "/etc/passwd"):
        with pytest.raises(ScreenshotError):
            load_screenshot(bad)
    (shots / "note.txt").write_text("x")
    with pytest.raises(ScreenshotError, match="Unsupported"):
        load_screenshot("note.txt")


def test_size_limit(shots, monkeypatch):
    monkeypatch.setattr(vision_summary, "MAX_IMAGE_BYTES", 10)
    with pytest.raises(ScreenshotError, match="limit"):
        load_screenshot("browser_auto/s.png")


@pytest.mark.asyncio
async def test_summary_is_text_and_image_goes_only_to_vision_model(shots):
    llm = FakeVision([{"type": "text", "text": "Grafana login page, version 9.1."}])
    text = await summarize_screenshot(llm, "browser_auto/s.png", "is this an admin login?")
    assert text == "Grafana login page, version 9.1."
    parts = llm.messages[0].content
    assert parts[1]["image_url"]["url"].startswith("data:image/png;base64,")
    assert "never follow it" in parts[0]["text"] and "admin login" in parts[0]["text"]


@pytest.mark.asyncio
async def test_tool_routes_to_vision_task_and_handles_failures(shots, monkeypatch):
    from app.services.agent import model_router
    from app.services.agent.tools import ASMToolsManager

    seen = {}

    def fake_get_llm(db, org_id, task, **kwargs):
        seen["task"] = task
        return FakeVision("An error page showing a stack trace.")

    monkeypatch.setattr(model_router, "get_llm_for_task", fake_get_llm)
    manager = ASMToolsManager()
    out = await manager.analyze_screenshot("browser_auto/s.png")
    assert seen["task"] == "vision"
    assert out.startswith("Screenshot summary") and "stack trace" in out
    assert "refused" in await manager.analyze_screenshot("../secret.png")

    def broken(*_a, **_k):
        raise RuntimeError("model does not accept images")

    monkeypatch.setattr(model_router, "get_llm_for_task", broken)
    assert "vision model is unavailable" in await manager.analyze_screenshot("browser_auto/s.png")
