"""External-tool bridge: manifest loading, safe argv building, guardrail posture."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent import tool_bridge as tb


def test_manifest_loads_and_hides_meta():
    tools = tb.list_tools()
    names = {t["name"] for t in tools}
    assert "dalfox" in names
    assert not any(n.startswith("_") for n in names)  # _meta filtered out
    for t in tools:
        assert set(("name", "description", "risk", "installed")).issubset(t)


def test_unknown_tool_rejected():
    r = tb.run_tool("definitely_not_a_tool", "https://example.com")
    assert r["ok"] is False
    assert "unknown tool" in r["error"]
    assert "available" in r


def test_invalid_target_rejected():
    r = tb.run_tool("dalfox", "https://example.com; rm -rf /")
    assert r["ok"] is False
    assert "unsafe" in r["error"] or "invalid" in r["error"]


def test_extra_args_metachars_rejected():
    spec = {"argv": ["url", "{target}", "{extra}"]}
    for bad in ["-w x; cat /etc/passwd", "$(id)", "a|b", "a`b`", "a>b", "a&&b"]:
        try:
            tb._safe_extra(bad)
            assert False, f"should have rejected: {bad!r}"
        except ValueError:
            pass


def test_extra_args_safe_tokens_allowed():
    toks = tb._safe_extra("-w /usr/share/wordlists/params.txt --depth=3")
    assert toks == ["-w", "/usr/share/wordlists/params.txt", "--depth=3"]


def test_build_argv_substitutes_target_and_extra():
    spec = {"argv": ["url", "{target}", "--format", "json", "{extra}"]}
    argv = tb.build_argv(spec, "https://t.example.com", ["-b", "cookie=1"])
    assert argv == ["url", "https://t.example.com", "--format", "json", "-b", "cookie=1"]


def test_build_argv_appends_extra_when_no_marker():
    spec = {"argv": ["-u", "{target}"]}
    argv = tb.build_argv(spec, "https://t.example.com", ["-s"])
    assert argv == ["-u", "https://t.example.com", "-s"]


def test_missing_binary_degrades_gracefully(monkeypatch):
    monkeypatch.setattr(tb.shutil, "which", lambda b: None)
    r = tb.run_tool("dalfox", "https://example.com")
    assert r["ok"] is False
    assert "not installed" in r["error"]
    assert r["install_hint"]


def test_never_uses_shell(monkeypatch):
    # Prove subprocess.run is invoked with a list argv and shell=False.
    monkeypatch.setattr(tb.shutil, "which", lambda b: "/usr/bin/" + b)
    captured = {}

    class _P:
        returncode = 0
        stdout = "{}"
        stderr = ""

    def fake_run(argv, **kw):
        captured["argv"] = argv
        captured["shell"] = kw.get("shell")
        return _P()

    monkeypatch.setattr(tb.subprocess, "run", fake_run)
    tb.run_tool("dalfox", "https://example.com")
    assert isinstance(captured["argv"], list)
    assert captured["shell"] is False
