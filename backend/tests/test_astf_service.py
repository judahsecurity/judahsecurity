"""Unit tests for ASTF argument parsing / report summarization (no JAR required)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from app.services.astf_service import _build_argv, _parse_opts, _summarize_json_report


def test_parse_opts_bare_url():
    opts = _parse_opts("https://api.example.com")
    assert opts.get("url") == "https://api.example.com"


def test_parse_opts_json():
    opts = _parse_opts('{"url":"https://api.example.com","token":"abc"}')
    assert opts["url"] == "https://api.example.com"
    assert opts["token"] == "abc"


def test_build_argv_includes_token_and_json_out():
    with tempfile.TemporaryDirectory() as tmp:
        out = str(Path(tmp) / "r.json")
        argv = _build_argv({"url": "https://api.example.com", "token": "t"}, out)
        assert "-u" in argv and "https://api.example.com" in argv
        assert "--token" in argv and "t" in argv
        assert "-f" in argv and "JSON" in argv
        assert "-o" in argv and out in argv


def test_summarize_findings_list():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "r.json"
        path.write_text(
            json.dumps(
                {
                    "findings": [
                        {
                            "severity": "CRITICAL",
                            "title": "Broken Object Level Authorization",
                            "endpoint": "/api/users/1",
                            "evidence": "both identities got 200",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        summary = _summarize_json_report(str(path))
        assert "CRITICAL" in summary
        assert "Broken Object Level Authorization" in summary
        assert "compare_requests" in summary
