"""Tests for parallel recon worker helpers."""

import asyncio

from app.services.agent.recon_workers import (
    PACKS,
    WORKER_KINDS,
    _normalize_url,
    _worker_body,
    format_briefs_for_prompt,
    is_bounded_nuclei_recon_args,
    nuclei_recon_args,
)


def test_packs_cover_known_kinds():
    for pack, kinds in PACKS.items():
        assert kinds, pack
        assert all(k in WORKER_KINDS for k in kinds)


def test_early_pack_includes_nuclei_recon():
    assert "nuclei_recon" in WORKER_KINDS
    assert PACKS["early"] == [
        "httpx_tech",
        "waf_probe",
        "whatweb",
        "nuclei_recon",
    ]
    assert PACKS["nuclei_recon"] == ["nuclei_recon"]
    assert "nuclei_recon" in PACKS["full"]
    assert "nuclei_recon" not in PACKS["enrich"]


def test_normalize_url():
    assert _normalize_url("example.com") == "https://example.com"
    assert _normalize_url("https://example.com/") == "https://example.com"


def test_format_briefs_for_prompt():
    text = format_briefs_for_prompt(
        [
            {
                "kind": "httpx_tech",
                "status": "completed",
                "worker_id": "rw_abc",
                "brief": "ok",
            }
        ]
    )
    assert "httpx_tech" in text
    assert "ok" in text
    assert format_briefs_for_prompt([]) == ""


def test_nuclei_recon_args_are_informational():
    args = nuclei_recon_args("https://example.com")
    assert is_bounded_nuclei_recon_args(args)
    assert "-severity info,low" in args
    assert "-tags tech,exposure,panel" in args
    assert "-jsonl" in args
    assert "-etags" in args


def test_is_bounded_nuclei_recon_args_rejects_cve_spray():
    assert not is_bounded_nuclei_recon_args("")
    assert not is_bounded_nuclei_recon_args("-u https://example.com -jsonl")
    assert not is_bounded_nuclei_recon_args(
        "-u https://example.com -severity critical,high -jsonl"
    )
    assert not is_bounded_nuclei_recon_args(
        "-u https://example.com -severity info -tags cve -jsonl"
    )
    assert is_bounded_nuclei_recon_args(
        "-u https://example.com -severity info -tags tech -jsonl"
    )


class _FakeTools:
    def __init__(self, result):
        self.calls = []
        self._fallback_target = ""
        self._result = result

    async def execute(self, tool_name, tool_args):
        self.calls.append((tool_name, tool_args))
        return self._result


def test_nuclei_recon_worker_runs_bounded_nuclei_and_filters():
    jsonl = (
        '{"template-id":"wordpress-detect","info":{"name":"WordPress Detect",'
        '"severity":"info","tags":"tech,wordpress"},'
        '"matched-at":"https://example.com"}\n'
        '{"template-id":"tech-detect","info":{"name":"Tech Detect",'
        '"severity":"info","tags":"tech"},'
        '"matched-at":"https://example.com"}\n'
    )
    tm = _FakeTools({"success": True, "output": jsonl})
    brief = asyncio.run(
        _worker_body(
            "nuclei_recon",
            "https://example.com",
            tm,
            user_id=None,
            org_id=None,
            session_id="t",
        )
    )
    assert tm.calls
    tool_name, tool_args = tm.calls[0]
    assert tool_name == "execute_nuclei"
    assert is_bounded_nuclei_recon_args(tool_args["args"])
    assert "[recon_worker:nuclei_recon]" in brief
    assert "wordpress" in brief.lower()
    assert "coverage leftover" in brief.lower()
    assert "NUCLEI SCAN" in brief or "signal=cms" in brief or "wordpress" in brief.lower()
