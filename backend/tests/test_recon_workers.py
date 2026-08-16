"""Tests for parallel recon worker helpers."""

from app.services.agent.recon_workers import (
    PACKS,
    WORKER_KINDS,
    _normalize_url,
    format_briefs_for_prompt,
)


def test_packs_cover_known_kinds():
    for pack, kinds in PACKS.items():
        assert kinds, pack
        assert all(k in WORKER_KINDS for k in kinds)


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
