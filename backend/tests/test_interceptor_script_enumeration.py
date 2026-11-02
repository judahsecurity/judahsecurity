"""Script bundles come from the page, since ``net log`` omits ``<script>`` loads."""

import asyncio

from app.services.interceptor_recon import (
    ReconResult,
    _collect_loaded_scripts,
    _parse_script_urls,
)


class FakeCLI:
    def __init__(self, isolated: str, main: str = ""):
        self.isolated = isolated
        self.main = main
        self.calls = []

    async def run(self, *args, timeout=0):
        self.calls.append(args)
        return self.main if "--main" in args else self.isolated


def _result():
    return ReconResult(target="https://app.example.com/", scope="example.com")


def test_first_party_scripts_added_and_third_party_recorded():
    cli = FakeCLI(
        '["https://app.example.com/static/js/main.abc.js?v=1",'
        '"https://cdn.example.com/chunks/42.def.chunk.js#x",'
        '"https://www.googletagmanager.com/gtm.js",'
        '"https://app.example.com/static/css/site.css"]'
    )
    result = _result()
    added = asyncio.run(_collect_loaded_scripts(cli, result))
    assert added == 2
    assert result.js_files == {
        "https://app.example.com/static/js/main.abc.js",
        "https://cdn.example.com/chunks/42.def.chunk.js",
    }
    assert "www.googletagmanager.com" in result.third_party
    assert len(cli.calls) == 1 and "--main" not in cli.calls[0]


def test_csp_block_retries_in_main_world():
    cli = FakeCLI(
        "__error__ exit 1: Evaluating a string as JavaScript violates the following "
        "Content Security Policy directive",
        main='["https://app.example.com/assets/index-1a2b.js"]',
    )
    result = _result()
    assert asyncio.run(_collect_loaded_scripts(cli, result)) == 1
    assert "--main" in cli.calls[-1]
    assert result.js_files == {"https://app.example.com/assets/index-1a2b.js"}


def test_empty_array_does_not_retry_and_repeat_is_not_new():
    result = _result()
    result.js_files.add("https://app.example.com/a.js")
    cli = FakeCLI('["https://app.example.com/a.js"]')
    assert asyncio.run(_collect_loaded_scripts(cli, result)) == 0
    cli = FakeCLI("[]")
    assert asyncio.run(_collect_loaded_scripts(cli, result)) == 0
    assert len(cli.calls) == 1


def test_parse_skips_non_json_brackets():
    out = 'note [info] ready\n["https://a.example.com/x.js", 3]'
    assert _parse_script_urls(out) == ["https://a.example.com/x.js"]
    assert _parse_script_urls("nothing here") == []
