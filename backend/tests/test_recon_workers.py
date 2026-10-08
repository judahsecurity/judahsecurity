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
    scoped_archive_urls,
)


def test_packs_cover_known_kinds():
    for pack, kinds in PACKS.items():
        assert kinds, pack
        assert all(k in WORKER_KINDS for k in kinds)


def test_early_pack_defers_nuclei_recon():
    assert "nuclei_recon" in WORKER_KINDS
    assert PACKS["early"] == [
        "httpx_tech",
        "waf_probe",
        "whatweb",
        "archive_params",
    ]
    assert PACKS["nuclei_recon"] == ["nuclei_recon"]
    assert "nuclei_recon" in PACKS["full"]
    assert "nuclei_recon" not in PACKS["enrich"]


def test_normalize_url():
    assert _normalize_url("example.com") == "https://example.com"
    assert _normalize_url("https://example.com/") == "https://example.com"


def test_archive_params_pack_and_exact_host_filter():
    assert "archive_params" in PACKS["early"]
    assert "archive_params" not in PACKS["enrich"]
    assert scoped_archive_urls(
        [
            "http://example.com/catalog?category=Drinks",
            "https://example.com/catalog?category=Drinks#old",
            "https://example.com/search?term=FUZZ",
            "https://api.example.com/admin?x=1",
            "https://example.com:8443/hidden?x=1",
            "https://user:secret@example.com/private?x=1",
            "https://example.com:bad/invalid",
        ],
        "https://example.com",
    ) == [
        "https://example.com/catalog?category=",
        "https://example.com/search?term=",
    ]


def test_archive_params_worker_emits_scoped_leads(monkeypatch):
    from app.services import paramspider_service
    from app.services.agent import recon_workers

    class FakeParamSpider:
        def is_available(self):
            return True

        async def scan_domain(self, domain, timeout):
            assert domain == "example.com"
            assert timeout <= 120
            return paramspider_service.ParamSpiderResult(
                domain=domain,
                urls=[
                    "http://example.com/catalog?searchTerm=old",
                    "https://other.example.com/private?token=x",
                ],
                success=True,
            )

    monkeypatch.setattr(paramspider_service, "ParamSpiderService", FakeParamSpider)
    observations = []
    token = recon_workers._capture_context.set(("https://example.com", observations))
    try:
        brief = asyncio.run(_worker_body(
            "archive_params", "https://example.com", None,
            user_id=None, org_id=None, session_id="t",
        ))
    finally:
        recon_workers._capture_context.reset(token)
    assert "same_origin_leads=1" in brief
    assert observations == [{
        "type": "HTTP_ENDPOINT",
        "target": "https://example.com/catalog?searchTerm=",
        "source": "paramspider_archive",
    }]


def test_archive_params_handoff_seeds_bug_class_work():
    from app.services.agent.capability_map import ingest_passive_urls
    from app.services.agent.methodology_catalog import methodologies_from_capability_map
    from app.services.agent.parameter_inventory import collect_parameter_inventory

    target = "https://example.com"
    leads = scoped_archive_urls([
        "http://example.com/catalog?searchTerm=FUZZ&category=FUZZ",
        "http://example.com/stock?url=FUZZ",
        "http://example.com/login?next=FUZZ",
        "http://example.com/download?file=FUZZ",
        "http://example.com/api/profile?user_id=FUZZ",
    ], target)
    cmap = ingest_passive_urls(None, leads, target=target, source="archive_params")
    names = {row["name"] for row in collect_parameter_inventory(cmap)}
    assert {"searchTerm", "category", "url", "next", "file", "user_id"} <= names
    method_ids = {method.id for method in methodologies_from_capability_map(cmap)}
    assert {
        "reflected_xss", "param_injection", "ssrf_url_fetch", "open_redirect",
        "file_path_traversal", "api_idor_bola",
    } <= method_ids
    search_only = ingest_passive_urls(None, ["https://example.com/catalog?searchTerm="], target=target)
    assert "reflected_xss" in {
        method.id for method in methodologies_from_capability_map(search_only)
    }


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
    assert "-severity info" in args
    assert "-tags tech,detect" in args
    assert "-rate-limit 20" in args
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


def test_ferox_worker_uses_compatible_output_flags():
    tm = _FakeTools({"success": True, "output": ""})
    asyncio.run(
        _worker_body(
            "ferox_dirs", "https://example.com", tm,
            user_id=None, org_id=None, session_id="t",
        )
    )
    tool_name, tool_args = tm.calls[0]
    assert tool_name == "execute_feroxbuster"
    assert "--silent" in tool_args["args"].split()
    assert "-q" not in tool_args["args"].split()


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
    assert "-rate-limit 20" in tool_args["args"]
    assert "-tags tech,detect" in tool_args["args"]
    assert "[recon_worker:nuclei_recon]" in brief
    assert "wordpress" in brief.lower()
    assert "coverage leftover" in brief.lower()
    assert "NUCLEI SCAN" in brief or "signal=cms" in brief or "wordpress" in brief.lower()
