"""Single-shot mutation lists — no LLM required."""

from app.services.agent.single_shot_mutate import generate_mutations


def test_paths_include_execute_and_observed():
    out = generate_mutations(
        "paths",
        "https://appsmith.example.com 404 /user/login",
        count=30,
    )
    assert out["ok"] is True
    items = " ".join(out["items"])
    assert "/api" in items
    assert "/actions" in items or "/execute" in items
    assert "/user/login" in out["items"] or "/user/login" in items


def test_params_ssrf_names():
    out = generate_mutations("params", "POST /api?callback=1", count=20)
    blob = " ".join(out["items"])
    assert "url" in blob
    assert "callback" in blob


def test_xss_list():
    out = generate_mutations("xss", "cloudflare waf", count=15)
    assert any("alert" in x for x in out["items"])


def test_rejects_bad_kind():
    out = generate_mutations("nuclei", "")
    assert out["ok"] is False
