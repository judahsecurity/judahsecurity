"""Campaign attack-path graph composition."""

from app.services.attack_path_campaign import (
    FindingView,
    build_graph,
    campaigns_from_views,
    classify_env,
    group_findings,
    path_title,
    status_for_finding,
)


def _row(**kwargs) -> FindingView:
    defaults = dict(
        id=1,
        title="Finding",
        host="app.example.com",
        severity="high",
        status="open",
    )
    defaults.update(kwargs)
    return FindingView(**defaults)


def test_classify_env_qa_vs_prod():
    assert classify_env("qa.unifytwin.com") == "QA"
    assert classify_env("glms.unifytwin.com") == "Production"
    assert classify_env("api.example.com", tags=["qa"]) == "QA"


def test_status_tested_vs_undetected_vs_logged():
    demonstrated = _row(has_chain=True, template_id=None, detected_by="agent")
    assert status_for_finding(demonstrated) == "undetected"

    both = _row(has_chain=True, template_id="cve-js-secret", detected_by="agent")
    assert status_for_finding(both) == "detected"

    scanner = _row(has_chain=False, template_id="nuclei-xss", detected_by="nuclei")
    assert status_for_finding(scanner) == "logged"

    closed = _row(status="resolved", has_chain=True)
    assert status_for_finding(closed) == "prevented"


def test_group_by_session_then_host():
    a = _row(id=1, session_id="sess-1", host="qa.example.com", has_chain=True)
    b = _row(id=2, session_id="sess-1", host="prod.example.com", has_chain=True, title="HMAC bypass")
    c = _row(id=3, host="lonely.example.com", has_chain=True, title="Solo chain")
    groups = group_findings([a, b, c])
    assert any(len(g) == 2 and {r.host for r in g} == {"qa.example.com", "prod.example.com"} for g in groups)
    assert any(len(g) == 1 and g[0].id == 3 for g in groups)


def test_graph_branches_qa_and_prod_and_maps_mitre():
    qa = _row(
        id=10,
        title="Hardcoded HMAC Signing Secret in JS Bundle",
        host="qa.unifytwin.com",
        env="QA",
        has_chain=True,
        session_id="rockwell",
        cwe_id="CWE-321",
        chain_steps=[{"tool": "execute_curl", "summary": "Fetched JS bundle"}],
        impact="Hardcoded HMAC secret in the QA FactoryTalk bundle.",
    )
    prod = _row(
        id=11,
        title="Hardcoded HMAC Key and ICS Credentials in JS Bundle",
        host="glms.unifytwin.com",
        env="Production",
        has_chain=True,
        session_id="rockwell",
        cwe_id="CWE-798",
        chain_steps=[{"tool": "execute_curl", "summary": "Fetched production JS"}],
        oracle_title="Hardcoded Secrets to ICS Integrity Bypass",
        oracle_scenario="Hardcoded cryptographic secrets in publicly accessible JavaScript bundles nullify request integrity controls.",
    )
    brute = _row(
        id=12,
        title="Missing Brute-Force Protection on Login",
        host="glms.unifytwin.com",
        env="Production",
        session_id="rockwell",
        has_chain=False,
        template_id="brute-login",
        severity="medium",
    )
    campaigns = campaigns_from_views([qa, prod, brute])
    assert len(campaigns) == 1
    path = campaigns[0]
    assert "Hardcoded Secrets" in path["title"]
    kinds = {n["kind"] for n in path["nodes"]}
    assert kinds >= {"attacker", "technique", "host", "vulnerability"}
    hosts = [n for n in path["nodes"] if n["kind"] == "host"]
    assert {h["title"] for h in hosts} == {"qa.unifytwin.com", "glms.unifytwin.com"}
    mitre_ids = {n["mitre_id"] for n in path["nodes"] if n["mitre_id"]}
    assert "T1592.004" in mitre_ids
    titles = [n["title"] for n in path["nodes"] if n["kind"] == "vulnerability"]
    assert any("Brute-Force" in t for t in titles)

    nodes, edges, _ = build_graph([qa, prod, brute])
    by_id = {n["id"]: n for n in nodes}
    # Both hosts hang off recon; brute-force is a convergence sink.
    host_ids = [n["id"] for n in nodes if n["kind"] == "host"]
    recon = next(n["id"] for n in nodes if n["kind"] == "technique" and n["mitre_id"] == "T1592.004")
    assert all(any(e["source"] == recon and e["target"] == hid for e in edges) for hid in host_ids)
    brute_id = next(n["id"] for n in nodes if "Brute-Force" in n["title"])
    assert by_id[brute_id]["status"] == "logged"


def test_path_title_falls_back_to_from_to():
    a = _row(id=1, title="Open JS bundle", has_chain=True, session_id="s")
    b = _row(id=2, title="ICS integrity bypass", has_chain=True, session_id="s", severity="critical")
    assert path_title([a, b]) == "Open JS bundle to ICS integrity bypass"
