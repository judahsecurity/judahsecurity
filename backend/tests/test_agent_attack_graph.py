"""Entity attack graph built from an EvoGraph session chain."""

from app.services.agent.attack_graph import (
    build_attack_graph,
    classify_capability,
    extract_targets,
)


def _step(iteration, phase, tool, args, success, findings=(), output="", failures=()):
    return {
        "id": f"step-{iteration}",
        "type": "step",
        "properties": {
            "iteration": iteration,
            "phase": phase,
            "tool_name": tool,
            "tool_args": args,
            "output_summary": output,
            "success": success,
            "thought": "",
            "findings": list(findings),
            "failures": list(failures),
        },
    }


def _chain(*steps):
    return {
        "nodes": [{"id": "chain-abc", "type": "chain"}, *steps],
        "edges": [],
        "meta": {"session_id": "abc", "objective": "test", "status": "completed"},
    }


def _by_kind(graph, kind):
    return [n for n in graph["nodes"] if n["kind"] == kind]


def _edge_set(graph):
    return {(e["source"], e["target"]) for e in graph["edges"]}


def test_classify_requires_gain_for_weak_nouns():
    assert classify_capability("Missing CSRF token on login form") is None
    assert classify_capability("Admin panel found at /admin") is None
    assert classify_capability("Hard-coded AWS access key in main.js") == ("credential", "Credential")
    assert classify_capability("Leaked database password in .env") == ("credential", "Credential")
    assert classify_capability("Authentication bypass via JWT none alg") == ("identity", "Privileged access")
    assert classify_capability("Command injection in ping parameter") == ("rce", "Code execution")
    assert classify_capability("Dumped customer records from database") == ("data", "Sensitive data")


def test_extract_targets_from_stringified_args():
    assert extract_targets("{'url': 'https://app.example.com/api/v1/users?id=1'}") == (
        "app.example.com",
        "/api/v1/users",
    )
    assert extract_targets("{'target': 'api.example.com', 'ports': '1-1000'}") == ("api.example.com", None)
    assert extract_targets("") == (None, None)


def test_empty_chain_yields_empty_graph():
    graph = build_attack_graph({"nodes": [], "edges": [], "meta": {}})
    assert graph["nodes"] == []
    assert graph["edges"] == []


def test_recon_noise_is_not_drawn():
    graph = build_attack_graph(_chain(
        _step(1, "informational", "nmap", "{'target': 'app.example.com'}", True,
              [{"type": "actionable", "severity": "medium", "description": "Port 443 open"}]),
    ))
    assert graph["nodes"] == []


def test_credential_reuse_chains_to_data_access():
    graph = build_attack_graph(_chain(
        _step(1, "informational", "http_request", "{'url': 'https://app.example.com/static/main.js'}", True,
              [{"type": "vulnerability", "severity": "high",
                "description": "Hard-coded API key exposed in main.js"}]),
        _step(2, "exploitation", "http_request",
              "{'url': 'https://app.example.com/api/export', 'headers': {'Authorization': 'Bearer abc.def'}}",
              True,
              [{"type": "vulnerability", "severity": "high",
                "description": "Exported customer records from database using leaked key"}]),
    ))

    origin = _by_kind(graph, "origin")
    hosts = _by_kind(graph, "host")
    creds = _by_kind(graph, "credential")
    data = _by_kind(graph, "data")
    actions = _by_kind(graph, "action")
    assert len(origin) == 1 and len(hosts) == 1
    assert len(creds) == 1 and len(data) == 1 and len(actions) == 2

    edges = _edge_set(graph)
    assert ("origin", hosts[0]["id"]) in edges
    # The second action is reached through its endpoint *and* the captured credential.
    assert (creds[0]["id"], actions[1]["id"]) in edges
    assert ("endpoint:app.example.com/api/export", actions[1]["id"]) in edges
    assert creds[0]["title"] == "API key"
    # No dangling endpoints: every endpoint leads somewhere.
    for ep in _by_kind(graph, "endpoint"):
        assert any(e["source"] == ep["id"] for e in graph["edges"])
    assert (actions[1]["id"], data[0]["id"]) in edges

    # Credential was later used in an exploitation step, so it is proven.
    assert creds[0]["status"] == "proven"
    assert actions[0]["status"] == "observed"
    assert actions[1]["status"] == "proven"
    assert graph["meta"]["proven"] == 1
    assert graph["meta"]["capabilities"] == 2


def test_no_auth_material_means_no_invented_chain():
    graph = build_attack_graph(_chain(
        _step(1, "informational", "http_request", "{'url': 'https://app.example.com/.env'}", True,
              [{"type": "vulnerability", "severity": "high", "description": "Leaked database password in .env"}]),
        _step(2, "exploitation", "sqlmap", "{'url': 'https://app.example.com/search'}", True,
              [{"type": "vulnerability", "severity": "critical", "description": "SQL injection in q parameter"}]),
    ))
    cred = _by_kind(graph, "credential")[0]
    sqli = [n for n in _by_kind(graph, "action") if "SQL" in n["title"]][0]
    assert all(e["source"] != cred["id"] for e in graph["edges"] if e["target"] == sqli["id"])
    assert cred["title"] == "Password"
    assert any(e["source"].startswith("endpoint:") and e["target"] == sqli["id"] for e in graph["edges"])


def test_failed_step_is_inferred_and_evidence_is_redacted():
    graph = build_attack_graph(_chain(
        _step(1, "exploitation", "http_request",
              "{'url': 'https://app.example.com/login', 'headers': {'Authorization': 'Bearer s3cr3tvalue'}}",
              False,
              [{"type": "vulnerability", "severity": "high", "description": "Authentication bypass via header"}],
              failures=[{"tool": "http_request", "error": "403", "lesson": ""}]),
    ))
    action = _by_kind(graph, "action")[0]
    assert action["status"] == "inferred"
    assert "s3cr3tvalue" not in action["evidence"]["args"]
    assert graph["meta"]["failed_attempts"] == 1
