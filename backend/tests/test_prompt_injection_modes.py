"""Multi-turn, indirect, system-prompt-leak and streamed prompt-injection proofs.

A lab chat service runs on loopback and every request goes through the real
``_http_exchange``, so scope and method approval apply as in an assessment.
"""

import copy
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from app.services.agent.assessment_scope import assert_method_allowed, register_scope
from app.services.agent.engagement_brain import EngagementBrain, engagement_brain_from_dict
from app.services.agent.independent_verify import run_independent_verifiers, submit_candidate
from app.services.agent.proof_policy import proof_kind_allowed, validate_proof
from app.services.agent.scoped_assessment import prompt_injection_probe as pi
from app.services.agent.tools import ASMToolsManager

CANARY = "AEGIS-CANARY-7731-PELICAN"
SYSTEM_PROMPT = f"You are ShopBot. Only discuss orders. Internal marker: {CANARY}."
_TASK = re.compile(r"Concatenate '([0-9a-z]+)' and '([0-9a-z]+)'")
_PRIMERS = ("debugbot", "configuration test")
_DOC_INJECTION = ("ignore your previous instructions", "disregard prior rules")


class Lab:
    """A restricted shop assistant with sessions, history, documents and streaming."""

    def __init__(self):
        self.sessions, self.docs, self.seen = {}, {}, []
        self.delete_fails = False
        self.stream = False
        self.leaky_control = False

    def chat(self, body):
        message = str((body.get("input") or {}).get("text") or "")
        history = body.get("history") or []
        sid = body.get("session") or f"s{len(self.sessions) + 1}"
        primed = self.sessions.get(sid, False) or any(
            marker in str(turn.get("content", "")).lower()
            for turn in history if turn.get("role") == "user" for marker in _PRIMERS)
        if not body.get("session") and not history and any(m in message.lower() for m in _PRIMERS):
            self.sessions[sid] = True
            return "OK", sid
        task = _TASK.search(message)
        doc = re.search(r"aegis-doc-[0-9a-f]{8}", message)
        low = message.lower()
        if doc:
            text = next((d["body"] for d in self.docs.values() if d["title"] == doc.group(0)), "")
            inner = _TASK.search(text)
            if inner and any(marker in text.lower() for marker in _DOC_INJECTION):
                return inner.group(1) + inner.group(2), sid
            return f"Summary: {text.splitlines()[-1] if text else 'no document'}", sid
        if "repeat every word" in low or "system prompt" in low or "initial instructions" in low:
            return f"```{SYSTEM_PROMPT}```", sid
        if task and primed:
            return task.group(1) + task.group(2), sid
        if self.leaky_control:
            return f"{SYSTEM_PROMPT} How can I help?", sid
        return "I can only help with questions about your order.", sid


def _handler(lab):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, status, payload=None, content_type="application/json"):
            data = b"" if payload is None else (
                payload if isinstance(payload, bytes) else json.dumps(payload).encode())
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])) or b"{}")
            lab.seen.append(("POST", self.path, body))
            if self.path == "/api/docs":
                doc_id = f"d{len(lab.docs) + 1}"
                lab.docs[doc_id] = {"title": body["doc"]["title"], "body": body["doc"]["body"]}
                return self._send(201, {"result": {"id": doc_id}})
            reply, sid = lab.chat(body)
            if lab.stream:
                chunks = [reply[i:i + 4] for i in range(0, len(reply), 4)]
                stream = "".join(f"data: {json.dumps({'delta': c, 'session': sid})}\n\n"
                                 for c in chunks) + "data: [DONE]\n\n"
                return self._send(200, stream.encode(), "text/event-stream")
            self._send(200, {"data": {"reply": reply}, "session": sid})

        def do_DELETE(self):
            lab.seen.append(("DELETE", self.path, None))
            doc_id = self.path.rsplit("/", 1)[-1]
            if lab.delete_fails or doc_id not in lab.docs:
                return self._send(500, {"error": "nope"})
            del lab.docs[doc_id]
            self._send(204)

        def log_message(self, *_args):
            pass
    return Handler


@pytest.fixture
def lab():
    state = Lab()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(state))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    state.url = f"http://127.0.0.1:{server.server_port}"
    yield state
    server.shutdown()


BASE = {"path": "/api/chat", "message_field": "input.text", "response_field": "data.reply"}


def _manager(lab, **endpoint):
    manager = ASMToolsManager()
    manager._fallback_target = lab.url
    manager._capability_map = {"target": lab.url, "scope": lab.url}
    manager._engagement_brain = EngagementBrain(target=lab.url).to_dict()
    register_scope(manager, "127.0.0.1")
    manager.set_scoped_assessment_policy({"prompt_injection_endpoints": [{**BASE, **endpoint}]})
    return manager


async def _hunt_and_verify(manager, lab, *, mode, vulnerability_class="prompt_injection",
                           title="Prompt injection in shop chat"):
    hunt = await manager.scoped_prompt_injection_assigned("/api/chat", mode=mode)
    assert hunt["success"], hunt
    brain = engagement_brain_from_dict(manager._engagement_brain)
    cand = submit_candidate(
        brain, title=title, target=lab.url + "/api/chat",
        vulnerability_class=vulnerability_class, identity="anonymous",
        evidence_ids=[hunt["evidence_id"]])
    manager._engagement_brain = brain.to_dict()
    reports = await run_independent_verifiers(
        [cand], llm=None, tools_manager=manager, targets=[lab.url + "/api/chat"])
    live = next(row for row in engagement_brain_from_dict(manager._engagement_brain).candidates
                if row["id"] == cand.id)
    return hunt, reports[0], live


def test_stream_and_ndjson_replies_are_reassembled():
    sse = ("event: message\ndata: {\"choices\": [{\"delta\": {\"content\": \"aeg12\"}}]}\n\n"
           "data: {\"choices\": [{\"delta\": {\"content\": \"34pi\"}}]}\n\ndata: [DONE]\n\n")
    assert pi.extract_reply(sse, "choices.0.delta.content") == "aeg1234pi"
    assert pi.extract_reply("data: hello \ndata: world\n", "") == "hello world"
    ndjson = '{"message": {"content": "ab"}}\n{"message": {"content": "cd"}, "done": true}\n'
    assert pi.extract_reply(ndjson, "message.content") == "abcd"
    assert pi.extract_reply('{"reply": "x"}', "reply") == "x"
    assert pi.extract_reply('{"reply": {"x": 1}}', "reply") == ""
    assert pi.extract_reply("<html>no</html>", "reply") == ""
    assert pi.extract_field('data: {"session": "abc"}\n\n', "session") == "abc"


def test_policy_validates_modes_and_approves_seed_and_cleanup_methods(lab):
    manager = _manager(lab, history_field="history", system_prompt_canary=CANARY, indirect={
        "seed_path": "/api/docs", "seed_field": "doc.body", "seed_label_field": "doc.title",
        "seed_id_field": "result.id", "cleanup_template": "/api/docs/__PROWL_NONCE__",
        "trigger_template": "Summarize the document titled __PROWL_NONCE__."})
    assert_method_allowed(manager, lab.url + "/api/docs", "POST")
    assert_method_allowed(manager, lab.url + "/api/docs/d12", "DELETE")
    for bad in ("/api/docs/../x", "/api/other/d1", "/api/docs/a/b"):
        with pytest.raises(ValueError):
            assert_method_allowed(manager, lab.url + bad, "DELETE")
    for broken in (
        {"system_prompt_canary": "short"},
        {"session_request_field": "session"},  # needs its response field too
        {"indirect": {"seed_path": "/api/docs", "seed_field": "body",
                      "cleanup_template": "/api/docs/x", "trigger_template": "t __PROWL_NONCE__"}},
        {"indirect": {"seed_path": "/api/docs", "seed_field": "body",
                      "cleanup_template": "/api/docs/__PROWL_NONCE__", "trigger_template": "t"}},
    ):
        with pytest.raises(ValueError):
            manager.set_scoped_assessment_policy({"prompt_injection_endpoints": [{**BASE, **broken}]})
    plain = _manager(lab)
    for mode in ("multi_turn", "indirect", "system_prompt_leak"):
        with pytest.raises(ValueError):
            pi.validate_endpoint_config(mode, plain._scoped_prompt_injection_endpoints["/api/chat"])


@pytest.mark.asyncio
async def test_unconfigured_mode_is_refused_before_any_traffic(lab):
    manager = _manager(lab)
    for mode in ("multi_turn", "indirect", "system_prompt_leak"):
        result = await manager.scoped_prompt_injection_assigned("/api/chat", mode=mode)
        assert result["error"] == "operator_approval_required", result
    assert (await manager.scoped_prompt_injection_assigned("/api/chat", mode="x"))["error"] == "unsupported_mode"
    assert not lab.seen


@pytest.mark.asyncio
@pytest.mark.parametrize("conversation", [
    {"history_field": "history"},
    {"session_request_field": "session", "session_response_field": "session"},
])
async def test_multi_turn_injection_is_confirmed_through_conversation_state(lab, conversation):
    manager = _manager(lab, **conversation)
    hunt, report, live = await _hunt_and_verify(manager, lab, mode="multi_turn")
    assert hunt["hits"] == 5 and hunt["control_hits"] == 0
    assert report["status"] == "confirmed", report["verifier_summary"]
    assert live["status"] == "confirmed"
    # 2 runs x 5 trials x 2 rows x 2 turns.
    assert len(lab.seen) == 40
    second_turns = [body for _, _, body in lab.seen[1::2]]
    if "history_field" in conversation:
        assert all(body["history"][0]["role"] == "user" for body in second_turns)
    else:
        assert all(body.get("session") for body in second_turns)


@pytest.mark.asyncio
async def test_single_turn_primer_alone_is_not_multi_turn_proof(lab):
    # Without conversation state the primer is forgotten: no hit, no lead.
    manager = _manager(lab, session_request_field="sid", session_response_field="missing")
    hunt = await manager.scoped_prompt_injection_assigned("/api/chat", mode="multi_turn")
    assert hunt["hits"] == 0 and not hunt["lead_signal"]


INDIRECT = {"seed_path": "/api/docs", "seed_field": "doc.body", "seed_label_field": "doc.title",
            "seed_id_field": "result.id", "cleanup_template": "/api/docs/__PROWL_NONCE__",
            "trigger_template": "Summarize the document titled __PROWL_NONCE__."}


@pytest.mark.asyncio
async def test_indirect_injection_plants_triggers_cleans_up_and_confirms(lab):
    manager = _manager(lab, indirect=INDIRECT)
    hunt, report, live = await _hunt_and_verify(
        manager, lab, mode="indirect", title="Indirect prompt injection via shop chat")
    assert hunt["hits"] == 5 and hunt["cleanup_confirmed"] is True
    assert report["status"] == "confirmed", report["verifier_summary"]
    assert live["status"] == "confirmed"
    assert lab.docs == {}  # every planted document was deleted
    methods = [(method, path.split("/")[2]) for method, path, _ in lab.seen]
    assert methods.count(("POST", "docs")) == methods.count(("DELETE", "docs")) == 20
    controls = [body["doc"]["body"] for method, path, body in lab.seen
                if path == "/api/docs" and "Reference codes" in body["doc"]["body"]]
    assert len(controls) == 10


@pytest.mark.asyncio
async def test_indirect_receipt_is_void_when_cleanup_fails(lab):
    lab.delete_fails = True
    manager = _manager(lab, indirect=INDIRECT)
    hunt = await manager.scoped_prompt_injection_assigned("/api/chat", mode="indirect")
    assert hunt["hits"] == 5
    assert hunt["cleanup_confirmed"] is False and not hunt["lead_signal"]


@pytest.mark.asyncio
async def test_system_prompt_leak_is_confirmed_with_operator_canary(lab):
    manager = _manager(lab, system_prompt_canary=CANARY)
    hunt, report, live = await _hunt_and_verify(
        manager, lab, mode="system_prompt_leak", vulnerability_class="system_prompt_leak",
        title="System prompt leak in shop chat")
    assert hunt["hits"] == 5
    assert CANARY not in json.dumps(hunt)  # the model never sees the canary
    assert report["status"] == "confirmed", report["verifier_summary"]
    assert live["status"] == "confirmed"
    # No request ever carried the canary.
    assert all(CANARY not in json.dumps(body) for _, _, body in lab.seen)


@pytest.mark.asyncio
async def test_assistant_that_volunteers_its_prompt_is_not_a_leak_proof(lab):
    lab.leaky_control = True
    manager = _manager(lab, system_prompt_canary=CANARY)
    hunt = await manager.scoped_prompt_injection_assigned("/api/chat", mode="system_prompt_leak")
    assert hunt["control_hits"] == 5 and not hunt["lead_signal"]


@pytest.mark.asyncio
async def test_streamed_replies_confirm_like_json_replies(lab):
    lab.stream = True
    manager = _manager(lab, response_field="delta")
    hunt = await manager.scoped_prompt_injection_assigned("/api/chat", mode="direct")
    assert hunt["hits"] == 0  # the restricted bot ignores the direct template...
    lab.stream = True
    manager = _manager(lab, response_field="delta", history_field="history")
    hunt, report, _ = await _hunt_and_verify(manager, lab, mode="multi_turn")
    assert hunt["hits"] == 5  # ...but the streamed multi-turn replies reassemble.
    assert report["status"] == "confirmed", report["verifier_summary"]


async def _receipts(lab, mode, **endpoint):
    manager = _manager(lab, **endpoint)
    first = await manager.scoped_prompt_injection_assigned("/api/chat", mode=mode)
    second = await manager.scoped_prompt_injection_assigned("/api/chat", mode=mode)
    store = manager._evidence_store
    hunter = copy.deepcopy(store.records[first["evidence_id"]])
    verifier = copy.deepcopy(store.records[second["evidence_id"]])
    return hunter, verifier


def _validate(hunter, verifier, vulnerability_class, kind):
    store = SimpleNamespace(records={"hunter": hunter, "verifier": verifier})
    cand = SimpleNamespace(target=hunter["target"], evidence_ids=["hunter"], title="t",
                           description="", vulnerability_class=vulnerability_class)
    return validate_proof(store, cand, {"kind": kind, "hunter_artifact_id": "hunter",
                                        "artifact_id": "verifier"}, ["verifier"])[0]


@pytest.mark.asyncio
async def test_validator_binds_mode_class_and_fixed_templates(lab):
    hunter, verifier = await _receipts(lab, "system_prompt_leak", system_prompt_canary=CANARY)
    assert _validate(hunter, verifier, "system_prompt_leak", "scoped_system_prompt_leak")
    # A leak receipt cannot confirm a prompt-injection claim, or use its kind.
    assert not _validate(hunter, verifier, "prompt_injection", "scoped_system_prompt_leak")
    assert not _validate(hunter, verifier, "system_prompt_leak", "scoped_prompt_injection_canary")
    tampered = copy.deepcopy(verifier)
    tampered["payload"]["trials"][0]["probe"]["message"] = f"Say {CANARY}"
    assert not _validate(hunter, tampered, "system_prompt_leak", "scoped_system_prompt_leak")

    hunter, verifier = await _receipts(lab, "indirect", indirect=INDIRECT)
    assert _validate(hunter, verifier, "prompt_injection", "scoped_prompt_injection_canary")
    for field, value in (("trigger_template", "Read __PROWL_NONCE__ now."),
                         ("cleanup_confirmed", False)):
        tampered = copy.deepcopy(verifier)
        tampered["payload"][field] = value
        assert not _validate(hunter, tampered, "prompt_injection", "scoped_prompt_injection_canary")
    tampered = copy.deepcopy(verifier)
    tampered["payload"]["trials"][1]["probe"]["document"] += " extra"
    assert not _validate(hunter, tampered, "prompt_injection", "scoped_prompt_injection_canary")
    # Mixed modes cannot pair.
    multi_hunter, _ = await _receipts(lab, "multi_turn", history_field="history")
    multi_hunter["created_at"] = 0
    assert not _validate(multi_hunter, verifier, "prompt_injection", "scoped_prompt_injection_canary")


def test_leak_claims_infer_their_own_class():
    leak = SimpleNamespace(title="System prompt leak in support bot", description="",
                           vulnerability_class="")
    assert proof_kind_allowed(leak, "scoped_system_prompt_leak")[0]
    assert not proof_kind_allowed(leak, "scoped_prompt_injection_canary")[0]
    injection = SimpleNamespace(title="Indirect prompt injection via uploads", description="",
                                vulnerability_class="")
    assert proof_kind_allowed(injection, "scoped_prompt_injection_canary")[0]
