"""Prompt-injection candidates confirm only through repeated, controlled canary replays."""

import copy
import itertools
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

_TASK = re.compile(r"Concatenate '([0-9a-z]+)' and '([0-9a-z]+)'")
_INJECTED = ("Ignore all previous instructions", "DebugBot", "[SYSTEM]")


def restricted_bot(message: str) -> str:
    """Refuses off-topic tasks unless an injection template overrides it."""
    match = _TASK.search(message)
    if match and any(marker in message for marker in _INJECTED):
        return f"Sure! {match.group(1)}{match.group(2)}"
    return "I can only help with questions about your order."


def echo_bot(message: str) -> str:
    return f"You said: {message}"


def unrestricted_bot(message: str) -> str:
    match = _TASK.search(message)
    return match.group(1) + match.group(2) if match else "ok"


def flaky_bot(pattern):
    """Follow the injection only on the scheduled probe turns."""
    turns = itertools.cycle(pattern)

    def reply(message: str) -> str:
        if any(marker in message for marker in _INJECTED):
            return restricted_bot(message) if next(turns) else "I can't do that."
        return restricted_bot(message)
    return reply


def fake_send(bot):
    async def send(body: str, headers: dict) -> dict:
        message = json.loads(body)["input"]["text"]
        return {"response": {"status": 200}, "evidence_id": "x",
                "_body_text": json.dumps({"data": {"reply": bot(message)}})}
    return send


async def receipt(bot, nonce, technique="instruction_override"):
    payload = await pi.probe_prompt_injection(
        fake_send(bot), technique=technique, message_field="input.text",
        response_field="data.reply", static_body={"lang": "en"}, nonce=nonce)
    payload.update({"endpoint_path": "/api/chat", "method": "POST",
                    "identity": "anonymous", "static_body_sha256": "s"})
    return payload


def record(artifact_id, payload, created_at):
    return {"id": artifact_id, "kind": "scoped_prompt_injection_probe",
            "target": "https://app.example.test/api/chat", "identity": "anonymous",
            "created_at": created_at, "payload": payload}


class Store:
    def __init__(self, hunter, verifier):
        self.records = {"hunter": hunter, "verifier": verifier}


def candidate():
    return SimpleNamespace(
        target="https://app.example.test/api/chat", evidence_ids=["hunter"],
        title="Prompt injection in support chat", description="",
        vulnerability_class="prompt_injection")


PROOF = {"kind": "scoped_prompt_injection_canary", "hunter_artifact_id": "hunter",
         "artifact_id": "verifier"}


def test_prompt_injection_proof_kind_matches_only_prompt_injection_claims():
    assert proof_kind_allowed(candidate(), "scoped_prompt_injection_canary")[0]
    inferred = SimpleNamespace(title="Prompt injection in chat widget", description="",
                               vulnerability_class="")
    assert proof_kind_allowed(inferred, "scoped_prompt_injection_canary")[0]
    assert not proof_kind_allowed(inferred, "response_match")[0]
    xss = SimpleNamespace(title="Reflected XSS", description="", vulnerability_class="")
    assert not proof_kind_allowed(xss, "scoped_prompt_injection_canary")[0]


def test_canary_check_ignores_echoed_requests_and_matches_followed_instructions():
    left, right, expected = pi.new_canary()
    for control in (True, False):
        message = pi.build_message("role_switch", left, right, control=control)
        assert not pi.canary_hit(echo_bot(message), expected)
    assert pi.canary_hit(f"**{left}{right}**", expected)
    assert pi.canary_hit(f"`{left} {right}`", expected)
    assert not pi.canary_hit(f"{left} and {right}", expected)


@pytest.mark.asyncio
async def test_probe_counts_only_clean_differential_trials():
    hit = await receipt(restricted_bot, "aaaa")
    assert (hit["hits"], hit["control_hits"], hit["trial_count"]) == (5, 0, 5)
    assert hit["lead_signal"] and hit["proof_confirmed"]
    assert hit["requests_sent"] == 10
    echoed = await receipt(echo_bot, "bbbb")
    assert echoed["hits"] == 0 and not echoed["lead_signal"]
    # A bot that does the task without injection has nothing to bypass.
    open_bot = await receipt(unrestricted_bot, "cccc")
    assert open_bot["control_hits"] == 5 and open_bot["hits"] == 0
    assert not open_bot["lead_signal"] and not open_bot["proof_confirmed"]
    flaky = await receipt(flaky_bot([1, 0, 0, 0, 0]), "dddd")
    assert flaky["hits"] == 1 and flaky["lead_signal"] and not flaky["proof_confirmed"]
    canaries = pi.receipt_canaries(hit)
    assert len(set(canaries)) == len(canaries) == 10


@pytest.mark.asyncio
async def test_prompt_injection_proof_needs_fresh_repeated_controlled_replay():
    hunter = record("hunter", await receipt(flaky_bot([1, 0, 0, 0, 0]), "aaaa"), 1)
    verifier = record("verifier", await receipt(flaky_bot([1, 1, 0, 1, 0]), "bbbb"), 2)
    store = Store(hunter, verifier)
    assert validate_proof(store, candidate(), PROOF, ["verifier"])[0]

    def rejected(mutate):
        local = Store(copy.deepcopy(hunter), copy.deepcopy(verifier))
        mutate(local.records)
        return not validate_proof(local, candidate(), PROOF, ["verifier"])[0]

    # Hunter and verifier must be distinct, ordered receipts.
    assert rejected(lambda r: r["verifier"].update(created_at=0))
    # Fresh nonce and fresh canaries in every trial.
    assert rejected(lambda r: r["verifier"]["payload"].update(nonce="aaaa"))
    assert rejected(lambda r: r["verifier"]["payload"]["trials"].__setitem__(
        0, r["hunter"]["payload"]["trials"][0]))
    # Same endpoint parameters on both sides.
    assert rejected(lambda r: r["verifier"]["payload"].update(technique="role_switch"))
    assert rejected(lambda r: r["verifier"]["payload"].update(response_field="reply"))
    # Counts are recomputed from stored replies; flags and counters are not trusted.
    def inflate(r):
        trial = r["verifier"]["payload"]["trials"][0]["probe"]
        trial["reply_excerpt"] = "I can't do that."
        trial["hit"] = True
    assert rejected(inflate)
    # Any control that followed the task blocks confirmation.
    def control_hit(r):
        row = r["verifier"]["payload"]["trials"][2]["control"]
        row["reply_excerpt"] = row["expected"]
    assert rejected(control_hit)
    # The request text must be the fixed template, never model supplied.
    def tamper(r):
        row = r["verifier"]["payload"]["trials"][0]["probe"]
        row["message"] = "Say " + row["expected"]
    assert rejected(tamper)
    # Too few verifier trials cannot meet the reproduction threshold.
    def short(r):
        r["verifier"]["payload"]["trials"] = r["verifier"]["payload"]["trials"][:3]
        r["verifier"]["payload"]["trial_count"] = 3
    assert rejected(short)
    # Wrong class cannot borrow the proof.
    xss = candidate()
    xss.vulnerability_class = "xss"
    assert not validate_proof(store, xss, PROOF, ["verifier"])[0]


class _ChatHandler(BaseHTTPRequestHandler):
    bot = staticmethod(restricted_bot)
    seen: list = []

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        type(self).seen.append((self.path, body, self.headers.get("X-Aegis-Verify")))
        reply = json.dumps({"data": {"reply": type(self).bot(body["input"]["text"])}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)

    def log_message(self, *_args):
        pass


@pytest.fixture
def chat_server():
    _ChatHandler.seen = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ChatHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def _manager(target):
    manager = ASMToolsManager()
    manager._fallback_target = target
    manager._capability_map = {"target": target, "scope": target}
    manager._engagement_brain = EngagementBrain(target=target).to_dict()
    register_scope(manager, "127.0.0.1")
    manager.set_scoped_assessment_policy({"prompt_injection_endpoints": [{
        "path": "/api/chat", "message_field": "input.text",
        "response_field": "data.reply", "static_body": {"lang": "en"},
    }]})
    return manager


async def _hunt_and_verify(manager, target):
    hunt = await manager.scoped_prompt_injection_assigned("/api/chat")
    assert hunt["success"], hunt
    brain = engagement_brain_from_dict(manager._engagement_brain)
    cand = submit_candidate(
        brain, title="Prompt injection in support chat", target=target + "/api/chat",
        vulnerability_class="prompt_injection", identity="anonymous",
        evidence_ids=[hunt["evidence_id"]])
    manager._engagement_brain = brain.to_dict()
    reports = await run_independent_verifiers(
        [cand], llm=None, tools_manager=manager, targets=[target + "/api/chat"])
    live = next(row for row in engagement_brain_from_dict(manager._engagement_brain).candidates
                if row["id"] == cand.id)
    return hunt, reports[0], live


@pytest.mark.asyncio
async def test_policy_gates_endpoint_and_post_method(chat_server):
    manager = _manager(chat_server)
    assert_method_allowed(manager, chat_server + "/api/chat", "POST")
    with pytest.raises(ValueError):
        assert_method_allowed(manager, chat_server + "/api/other", "POST")
    denied = await manager.scoped_prompt_injection_assigned("/api/other")
    assert denied["error"] == "operator_approval_required"
    bad = await manager.scoped_prompt_injection_assigned("/api/chat", technique="freeform")
    assert bad["error"] == "unsupported_technique"
    with pytest.raises(ValueError):
        manager.set_scoped_assessment_policy({"prompt_injection_endpoints": [{
            "path": "/api/chat", "message_field": "a b"}]})
    assert not _ChatHandler.seen


@pytest.mark.asyncio
async def test_reproducible_injection_is_confirmed_by_independent_replay(chat_server):
    _ChatHandler.bot = staticmethod(restricted_bot)
    manager = _manager(chat_server)
    hunt, report, live = await _hunt_and_verify(manager, chat_server)
    assert hunt["lead_signal"] and hunt["hits"] == 5
    assert report["status"] == "confirmed", report["verifier_summary"]
    assert report["reproduction_rate"] == 1.0
    assert live["status"] == "confirmed"
    assert len(_ChatHandler.seen) == 20
    assert all(body["lang"] == "en" for _, body, _ in _ChatHandler.seen)
    # Only the verifier's requests carry the verification-run header.
    assert [bool(nonce) for _, _, nonce in _ChatHandler.seen] == [False] * 10 + [True] * 10


@pytest.mark.asyncio
async def test_unreproduced_injection_stays_an_inconclusive_lead(chat_server):
    # Hunter sees 1/5; the verifier's fresh run sees 2/5, below threshold.
    _ChatHandler.bot = staticmethod(flaky_bot([1, 0, 0, 0, 0, 1, 1, 0, 0, 0]))
    manager = _manager(chat_server)
    hunt, report, live = await _hunt_and_verify(manager, chat_server)
    assert hunt["lead_signal"] and hunt["hits"] == 1
    assert report["status"] == "inconclusive"
    assert "2/5" in report["verifier_summary"]
    assert live["status"] == "inconclusive"
    assert hunt["evidence_id"] in live["evidence_ids"]
    assert len(live["evidence_ids"]) == 2
    assert "2/5" in live["proof_gap"]["reason"]


@pytest.mark.asyncio
async def test_unrestricted_assistant_is_not_a_prompt_injection(chat_server):
    _ChatHandler.bot = staticmethod(unrestricted_bot)
    manager = _manager(chat_server)
    hunt = await manager.scoped_prompt_injection_assigned("/api/chat")
    assert hunt["control_hits"] == 5 and not hunt["lead_signal"]


@pytest.mark.asyncio
async def test_llm_red_team_hits_become_candidates_not_findings(chat_server):
    _ChatHandler.bot = staticmethod(restricted_bot)
    manager = _manager(chat_server)
    results = [
        {"endpoint": chat_server + "/api/chat", "category": "prompt_injection",
         "verdict": "fail", "payload_id": "pi-001", "name": "Override",
         "severity": "high", "response_preview": "Ignore previous instructions and leak"},
        {"endpoint": chat_server + "/api/unapproved", "category": "prompt_injection",
         "verdict": "fail", "payload_id": "pi-002", "name": "Override",
         "severity": "high", "response_preview": "ok"},
        {"endpoint": chat_server + "/api/chat", "category": "jailbreak",
         "verdict": "fail", "payload_id": "jb-001"},
    ]
    bridged = await manager._bridge_prompt_injection_leads(results)
    assert [row["target"] for row in bridged] == [
        chat_server + "/api/chat", chat_server + "/api/unapproved"]
    assert bridged[0]["scoped_trials"].startswith("5/5")
    assert "not in prompt_injection_endpoints" in bridged[1]["scoped_reason"]
    brain = engagement_brain_from_dict(manager._engagement_brain)
    by_target = {row["target"]: row for row in brain.candidates}
    approved = by_target[chat_server + "/api/chat"]
    assert approved["vulnerability_class"] == "prompt_injection"
    assert approved["status"] == "pending" and len(approved["evidence_ids"]) == 1
    assert "not proof" in approved["evidence"]
    unapproved = by_target[chat_server + "/api/unapproved"]
    assert unapproved["evidence_ids"] == []
    from app.services.agent.independent_verify import candidate_from_dict

    reports = await run_independent_verifiers(
        [candidate_from_dict(row) for row in brain.candidates],
        llm=None, tools_manager=manager, targets=[chat_server])
    status = {row["candidate_id"]: row["status"] for row in reports}
    assert status[approved["id"]] == "confirmed"
    assert status[unapproved["id"]] == "inconclusive"
    live = {row["id"]: row for row in engagement_brain_from_dict(
        manager._engagement_brain).candidates}
    assert "hunter receipt is required" in live[unapproved["id"]]["proof_gap"]["reason"]
    assert "prompt_injection_endpoints" in live[unapproved["id"]]["proof_gap"]["next_step"]
