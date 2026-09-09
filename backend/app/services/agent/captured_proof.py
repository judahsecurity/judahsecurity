"""Controlled capture-to-proof recipes. Verdicts derive from fresh server state."""

import json
import math
import secrets
from copy import deepcopy
from urllib.parse import unquote, urlsplit, urlunsplit

from app.services.agent.evidence_store import origin
from app.services.agent.proof_engine import pointer, render

METHODS = {
    "captured_read": ("GET",),
    "captured_mutation": ("PATCH", "PUT"),
    "captured_property": ("PATCH", "PUT"),
    "captured_delete": ("DELETE",),
}


def field_name(path):
    if (
        not isinstance(path, str)
        or not path.startswith("/")
        or "/" in path[1:]
        or len(path) < 2
    ):
        raise ValueError("Stage 1 requires a top-level JSON property pointer")
    return path[1:].replace("~1", "/").replace("~0", "~")


def build_plan(capture, *, owner_identity, object_id, configuration):
    config = deepcopy(configuration)
    strategy = config["strategy"]
    attack = deepcopy(capture["request"])
    if strategy not in METHODS or attack["method"] not in METHODS[strategy]:
        raise ValueError("Capture method does not match the selected strategy")
    if capture["identity"] != owner_identity or owner_identity in (
        "anonymous",
        "legacy",
    ):
        raise ValueError("Capture must belong to the registered owner identity")
    parts = urlsplit(attack["url"])
    segments = parts.path.split("/")
    matches = [
        i for i, value in enumerate(segments) if unquote(value) == str(object_id)
    ]
    if len(matches) != 1 or not str(object_id) or str(object_id) in (".", ".."):
        raise ValueError(
            "Captured object ID must occupy exactly one complete URL path segment"
        )
    segments[matches[0]] = "{{object_id}}"
    attack["url"] = urlunsplit(parts._replace(path="/".join(segments)))
    canary_path = config.get("canary_path", "/marker")
    marker = field_name(canary_path)
    setup = config["setup"]
    if setup.get("method", "POST").upper() != "POST" or not isinstance(
        setup.get("body"), dict
    ):
        raise ValueError("Setup must POST a fresh disposable JSON object")
    setup["method"] = "POST"
    setup["body"][marker] = "{{nonce}}"
    if "{{object_id}}" in json.dumps(setup):
        raise ValueError("Setup cannot depend on a pre-existing object ID")
    value_path = config.get("value_path", canary_path)
    value_field = field_name(value_path)
    if strategy in ("captured_mutation", "captured_property"):
        if not isinstance(attack["body"], dict) or value_field not in attack["body"]:
            raise ValueError(
                "Selected mutation property must exist in the captured JSON body"
            )
        if strategy == "captured_property":
            value = config.get("attack_value")
            if type(value) not in (bool, int, float) or (
                type(value) is float and not math.isfinite(value)
            ):
                raise ValueError(
                    "Property proofs require a finite numeric or boolean attack_value"
                )
            if value_field == marker:
                raise ValueError(
                    "Typed property proof needs a separate string canary property"
                )
            if marker in attack["body"]:
                attack["body"][marker] = "{{nonce}}"
        else:
            value = "{{attack_nonce}}"
        attack["body"][value_field] = value
    elif attack.get("body") is not None:
        raise ValueError("Read/delete captures must have no request body")
    cleanup = config["cleanup"]
    cleanup["method"] = "DELETE"
    if cleanup["url"] != attack["url"] or cleanup.get("body"):
        raise ValueError("Cleanup must delete the same fresh controlled-object URL")
    verify = config["verify"]
    if verify.get("method", "GET").upper() != "GET" or verify.get("body"):
        raise ValueError("Verification must be a read-only GET")
    if strategy != "captured_delete" and verify["url"] != attack["url"]:
        raise ValueError("Owner readback must address the same controlled object")
    for spec in (setup, verify, cleanup):
        if origin(spec["url"]) != origin(attack["url"]):
            raise ValueError("Every recipe step must stay on the capture origin")
    if strategy == "captured_delete" and "{{" in verify["url"]:
        raise ValueError("Delete verification requires a stable owner inventory URL")
    # User-supplied templates cannot inject a proof nonce into a readback.
    for spec in (verify, cleanup):
        if any(
            binding in json.dumps(spec) for binding in ("{{nonce}}", "{{attack_nonce}}")
        ):
            raise ValueError("Verification/cleanup cannot receive a canary")
    return {
        "strategy": strategy,
        "capture_id": capture["id"],
        "controlled_resource": True,
        "owner_identity": owner_identity,
        "target": capture["request"]["url"],
        "operation_id": capture["operation_id"],
        "setup": setup,
        "attack": attack,
        "verify": verify,
        "cleanup": cleanup,
        "object_path": config.get("object_path", "/id"),
        "canary_path": canary_path,
        "value_path": value_path,
        "inventory_path": config.get("inventory_path", "/items"),
    }


def same_value(a, b):
    # Python considers True == 1. Evidence must preserve JSON scalar types.
    return type(a) is type(b) and a == b


async def run_captured(engine, plan, cell, *, execute, registry):
    owner, attacker = plan["owner_identity"], cell["identity"]
    strategy = plan["strategy"]
    if cell["expected"] != "deny" or not plan.get("controlled_resource"):
        raise ValueError(
            "Controlled-resource proof requires an explicit deny expectation"
        )
    if owner in (attacker, "anonymous"):
        raise ValueError("Owner and attacker must be distinct")
    sessions = {
        name: registry.resolve(name, plan["target"]) for name in (owner, attacker)
    }
    principals = [
        s.get("identity_check", {}).get("expected") for s in sessions.values()
    ]
    if any(
        name != "anonymous"
        and (not s.get("authenticated") or not s.get("identity_check"))
        for name, s in sessions.items()
    ) or (attacker != "anonymous" and principals[0] == principals[1]):
        return engine._receipt(
            cell,
            strategy,
            "blocked",
            "Distinct verified identities are required",
            [],
            "",
        )
    ids, cleanup_ids, created = [], [], []
    bindings = {"nonce": secrets.token_hex(16), "attack_nonce": secrets.token_hex(16)}
    attack_url = ""
    cleanup_status = "not_needed"
    uncertain_creation = False
    verdict, reason = "inconclusive", "Proof did not complete"
    object_path, marker_path, value_path = (
        plan["object_path"],
        plan["canary_path"],
        plan["value_path"],
    )

    async def exchange(spec, identity, env, *, cleanup=False):
        url = render(spec["url"], env, url=True)
        if origin(url) != origin(plan["target"]):
            raise ValueError("Proof step left capture origin")
        response = await execute(
            method=spec.get("method", "GET"),
            url=url,
            headers=render(spec.get("headers", {}), env),
            body=render(spec.get("body"), env),
            identity=identity,
            hypothesis_id=cell["hypothesis_id"],
            follow_redirects=False,
        )
        eid = response.get("evidence_id")
        if not eid or eid not in engine.store.records:
            raise ValueError("Proof requires an execution-owned transport artifact")
        (cleanup_ids if cleanup else ids).append(eid)
        return response

    def document(response, *, successful=True):
        if successful and not 200 <= response["response"]["status"] < 300:
            raise ValueError("Control/readback request failed")
        try:
            return json.loads(response["_body_text"])
        except (ValueError, KeyError, TypeError):
            raise ValueError("Control/readback requires structured JSON") from None

    def identified(doc, object_id, marker):
        if (
            not same_value(pointer(doc, object_path), object_id)
            or pointer(doc, marker_path) != marker
        ):
            raise ValueError("Readback does not identify the fresh controlled object")

    async def create(identity, marker):
        nonlocal uncertain_creation
        env = {**bindings, "nonce": marker}
        uncertain_creation = True
        response = await exchange(plan["setup"], identity, env)
        doc = document(response)
        oid = pointer(doc, object_path)
        if type(oid) not in (str, int) or str(oid) in ("", ".", ".."):
            raise ValueError("Setup did not identify a disposable object")
        # Keep cleanup obligations even if subsequent canary validation fails.
        created.append((identity, {**env, "object_id": oid}))
        uncertain_creation = False
        identified(doc, oid, marker)
        return oid

    def inventory(doc):
        rows = pointer(doc, plan["inventory_path"])
        if not isinstance(rows, list):
            raise TypeError("Delete verification requires an owner JSON inventory")
        result = {}
        for row in rows:
            key = json.dumps(pointer(row, object_path))
            if key in result:
                raise ValueError("Owner inventory has duplicate object IDs")
            result[key] = row
        return result

    try:
        victim = await create(owner, bindings["nonce"])
        bindings["object_id"] = victim
        attack_url = render(plan["attack"]["url"], bindings, url=True)
        if strategy == "captured_delete":
            survivor_marker = secrets.token_hex(16)
            survivor = await create(owner, survivor_marker)
            if same_value(victim, survivor):
                raise ValueError("Setup reused an existing object")
            before = inventory(
                document(await exchange(plan["verify"], owner, bindings))
            )
            victim_key, survivor_key = json.dumps(victim), json.dumps(survivor)
            identified(before[victim_key], victim, bindings["nonce"])
            identified(before[survivor_key], survivor, survivor_marker)
        else:
            before = document(await exchange(plan["verify"], owner, bindings))
            identified(before, victim, bindings["nonce"])
        if strategy == "captured_read":
            if attacker == "anonymous":
                raise ValueError(
                    "Stage 1 read proof needs an authenticated attacker-owned control"
                )
            control_marker = secrets.token_hex(16)
            control_id = await create(attacker, control_marker)
            control_env = {**bindings, "object_id": control_id}
            control = document(await exchange(plan["verify"], attacker, control_env))
            identified(control, control_id, control_marker)
            if same_value(control_id, victim) or bindings["nonce"] in json.dumps(
                control
            ):
                raise ValueError("Attacker control is not a distinct object")
        if strategy in ("captured_mutation", "captured_property"):
            expected = render(plan["attack"]["body"], bindings)[field_name(value_path)]
            prior = pointer(before, value_path)
            if same_value(prior, expected):
                raise ValueError("Selected property already has the attack value")
        attack_response = await exchange(plan["attack"], attacker, bindings)
        after_doc = document(await exchange(plan["verify"], owner, bindings))
        # Expiration can masquerade as denial or misattribute anonymous access.
        # Recheck both identities using their registered principal endpoints.
        for name in (owner, attacker):
            if name == "anonymous":
                continue
            check = sessions[name]["identity_check"]
            me = document(await exchange({"url": check["url"]}, name, bindings))
            if not same_value(me[check["field"]], check["expected"]):
                raise ValueError("Registered identity changed during proof")
        if strategy == "captured_delete":
            after = inventory(after_doc)
            identified(after[survivor_key], survivor, survivor_marker)
            if victim_key not in after and set(before) - set(after) == {victim_key}:
                verdict, reason = (
                    "confirmed",
                    "Only the fresh victim disappeared from the owner inventory; survivor remains",
                )
            elif victim_key in after and before == after:
                verdict, reason = (
                    "refuted",
                    "Owner inventory and controlled victim are unchanged",
                )
            else:
                reason = "Inventory changed beyond the expected controlled deletion"
        elif strategy == "captured_read":
            identified(after_doc, victim, bindings["nonce"])
            try:
                disclosed = document(attack_response, successful=False)
                identified(disclosed, victim, bindings["nonce"])
                verdict, reason = (
                    "confirmed",
                    "Attacker read the fresh owner-only canary and object ID",
                )
            except (ValueError, KeyError, TypeError, IndexError):
                reason = "Owner-only canary was not observed; this does not prove the access policy safe"
        else:
            # A string mutation may intentionally replace the canary field.
            marker = expected if value_path == marker_path else bindings["nonce"]
            if not same_value(pointer(after_doc, object_path), victim):
                raise ValueError("Owner readback refers to another object")
            actual = pointer(after_doc, value_path)
            if same_value(actual, expected):
                identified(after_doc, victim, marker)
                verdict, reason = (
                    "confirmed",
                    "Owner readback proves the selected unauthorized property change",
                )
            elif same_value(actual, prior):
                identified(after_doc, victim, bindings["nonce"])
                verdict, reason = (
                    "refuted",
                    "Owner readback proves the selected property remained unchanged",
                )
            else:
                reason = "Readback differs without the expected typed property value"
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        verdict, reason = "inconclusive", str(exc)
    except Exception:  # noqa: BLE001 - transport failures must settle as inconclusive
        verdict, reason = "inconclusive", "Transport failed; proof did not complete"
    finally:
        cleanup_status = (
            "needs_follow_up"
            if uncertain_creation
            else "attempted"
            if created
            else "not_needed"
        )
        for identity, env in reversed(created):
            try:
                response = await exchange(plan["cleanup"], identity, env, cleanup=True)
                if response["response"]["status"] not in (200, 202, 204, 404, 410):
                    cleanup_status = "needs_follow_up"
            except Exception:  # noqa: BLE001 - retain cleanup obligations on any transport error
                cleanup_status = "needs_follow_up"
    return engine._receipt(
        cell,
        strategy,
        verdict,
        reason,
        ids,
        secrets.token_hex(16),
        plan["target"],
        attack_url,
        capture_id=plan["capture_id"],
        cleanup_status=cleanup_status,
        cleanup_evidence_ids=tuple(cleanup_ids),
    )
