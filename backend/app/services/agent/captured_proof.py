"""Controlled capture-to-proof recipes. Verdicts derive from fresh server state."""

import json
import math
import secrets
from copy import deepcopy
from urllib.parse import parse_qsl, quote_plus, unquote, unquote_plus, urlsplit, urlunsplit

from app.services.agent.evidence_store import origin
from app.services.agent.proof_engine import pointer, render

METHODS = {
    "captured_read": ("GET", "POST"),
    "captured_mutation": ("POST", "PATCH", "PUT"),
    "captured_property": ("POST", "PATCH", "PUT"),
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


def bind_captured_object_url(url, object_id, selector=""):
    """Replace one observed path segment or complete query value, preserving the rest."""
    parts = urlsplit(url)
    given_id = str(object_id or "")
    if given_id in (".", "..") or (
        not given_id and not str(selector).startswith("query:")
    ):
        raise ValueError("Select a query field or provide the captured object ID")
    segments = parts.path.split("/")
    candidates = [
        ("path", i)
        for i, value in enumerate(segments)
        if given_id and unquote(value) == given_id
    ]
    fields = (
        [part.partition("=") for part in parts.query.split("&")]
        if parts.query
        else []
    )
    candidates.extend(
        ("query:" + unquote_plus(raw_key), i)
        for i, (raw_key, separator, raw_value) in enumerate(fields)
        if separator
        and unquote_plus(raw_value)
        and (not given_id or unquote_plus(raw_value) == given_id)
    )
    matches = [item for item in candidates if not selector or item[0] == selector]
    if len(matches) != 1:
        raise ValueError(
            "Captured object ID must identify exactly one URL path segment or query value"
        )
    location, index = matches[0]
    if location == "path":
        segments[index] = "{{object_id}}"
        parts = parts._replace(path="/".join(segments))
    else:
        raw_key, _, _ = fields[index]
        fields[index] = (raw_key, "=", "{{object_id}}")
        parts = parts._replace(query="&".join("".join(field) for field in fields))
    return urlunsplit(parts), location


def _json_parts(path):
    if not isinstance(path, str) or not path.startswith("/") or path == "/":
        raise ValueError("Select an existing JSON pointer")
    return [part.replace("~1", "/").replace("~0", "~") for part in path[1:].split("/")]


def _set_json_pointer(document, path, value):
    parts = _json_parts(path)
    current = document
    for part in parts[:-1]:
        current = current[int(part)] if isinstance(current, list) else current[part]
    leaf = parts[-1]
    if isinstance(current, list):
        current[int(leaf)] = value
    else:
        if leaf not in current:
            raise ValueError("Selected JSON field is not present in the capture")
        current[leaf] = value


def _set_form_field(body, field, value, expected_id=None, require_nonempty=False):
    """Replace exactly one raw form value, retaining every other encoded field."""
    if not isinstance(body, str) or not field:
        raise ValueError("Captured form body and field are required")
    segments = body.split("&")
    matches = []
    occurrences = 0
    for index, segment in enumerate(segments):
        key, separator, raw = segment.partition("=")
        if separator and unquote_plus(key) == field:
            occurrences += 1
            decoded = unquote_plus(raw)
            if expected_id is None or decoded == str(expected_id):
                matches.append((index, key, decoded))
    if occurrences != 1 or len(matches) != 1 or (require_nonempty and not matches[0][2]):
        raise ValueError("Selected form field must occur once with the observed object ID")
    index, key, _ = matches[0]
    segments[index] = key + "=" + value
    return "&".join(segments)


def bind_captured_object_body(attack, selector, object_id, body_format):
    """Bind a single observed JSON pointer, GraphQL variable or form field."""
    given_id = str(object_id or "")
    if selector.startswith("form:") and body_format == "form":
        field = selector.removeprefix("form:")
        attack["body"] = _set_form_field(
            attack["body"], field, "{{object_id}}", given_id or None,
            require_nonempty=True,
        )
        return selector
    if selector.startswith("body:/") and body_format == "json":
        path = selector.removeprefix("body:")
    elif selector.startswith("variable:/") and body_format == "json":
        path = "/variables" + selector.removeprefix("variable:")
    else:
        raise ValueError("Object selector does not match the captured body format")
    observed = pointer(attack["body"], path)
    if type(observed) not in (str, int) or str(observed) in ("", ".", ".."):
        raise ValueError("Selected body object ID must be a nonempty string or integer")
    if given_id and str(observed) != given_id:
        raise ValueError("Selected body field does not contain the captured object ID")
    _set_json_pointer(attack["body"], path, "{{object_id}}")
    return selector


def render_captured_body(body, bindings, body_format):
    if body_format != "form":
        return render(body, bindings)
    result = body
    for key, value in bindings.items():
        result = result.replace("{{" + key + "}}", quote_plus(str(value), safe=""))
    if "{{" in result:
        raise ValueError("Unresolved form proof binding")
    return result


def matrix_parameter_for_object(selector):
    if selector.startswith("query:"):
        return selector
    if selector.startswith("form:"):
        return "body:" + selector.removeprefix("form:")
    if selector.startswith("body:/"):
        return "body:" + _json_parts(selector.removeprefix("body:"))[0]
    if selector.startswith("variable:/"):
        return "variable:" + _json_parts(selector.removeprefix("variable:"))[0]
    return ""


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
    selector = str(config.get("object_parameter") or "")
    body_format = capture.get("body_format", "json" if isinstance(attack.get("body"), dict) else "none")
    protocol = capture.get("protocol", "rest")
    if selector.startswith(("body:/", "form:", "variable:/")):
        object_parameter = bind_captured_object_body(attack, selector, object_id, body_format)
    else:
        attack["url"], object_parameter = bind_captured_object_url(
            attack["url"], object_id, selector
        )
    if protocol == "graphql":
        if attack["method"] != "POST" or (
            strategy == "captured_read" and capture.get("graphql_kind") != "query"
        ) or (
            strategy in ("captured_mutation", "captured_property")
            and capture.get("graphql_kind") != "mutation"
        ):
            raise ValueError("GraphQL proof strategy must match the captured query or mutation")
    elif strategy == "captured_read" and attack["method"] == "POST" and config.get("post_read_only") is not True:
        raise ValueError("REST POST read proof requires an explicit post_read_only assertion")
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
    attack_value = None
    if strategy in ("captured_mutation", "captured_property"):
        attack_value_path = config.get("attack_value_path", value_path)
        if strategy == "captured_property":
            value = config.get("attack_value")
            if type(value) not in (bool, int, float) or (
                type(value) is float and not math.isfinite(value)
            ):
                raise ValueError(
                    "Property proofs require a finite numeric or boolean attack_value"
                )
            if value_path == canary_path:
                raise ValueError(
                    "Typed property proof needs a separate string canary property"
                )
            if isinstance(attack["body"], dict) and marker in attack["body"]:
                attack["body"][marker] = "{{nonce}}"
            if body_format == "form" and any(
                key == marker for key, _ in parse_qsl(attack["body"], keep_blank_values=True)
            ):
                attack["body"] = _set_form_field(attack["body"], marker, "{{nonce}}")
        else:
            value = "{{attack_nonce}}"
        if body_format == "form":
            field = (
                attack_value_path.removeprefix("form:")
                if attack_value_path.startswith("form:")
                else field_name(attack_value_path)
            )
            attack["body"] = _set_form_field(attack["body"], field, value)
        elif body_format == "json":
            _set_json_pointer(attack["body"], attack_value_path, value)
        else:
            raise ValueError("Mutation requires a captured JSON or form body")
        attack_value = value
    elif strategy == "captured_delete" and attack.get("body") is not None:
        raise ValueError("Delete captures must have no request body")
    elif strategy == "captured_read" and attack["method"] == "GET" and attack.get("body") is not None:
        raise ValueError("GET read captures must have no request body")
    cleanup = config["cleanup"]
    cleanup["method"] = "DELETE"
    if cleanup.get("body") or cleanup["url"].count("{{object_id}}") != 1:
        raise ValueError("Cleanup must address the fresh controlled object")
    if object_parameter == "path" and cleanup["url"] != attack["url"]:
        raise ValueError("Path-object cleanup must use the captured object URL")
    verify = config["verify"]
    if verify.get("method", "GET").upper() != "GET" or verify.get("body"):
        raise ValueError("Verification must be a read-only GET")
    if strategy != "captured_delete":
        same_url = verify["url"] == attack["url"]
        separate_control = verify["url"].count("{{object_id}}") == 1
        if not (same_url or separate_control):
            raise ValueError("Owner readback must address the fresh controlled object")
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
        "object_parameter": object_parameter,
        "body_format": body_format,
        "protocol": protocol,
        "attack_value": attack_value,
        "attack_value_path": config.get("attack_value_path", value_path),
        "attack_object_path": config.get("attack_object_path", config.get("object_path", "/id")),
        "attack_canary_path": config.get("attack_canary_path", canary_path),
        "owner_identity": owner_identity,
        "target": urlunsplit(urlsplit(capture["request"]["url"])._replace(query="")),
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
            body=render_captured_body(
                spec.get("body"), env,
                plan["body_format"] if spec is plan["attack"] else "json",
            ),
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
            expected = render(plan["attack_value"], bindings)
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
                if (
                    not same_value(pointer(disclosed, plan["attack_object_path"]), victim)
                    or pointer(disclosed, plan["attack_canary_path"]) != bindings["nonce"]
                ):
                    raise ValueError("Attacker response did not identify the fresh owner object")
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
