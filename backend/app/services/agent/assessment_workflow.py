"""Resumable HTTP recipes built from legitimate, captured application actions."""

from __future__ import annotations

import copy
import json
import re
import uuid


_VARIABLE = re.compile(r"\{\{([a-zA-Z0-9_]+)\}\}")


def _resolve(value, variables):
    if isinstance(value, str):
        match = _VARIABLE.fullmatch(value)
        if match:
            if match[1] not in variables:
                raise ValueError(f"Missing workflow variable: {match[1]}")
            return copy.deepcopy(variables[match[1]])

        def replace(match):
            if match[1] not in variables:
                raise ValueError(f"Missing workflow variable: {match[1]}")
            return str(variables[match[1]])

        return _VARIABLE.sub(replace, value)
    if isinstance(value, dict):
        return {k: _resolve(v, variables) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve(v, variables) for v in value]
    return value


async def run_workflow(manager, *, steps=None, workflow_id="", max_steps=6):
    if not workflow_id:
        if not isinstance(steps, list) or not 1 <= len(steps) <= 30:
            raise ValueError("Provide 1–30 captured request steps")
        ids = [s.get("id") for s in steps if isinstance(s, dict)]
        if (
            len(ids) != len(steps)
            or any(not i for i in ids)
            or len(ids) != len(set(ids))
        ):
            raise ValueError("Workflow step IDs must be unique and nonempty")
        workflow_id = uuid.uuid4().hex
        manager._assessment_workflows[workflow_id] = {
            "steps": copy.deepcopy(steps),
            "variables": {},
            "results": {},
            "failed": False,
        }
    state = manager._assessment_workflows.get(workflow_id)
    if state is None:
        raise ValueError("Unknown workflow in this assessment session")
    for step in state["steps"]:
        if step["id"] in state["results"]:
            continue
        if max_steps <= 0:
            break
        if state["failed"] and not step.get("cleanup"):
            state["results"][step["id"]] = {
                "status": "blocked",
                "reason": "Earlier prerequisite failed",
            }
            continue
        max_steps -= 1
        try:
            request = _resolve(step["request"], state["variables"])
            if not request.get("identity"):
                raise ValueError("Every workflow step must name its test identity")
            # Use the public replay path so existing request guardrails still apply.
            result = json.loads(
                await manager.replay_http_request(
                    **request, hypothesis_id=step.get("hypothesis_id", "")
                )
            )
            if result.get("error") or not result.get("evidence_id"):
                raise ValueError(result.get("error") or "No completed request")
            from app.services.agent.evidence_store import evidence_store

            record = evidence_store(manager).records[result["evidence_id"]]
            response = record["payload"]["response"]
            expected = step.get("expect_status", [200])
            if response["status"] not in expected:
                raise ValueError(
                    f"Expected {expected}, observed {response['status']}; evidence_id={result['evidence_id']}"
                )
            if step.get("extract"):
                data = json.loads(response["body"])
                for name, field in step["extract"].items():
                    state["variables"][name] = data[field]
            state["results"][step["id"]] = {
                "status": "completed",
                "evidence_id": result["evidence_id"],
            }
        except Exception as exc:
            state["failed"] = True
            state["results"][step["id"]] = {
                "status": "inconclusive",
                "reason": str(exc)[:400],
            }
    pending = [s["id"] for s in state["steps"] if s["id"] not in state["results"]]
    # Extracted object IDs/tokens remain inside the workflow; never dump state into a prompt.
    return {
        "workflow_id": workflow_id,
        "complete": not pending,
        "failed": state["failed"],
        "pending": pending,
        "results": copy.deepcopy(state["results"]),
    }
