"""Run deterministic PyRIT attacks against one approved chat endpoint.

This script runs under PyRIT's own interpreter (its openai pin conflicts with
garak's), so it imports nothing from the platform. It reads a JSON spec, runs
each case turn by turn with PromptSendingAttack, carrying the conversation
through the endpoint's session or history field, scores the last reply with a
SubStringScorer on the case's canary, and writes normalized JSON:

    {"tool": "pyrit", "pyrit_version": ..., "endpoint": url,
     "results": [{"id", "mode", "turns", "responses", "success", "error"}]}

Results are leads. The platform's scoped verifier decides confirmation.

Usage: python pyrit_runner.py SPEC.json OUT.json
"""

from __future__ import annotations

import asyncio
import json
import sys
from urllib.parse import urlsplit


def _raw_request(url: str, body: dict, headers: dict) -> str:
    parts = urlsplit(url)
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    lines = [f"POST {path} HTTP/1.1", f"Host: {parts.netloc}",
             "Content-Type: application/json"]
    lines += [f"{key}: {value}" for key, value in (headers or {}).items()
              if key.lower() not in {"host", "content-type", "content-length"}]
    return "\r\n".join(lines) + "\r\n\r\n" + json.dumps(body)


def _set(body: dict, path: str, value) -> None:
    keys = path.split(".")
    cursor = body
    for key in keys[:-1]:
        cursor = cursor.setdefault(key, {})
    cursor[keys[-1]] = value


def _field(text: str, path: str) -> str:
    try:
        data = json.loads(text or "")
    except ValueError:
        return ""
    for key in path.split("."):
        if isinstance(data, list) and key.isdigit() and int(key) < len(data):
            data = data[int(key)]
        elif isinstance(data, dict) and key in data:
            data = data[key]
        else:
            return ""
    return data if isinstance(data, (str, int)) and not isinstance(data, bool) else ""


async def run(spec: dict) -> dict:
    import pyrit
    from pyrit.executor.attack import AttackScoringConfig, PromptSendingAttack
    from pyrit.prompt_target import HTTPTarget
    from pyrit.score import SubStringScorer
    from pyrit.setup import initialize_pyrit_async

    await initialize_pyrit_async("InMemory", silent=True, load_defaults=False)
    url = spec["url"]
    response_field = spec.get("response_field") or ""

    def target_for(body: dict, raw: list) -> HTTPTarget:
        def callback(response) -> str:
            raw.append(response.text)
            return str(_field(response.text, response_field)) if response_field else response.text
        return HTTPTarget(
            http_request=_raw_request(url, body, spec.get("headers") or {}),
            prompt_regex_string="{PROMPT}", use_tls=url.startswith("https://"),
            callback_function=callback,
            max_requests_per_minute=int(spec.get("max_requests_per_minute") or 30),
            follow_redirects=False, **({"proxy": spec["proxy"]} if spec.get("proxy") else {}),
        )

    results = []
    for case in spec.get("cases") or []:
        turns = [str(turn) for turn in case.get("turns") or []][:6]
        row = {"id": case.get("id"), "mode": case.get("mode", "direct"), "turns": turns,
               "canary": case["canary"], "responses": [], "success": False, "error": ""}
        history, session = [], ""
        try:
            # HTTPTarget has no native conversation state, so each turn is one
            # PromptSendingAttack and the endpoint's own session or history
            # field carries the conversation, as in the platform's scoped probe.
            for index, turn in enumerate(turns):
                body = json.loads(json.dumps(spec.get("static_body") or {}))
                _set(body, spec["message_field"], "{PROMPT}")
                if index and spec.get("history_field"):
                    _set(body, spec["history_field"], history)
                if index and spec.get("session_request_field"):
                    if not session:
                        raise ValueError("No session id in the previous reply")
                    _set(body, spec["session_request_field"], session)
                raw: list = []
                last = index == len(turns) - 1
                scoring = (AttackScoringConfig(objective_scorer=SubStringScorer(substring=case["canary"]))
                           if last else None)
                attack = PromptSendingAttack(objective_target=target_for(body, raw),
                                             attack_scoring_config=scoring)
                result = await attack.execute_async(objective=turn)
                text = raw[-1] if raw else ""
                reply = str(_field(text, response_field)) if response_field else text
                row["responses"].append(reply[:4000])
                history += [{"role": "user", "content": turn},
                            {"role": "assistant", "content": reply}]
                if spec.get("session_response_field"):
                    session = str(_field(text, spec["session_response_field"]) or session)
                if last:
                    row["success"] = str(getattr(result, "outcome", "")).lower().endswith("success")
        except Exception as exc:  # one failing case must not end the run
            row["error"] = f"{type(exc).__name__}: {str(exc)[:200]}"
        results.append(row)
    return {"tool": "pyrit", "pyrit_version": pyrit.__version__, "endpoint": url,
            "results": results}


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__)
        return 2
    with open(argv[1], encoding="utf-8") as handle:
        spec = json.load(handle)
    output = asyncio.run(run(spec))
    with open(argv[2], "w", encoding="utf-8") as handle:
        json.dump(output, handle)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
