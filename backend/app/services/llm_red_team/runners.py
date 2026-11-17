"""Run garak, promptfoo and PyRIT as lead sources against one approved chat endpoint.

These tools send their own traffic, so they cannot use ``_http_exchange``. The
callers (``ASMToolsManager.scoped_llm_lead_scan``) only pass an endpoint the
operator approved in ``prompt_injection_endpoints`` on the scoped origin, refuse
to run during a pilot pass, and route the tools through the assessment proxy
when one is configured. Each tool runs in its own interpreter or binary
(garak's and PyRIT's ``openai`` pins conflict). Output is parsed by
``leads.py`` into leads; confirmation still needs the scoped verifier.

Test prompts are built from the scoped probe's fixed templates with fresh
canaries, so a tool's pass/fail is a canary match rather than an LLM grade.
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from pathlib import Path

from app.services.agent.scoped_assessment import prompt_injection_probe as pi

RUNNER_TIMEOUT = {"garak": 1800, "promptfoo": 900, "pyrit": 900}
GARAK_PROBES = {
    "promptinject": "promptinject",
    "latentinjection": "latentinjection",
}
TOOLS = ("garak", "promptfoo", "pyrit")
TOOL_MODES = {
    "garak": ("direct", "indirect"),
    "promptfoo": ("direct", "system_prompt_leak"),
    "pyrit": ("direct", "multi_turn", "system_prompt_leak"),
}
PYRIT_RUNNER = Path(__file__).with_name("pyrit_runner.py")


def tool_command(tool: str) -> list[str]:
    if tool == "garak":
        return [os.environ.get("GARAK_PYTHON", "/opt/garak/bin/python"), "-m", "garak"]
    if tool == "pyrit":
        return [os.environ.get("PYRIT_PYTHON", "/opt/pyrit/bin/python"), "-I", str(PYRIT_RUNNER)]
    if tool == "promptfoo":
        return [os.environ.get("PROMPTFOO_BIN", "promptfoo")]
    raise ValueError("tool must be garak, promptfoo or pyrit")


def _template_body(config: dict, placeholder: str) -> dict:
    body = json.loads(json.dumps(config.get("static_body") or {}))
    cursor = body
    keys = config["message_field"].split(".")
    for key in keys[:-1]:
        cursor = cursor.setdefault(key, {})
    cursor[keys[-1]] = placeholder
    return body


def canary_cases(mode: str, config: dict) -> list[dict]:
    """One probe case per fixed technique of ``mode``, each with a fresh canary."""
    cases = []
    for technique in pi.TECHNIQUES_BY_MODE[mode]:
        if mode == "system_prompt_leak":
            canary = config["system_prompt_canary"]
            texts = pi.build_row_text(mode, technique, control=False)
        else:
            left, right, canary = pi.new_canary()
            texts = pi.build_row_text(mode, technique, control=False, left=left, right=right)
        turns = texts.get("turns") or [texts["message"]]
        cases.append({"id": f"aegis-{mode}-{technique}", "mode": mode,
                      "technique": technique, "canary": canary, "turns": turns})
    return cases


def promptfoo_config(url: str, config: dict, cases: list[dict]) -> dict:
    provider = {"url": url, "method": "POST",
                "headers": {"Content-Type": "application/json"},
                "body": _template_body(config, "{{prompt}}")}
    if config.get("response_field"):
        provider["transformResponse"] = "json." + config["response_field"]
    return {
        "description": "Aegis scoped prompt-injection lead scan",
        "providers": [{"id": "http", "label": "approved-chat-endpoint", "config": provider}],
        "prompts": ["{{prompt}}"],
        "tests": [{"description": case["id"], "vars": {"prompt": case["turns"][-1]},
                   "metadata": {"aegis_mode": case["mode"], "aegis_canary": case["canary"]},
                   "assert": [{"type": "not-icontains", "value": case["canary"]}]}
                  for case in cases if len(case["turns"]) == 1],
    }


def garak_generator(url: str, config: dict) -> dict:
    field = config.get("response_field") or ""
    rest = {"name": "aegis-approved-endpoint", "uri": url, "method": "post",
            "headers": {"Content-Type": "application/json"},
            "req_template_json_object": _template_body(config, "$INPUT"),
            "response_json": bool(field)}
    if field:
        rest["response_json_field"] = field if "." not in field else "$." + field
    return {"rest": {"RestGenerator": rest}}


def pyrit_spec(url: str, config: dict, cases: list[dict], proxy: str | None) -> dict:
    spec = {"url": url, "message_field": config["message_field"],
            "response_field": config.get("response_field") or "",
            "static_body": config.get("static_body") or {}, "cases": cases,
            "max_requests_per_minute": 30}
    for name in ("history_field", "session_request_field", "session_response_field"):
        if config.get(name):
            spec[name] = config[name]
    if proxy:
        spec["proxy"] = proxy
    return spec


def runner_env(workdir: str) -> dict:
    from app.services.agent.assessment_proxy import assessment_ca_bundle, assessment_proxy_url

    proxy = assessment_proxy_url()
    env = {key: value for key, value in os.environ.items()
           if key in {"PATH", "LANG", "LC_ALL", "TZ", "SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS"}}
    env.update(HOME=workdir, XDG_DATA_HOME=workdir, XDG_CONFIG_HOME=workdir,
               XDG_CACHE_HOME=workdir, PROMPTFOO_DISABLE_TELEMETRY="1",
               PROMPTFOO_DISABLE_UPDATE="1", PROMPTFOO_DISABLE_REMOTE_GENERATION="1",
               PROMPTFOO_DISABLE_SHARING="1", PROMPTFOO_CONFIG_DIR=workdir,
               PROMPTFOO_FAILED_TEST_EXIT_CODE="0",
               NO_PROXY="", no_proxy="")
    if proxy:
        bundle = assessment_ca_bundle(proxy)
        env.update(HTTP_PROXY=proxy, HTTPS_PROXY=proxy, http_proxy=proxy, https_proxy=proxy)
        if isinstance(bundle, str):
            env.update(SSL_CERT_FILE=bundle, REQUESTS_CA_BUNDLE=bundle, NODE_EXTRA_CA_CERTS=bundle)
    return env


async def _run(cmd: list[str], *, cwd: str, env: dict, timeout: int) -> tuple[int, str]:
    process = await asyncio.create_subprocess_exec(
        *cmd, cwd=cwd, env=env, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT)
    try:
        output, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        return -1, "timed out"
    return process.returncode or 0, output.decode(errors="replace")[-2000:]


async def run_lead_tool(tool: str, *, url: str, config: dict, mode: str,
                        repeat: int = 3, probes: str = "promptinject",
                        workdir: str | None = None) -> dict:
    """Run one tool and return {"report_path", "returncode", "output_tail", "source"}."""
    from app.services.agent.assessment_proxy import assessment_proxy_url

    if tool not in TOOLS:
        raise ValueError("tool must be garak, promptfoo or pyrit")
    if mode not in TOOL_MODES[tool]:
        raise ValueError(f"{tool} supports modes: {', '.join(TOOL_MODES[tool])}")
    pi.validate_endpoint_config(mode, config)
    workdir = workdir or tempfile.mkdtemp(prefix=f"aegis-{tool}-")
    env = runner_env(workdir)
    command = tool_command(tool)
    if tool == "garak":
        probe = GARAK_PROBES.get(probes)
        if not probe:
            raise ValueError(f"garak probes must be one of {sorted(GARAK_PROBES)}")
        if mode == "indirect" and probe != "latentinjection":
            probe = "latentinjection"
        generator = Path(workdir, "generator.json")
        generator.write_text(json.dumps(garak_generator(url, config)))
        prefix = str(Path(workdir, "garak"))
        cmd = [*command, "--target_type", "rest", "-G", str(generator), "--probes", probe,
               "--generations", "1", "--report_prefix", prefix]
        report = prefix + ".report.jsonl"
    elif tool == "promptfoo":
        cases = canary_cases(mode, config)
        cfg = Path(workdir, "promptfooconfig.yaml")
        cfg.write_text(json.dumps(promptfoo_config(url, config, cases)))  # JSON is valid YAML
        report = str(Path(workdir, "promptfoo.json"))
        cmd = [*command, "eval", "-c", str(cfg), "-o", report, "--no-cache",
               "--no-progress-bar", "--repeat", str(max(1, min(int(repeat or 1), 5)))]
    else:
        cases = canary_cases(mode, config)
        spec = Path(workdir, "spec.json")
        spec.write_text(json.dumps(pyrit_spec(url, config, cases, assessment_proxy_url())))
        report = str(Path(workdir, "pyrit.json"))
        cmd = [*command, str(spec), report]
    try:
        returncode, tail = await _run(cmd, cwd=workdir, env=env, timeout=RUNNER_TIMEOUT[tool])
    except FileNotFoundError as exc:
        raise ValueError(f"{tool} is not installed: {exc.filename}") from exc
    return {"source": tool, "report_path": report, "returncode": returncode,
            "output_tail": tail, "workdir": workdir}
