#!/usr/bin/env python3
"""
Aegis Vanguard Single-Finding Validator

Point the Aegis Vanguard `validator_agent` at ONE existing finding and have it
actively re-test the live target (real HTTP requests + targeted nuclei re-runs)
to decide whether the detection is a true positive, a false positive, or needs
more evidence.

Unlike run_pentest.py this does NOT run a full pentest pipeline and does NOT
submit findings back to the platform. It emits a single structured JSON verdict
on stdout so a backend worker can parse it and write the result to the ASM
database.

Usage:
    python3 validate_finding.py --finding-json /path/to/finding.json
    python3 validate_finding.py --finding-json - < finding.json   # read stdin
    python3 validate_finding.py --finding-json finding.json --scope example.com

Input finding JSON schema (source-agnostic; only title + target are required).
Any of these may be present depending on the finding's source (nuclei,
port_scanner, trufflehog, manual pentest, etc.); the agent adapts its re-test
strategy to `source_kind`:
    {
      "title": "...",
      "description": "...",
      "severity": "medium",
      "target": "https://host:443",   # or "host:443" / "host"
      "source_kind": "web|network_service|secret|manual|generic",
      "detected_by": "nuclei",
      "template_id": "ldap-anonymous-login-detect",
      "template_yaml": "...",          # for template/signature sources
      "cve_id": "CVE-...", "cwe_id": "CWE-...",
      "evidence": "matched at ...",
      "impact": "...", "affected_component": "...",
      "steps_to_reproduce": "...", "proof_of_concept": "...",
      "metadata": { "port": 443, "service": "https", ... }
    }

Output (stdout), wrapped in sentinels so it is trivially machine-parseable:
    ===VALIDATION_JSON_START===
    { "verdict": "false_positive", "confidence": "high", ... }
    ===VALIDATION_JSON_END===
"""

import argparse
import json
import logging
import os
import re
import sys
import time
from urllib.parse import urlparse

# Add this dir to path so agent/ and scanners are importable (mirrors run_pentest)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent.core import Agent, AgentRunner
from agent.guardrails import GuardrailEngine
from agent.tracing import Tracer

# Importing agents registers all @security_tool tools on the global registry
# (send_http_request, scan_nuclei, etc.) and gives us the validator instructions.
from agent.agents import create_validator_agent  # noqa: E402

try:
    from aegis_praetorium import (
        HostListResolver,
        PraetoriumConfig,
        load_from_env,
        set_config,
        set_scope_resolver,
    )
    _AEGIS_AVAILABLE = True
except Exception:
    _AEGIS_AVAILABLE = False

logger = logging.getLogger("aegis_vanguard.validate_finding")

# Sentinels so the caller can extract the JSON verdict even if the LLM prints
# surrounding prose or the framework logs interleave on other streams.
JSON_START = "===VALIDATION_JSON_START==="
JSON_END = "===VALIDATION_JSON_END==="

# Validation must never write back to the platform. Restrict to live re-test
# tools only (no confirm_vulnerability_poc / submit_findings_to_platform).
# probe_http / scan_ports help catch "wrong service on this port" FPs
# (e.g. LDAP template firing on HTTPS:443) and confirm the issue is still open.
VALIDATION_ONLY_TOOLS = [
    "send_http_request",
    "scan_nuclei",
    "probe_http",
    "scan_ports",
    "fingerprint_tech",
]

# Well-known service → expected ports. Used for deterministic logic checks
# before (and as guidance for) the LLM re-test.
_SERVICE_PORTS: dict[str, set[int]] = {
    "ldap": {389, 636, 3268, 3269},
    "ldaps": {636, 3269},
    "smtp": {25, 465, 587},
    "smtps": {465},
    "imap": {143, 993},
    "imaps": {993},
    "pop3": {110, 995},
    "pop3s": {995},
    "ftp": {21, 990},
    "ftps": {990},
    "ssh": {22},
    "telnet": {23},
    "mysql": {3306},
    "mariadb": {3306},
    "postgres": {5432},
    "postgresql": {5432},
    "mssql": {1433},
    "redis": {6379},
    "mongodb": {27017},
    "memcached": {11211},
    "elasticsearch": {9200, 9300},
    "kibana": {5601},
    "rdp": {3389},
    "smb": {139, 445},
    "nfs": {2049},
    "vnc": {5900, 5901},
    "mqtt": {1883, 8883},
    "amqp": {5672},
    "cassandra": {9042},
    "couchdb": {5984},
    "zookeeper": {2181},
    "kafka": {9092},
    "dns": {53},
    "snmp": {161, 162},
    "sip": {5060, 5061},
}

_WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9443}

_STRUCTURED_OUTPUT_INSTRUCTIONS = """

## Your task in THIS run (single-finding re-validation)

You are re-validating exactly ONE existing finding that is already in the ASM
platform (often still marked Open). Do NOT submit anything to any platform.
Available tools: send_http_request, scan_nuclei, probe_http, scan_ports,
fingerprint_tech.

Goals (in order):
1. **Logical sanity** — Does the claimed vulnerability even make sense on this
   host/port/service? Classic false positives:
   - LDAP / AD / Kerberos / SMB / SSH / SMTP / Redis / MySQL / Mongo / RDP
     findings on HTTP(S) ports 80/443/8080/8443
   - Template name implies service X but the live response is clearly a web app
   - Port in metadata does not match the protocol the finding claims
   If the claim is nonsensical for the observed service, verdict = false_positive
   with high confidence (set logical_mismatch=true). Do not "confirm" just because
   a nuclei template once matched.
2. **Still open?** — Re-test the live target. If the issue no longer reproduces
   (fixed, port closed, endpoint gone), prefer false_positive (or note
   still_open=false). If it still reproduces with real impact, confirmed +
   still_open=true.
3. **Meaningful impact** — A bare "scanner matched" or "template matched" is NOT
   enough (KILL Q1) unless you can reproduce vulnerable BEHAVIOUR.

When you are done, output your decision as a SINGLE JSON object wrapped exactly
between these two sentinel lines, on their own lines, with nothing else after
the closing sentinel:

===VALIDATION_JSON_START===
{
  "verdict": "confirmed | false_positive | needs_more_evidence",
  "confidence": "high | medium | low",
  "is_false_positive": true or false,
  "still_open": true or false,
  "logical_mismatch": true or false,
  "recommended_severity": "critical | high | medium | low | info",
  "reasoning": "one or two sentences: why this verdict, referencing the re-test",
  "evidence": "the concrete request/response or scan output that supports it",
  "template_logic_issue": "if false_positive due to the detection template's own logic (wrong service/port/matcher), describe the flaw; otherwise null"
}
===VALIDATION_JSON_END===

Rules for the JSON:
- verdict "confirmed": you reproduced real, exploitable/meaningful impact AND
  the finding is logically consistent with the live service (still_open=true).
- verdict "false_positive": does not hold up — wrong service/port, remediated,
  or no longer reproducible (set is_false_positive=true; set still_open=false
  when the issue is gone).
- verdict "needs_more_evidence": inconclusive after re-test.
- logical_mismatch=true when service/port/protocol cannot be what the finding
  claims (e.g. "Anonymous LDAP" against https://host:443).
- Set "template_logic_issue" when a template/signature matched the wrong
  protocol or a weak banner/version check.
- recommended_severity reflects the ACHIEVED impact, not the original label.
- If your tools cannot verify this class of finding (e.g. live credential use),
  return "needs_more_evidence" — do not guess.
"""


def _extract_port(finding: dict, target: str) -> int | None:
    """Best-effort port from metadata, target URL, or host:port string."""
    meta = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
    for key in ("port", "nuclei_port", "dst_port"):
        raw = meta.get(key)
        if raw is None:
            continue
        try:
            return int(raw)
        except (TypeError, ValueError):
            pass
    parsed = urlparse(target if "://" in target else f"//{target}")
    if parsed.port:
        return parsed.port
    if parsed.scheme == "https":
        return 443
    if parsed.scheme == "http":
        return 80
    # host:port without scheme
    host = str(finding.get("target") or finding.get("host") or target or "")
    m = re.search(r":(\d{2,5})(?:/|$)", host)
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            return None
    return None


def _infer_claimed_services(finding: dict) -> list[str]:
    """Infer which non-HTTP service the finding claims from title/template/tags."""
    blob = " ".join(
        str(x or "")
        for x in (
            finding.get("title"),
            finding.get("description"),
            finding.get("template_id"),
            finding.get("affected_component"),
            " ".join(finding.get("tags") or []),
        )
    ).lower()
    hits: list[str] = []
    for name in _SERVICE_PORTS:
        # word-ish match so "ldap" hits ldap-anonymous but not "gladly"
        if re.search(rf"(?<![a-z]){re.escape(name)}(?![a-z])", blob):
            hits.append(name)
    return hits


def _logical_sanity_check(finding: dict, target: str) -> dict | None:
    """
    Deterministic pre-check for nonsensical findings.

    Example: LDAP anonymous bind template matched against https://host:443.
    Returns an early false_positive verdict, or None to continue with LLM re-test.
    """
    port = _extract_port(finding, target)
    claimed = _infer_claimed_services(finding)
    if not claimed or port is None:
        return None

    # Only auto-FP when claimed service is clearly non-web AND port is a web port
    # (or otherwise outside the service's well-known ports).
    mismatches = []
    for svc in claimed:
        expected = _SERVICE_PORTS.get(svc) or set()
        if not expected:
            continue
        if port in expected:
            continue
        # Strong signal: non-HTTP service claimed on typical HTTP(S) ports
        if port in _WEB_PORTS:
            mismatches.append((svc, expected))
        # Also flag when port is nowhere near the service's range and not a
        # common alternate (keep conservative — only web-port case auto-kills).

    if not mismatches:
        return None

    svc_list = ", ".join(f"{s} (expected ports {sorted(p)})" for s, p in mismatches)
    return {
        "verdict": "false_positive",
        "confidence": "high",
        "is_false_positive": True,
        "still_open": False,
        "logical_mismatch": True,
        "recommended_severity": "info",
        "reasoning": (
            f"Logical mismatch: finding claims {svc_list}, but target port is {port} "
            f"({target}). Non-HTTP service detections on HTTP(S) ports are almost "
            f"always template/protocol false positives."
        ),
        "evidence": (
            f"claimed_services={[s for s, _ in mismatches]} observed_port={port} "
            f"target={target} template_id={finding.get('template_id')}"
        ),
        "template_logic_issue": (
            f"Template/detection for {[s for s, _ in mismatches]} fired against "
            f"port {port} instead of the service's well-known ports. Matcher likely "
            f"does not verify the actual protocol/handshake."
        ),
        "sanity_flags": [
            f"service_port_mismatch:{s}:port_{port}" for s, _ in mismatches
        ],
    }


def _sanity_guidance(finding: dict, target: str) -> str:
    """Soft guidance injected into the LLM prompt even when we don't auto-FP."""
    port = _extract_port(finding, target)
    claimed = _infer_claimed_services(finding)
    lines = [
        "\n## Logical sanity (check BEFORE confirming)\n",
        "- Ask: would this vulnerability class exist on the live service at this port?\n",
        "- LDAP/AD/SMB/SSH/SMTP/DB/Redis/RDP findings on 80/443/8080/8443 → almost always FP.\n",
        "- If probe_http/fingerprint_tech shows a normal web app and the finding is a "
        "non-HTTP protocol issue, mark false_positive with logical_mismatch=true.\n",
        "- Re-check whether the issue is STILL OPEN (still_open). Remediated or "
        "closed ports → false_positive / still_open=false.\n",
    ]
    if port is not None:
        lines.append(f"- Observed port for this target: **{port}**.\n")
    if claimed:
        lines.append(
            f"- Finding text appears to claim service(s): **{', '.join(claimed)}**. "
            f"Verify the live protocol matches before confirming.\n"
        )
    return "".join(lines)


# Source-specific validation guidance. The finding's `source_kind` (set by the
# backend) tells us HOW to re-test, since a Nuclei web match, an open-port
# observation, a leaked secret, and a manual pentest finding each need a
# different validation strategy.
def _source_guidance(finding: dict) -> str:
    kind = str(finding.get("source_kind") or "").lower()
    detected_by = finding.get("detected_by") or "unknown"
    common = f"\n## Source of this finding\nDetected by: {detected_by} (kind: {kind or 'generic'}).\n"

    if kind == "web":
        return common + (
            "This is a web/application finding. Re-issue the relevant HTTP "
            "request(s) with send_http_request (and/or a targeted scan_nuclei run) "
            "and confirm the vulnerable BEHAVIOUR in the live response — not just a "
            "version string or a page that merely exists. If the issue no longer "
            "reproduces, mark false_positive with still_open=false (likely remediated).\n"
        )
    if kind == "network_service":
        return common + (
            "This is a network/service finding (open port / exposed service). "
            "Confirm the service is actually reachable and behaving as claimed at "
            "the given host:port (use scan_ports / probe_http as needed). A port "
            "simply being open is NOT proof of the vulnerability — verify the risky "
            "capability (e.g. anonymous access, outdated protocol). If the port is "
            "closed or filtered on re-test, the finding is no longer open "
            "(false_positive / still_open=false).\n"
        )
    if kind == "secret":
        return common + (
            "This is a leaked-secret finding. Your HTTP tools usually CANNOT prove "
            "a credential is live without risky authentication attempts, which are "
            "out of scope here. Assess what you safely can (e.g. is the endpoint the "
            "secret would authenticate to reachable, is the secret format valid) and "
            "prefer 'needs_more_evidence' over guessing. Never exfiltrate or fully "
            "use the secret.\n"
        )
    if kind == "manual":
        return common + (
            "This is a MANUAL pentest finding. Use the provided steps_to_reproduce "
            "and proof_of_concept to re-run the check with send_http_request. If the "
            "documented steps still reproduce the issue, it is confirmed; if they no "
            "longer do, it may be remediated or a false positive.\n"
        )
    return common + (
        "Re-test the finding as directly as your tools allow and confirm the "
        "claimed impact against the live target before deciding.\n"
    )


def _load_finding(path: str) -> dict:
    if path == "-":
        raw = sys.stdin.read()
    else:
        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.read()
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("finding JSON must be an object")
    return data


def _normalize_target(finding: dict, override: str | None) -> str:
    """Return a URL suitable for the validator/tools from the finding target."""
    target = override or finding.get("target") or finding.get("host") or finding.get("url") or ""
    target = str(target).strip()
    if not target:
        raise ValueError("finding has no target/host/url and none was provided via --target")
    if not target.startswith(("http://", "https://")):
        # host or host:port -> assume https unless port clearly maps to http
        if target.endswith(":80") or ":80/" in target:
            target = "http://" + target
        else:
            target = "https://" + target
    return target


def _extract_verdict(text: str) -> dict | None:
    """Pull the JSON verdict out of the agent's final text."""
    if not text:
        return None
    # Preferred: sentinel-wrapped block.
    m = re.search(
        re.escape(JSON_START) + r"\s*(.*?)\s*" + re.escape(JSON_END),
        text,
        re.DOTALL,
    )
    candidate = None
    if m:
        candidate = m.group(1)
    else:
        # Fallback: a fenced ```json block.
        fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if fence:
            candidate = fence.group(1)
        else:
            # Last resort: first {...} that parses.
            brace = re.search(r"\{.*\}", text, re.DOTALL)
            if brace:
                candidate = brace.group(0)
    if not candidate:
        return None
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        return None


def _build_validation_agent(max_turns: int) -> Agent:
    base = create_validator_agent()
    return Agent(
        name=base.name,
        instructions=base.instructions + _STRUCTURED_OUTPUT_INSTRUCTIONS,
        tool_names=VALIDATION_ONLY_TOOLS,
        model=base.model,
        max_turns=max_turns,
        temperature=base.temperature,
    )


def _emit(verdict: dict) -> None:
    """Print the verdict on stdout between sentinels for the caller to parse."""
    print(JSON_START)
    print(json.dumps(verdict, indent=2, default=str))
    print(JSON_END)
    sys.stdout.flush()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate a single existing finding with the Aegis Vanguard validator agent",
    )
    parser.add_argument("--finding-json", required=True,
                        help="Path to a JSON file describing the finding, or '-' for stdin")
    parser.add_argument("--target", help="Override the target URL (default: from finding)")
    parser.add_argument("--scope", help="Root domain scope (default: derived from target host)")
    parser.add_argument("--model", help="Anthropic model (default: env AEGIS_MODEL)")
    parser.add_argument("--max-risk", choices=["safe", "low", "medium", "high", "critical"],
                        default="high", help="Max tool risk level allowed (default: high)")
    parser.add_argument("--max-turns", type=int, default=25,
                        help="ReAct turn budget for the validator (default: 25)")
    parser.add_argument("--no-guardrails", action="store_true")
    parser.add_argument("--output", help="Optional path to also write the verdict JSON")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    # All framework/agent logs go to STDERR so STDOUT carries only the verdict.
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )

    try:
        finding = _load_finding(args.finding_json)
    except Exception as e:
        _emit({
            "verdict": "needs_more_evidence",
            "confidence": "low",
            "is_false_positive": False,
            "recommended_severity": "info",
            "reasoning": f"Could not load finding JSON: {e}",
            "evidence": "",
            "template_logic_issue": None,
            "error": "invalid_finding_json",
        })
        return 2

    try:
        target = _normalize_target(finding, args.target)
    except Exception as e:
        _emit({
            "verdict": "needs_more_evidence",
            "confidence": "low",
            "is_false_positive": False,
            "still_open": None,
            "logical_mismatch": False,
            "recommended_severity": str(finding.get("severity", "info")),
            "reasoning": f"Could not determine target: {e}",
            "evidence": "",
            "template_logic_issue": None,
            "error": "invalid_target",
        })
        return 2

    # Fast path: nonsensical service/port combos (LDAP on 443, etc.)
    early = _logical_sanity_check(finding, target)
    if early:
        early["_meta"] = {
            "template_id": finding.get("template_id"),
            "detected_by": finding.get("detected_by"),
            "source_kind": finding.get("source_kind"),
            "target": target,
            "short_circuit": "logical_sanity",
        }
        logger.info(
            "Logical sanity short-circuit FP for template_id=%s target=%s flags=%s",
            finding.get("template_id"), target, early.get("sanity_flags"),
        )
        if args.output:
            try:
                with open(args.output, "w", encoding="utf-8") as fh:
                    json.dump(early, fh, indent=2, default=str)
            except Exception as e:
                logger.warning("Could not write --output file: %s", e)
        _emit(early)
        return 0

    parsed = urlparse(target)
    target_host = parsed.hostname or ""
    scope_domain = args.scope or target_host
    model = args.model or os.environ.get(
        "AEGIS_MODEL", "claude-sonnet-4-6"
    )
    llm_backend = os.environ.get("AEGIS_LLM_BACKEND", "auto").lower()

    needs_anthropic_key = (
        llm_backend == "anthropic"
        or (llm_backend == "auto" and model.startswith("claude-"))
    )
    if needs_anthropic_key and not os.environ.get("ANTHROPIC_API_KEY"):
        _emit({
            "verdict": "needs_more_evidence",
            "confidence": "low",
            "is_false_positive": False,
            "recommended_severity": str(finding.get("severity", "info")),
            "reasoning": "ANTHROPIC_API_KEY not set; validator could not run.",
            "evidence": "",
            "template_logic_issue": None,
            "error": "missing_api_key",
        })
        return 3

    guardrails = GuardrailEngine(
        enabled=not args.no_guardrails,
        scope_domains=[scope_domain] if scope_domain else None,
        max_risk=args.max_risk,
    )

    if _AEGIS_AVAILABLE:
        try:
            base = load_from_env()
            set_config(PraetoriumConfig(
                lictor_enabled=base.lictor_enabled and not args.no_guardrails,
                censor_enabled=base.censor_enabled and not args.no_guardrails,
                augur_enabled=base.augur_enabled,
                augur_verbose=base.augur_verbose,
                enforce_scope=base.enforce_scope and bool(scope_domain) and not args.no_guardrails,
                rate_capacity=base.rate_capacity,
                rate_per_minute=base.rate_per_minute,
                tool_output_max_chars=base.tool_output_max_chars,
            ))
            if scope_domain:
                set_scope_resolver(HostListResolver([scope_domain]))
        except Exception as e:
            logger.warning("aegis_praetorium config failed (continuing): %s", e)

    tracer = Tracer(enabled=False)
    runner = AgentRunner(guardrails=guardrails, tracer=tracer, default_model=model)
    validator = _build_validation_agent(max_turns=args.max_turns)

    # Present a source-agnostic view of the finding. Only include keys that carry
    # a value so the agent isn't distracted by empty Nuclei-specific fields on a
    # secret/port/manual finding (and vice-versa).
    candidate_view = {
        "title": finding.get("title"),
        "description": finding.get("description"),
        "severity": finding.get("severity", "medium"),
        "status": finding.get("status"),
        "target": target,
        "asset": finding.get("asset"),
        "source_kind": finding.get("source_kind"),
        "detected_by": finding.get("detected_by"),
        "template_id": finding.get("template_id"),
        "matcher_name": finding.get("matcher_name"),
        "cve_id": finding.get("cve_id"),
        "cwe_id": finding.get("cwe_id"),
        "detection_confidence": finding.get("detection_confidence"),
        "references": finding.get("references"),
        "evidence": finding.get("evidence"),
        # Manual / pentest context.
        "impact": finding.get("impact"),
        "affected_component": finding.get("affected_component"),
        "steps_to_reproduce": finding.get("steps_to_reproduce"),
        "proof_of_concept": finding.get("proof_of_concept"),
        # Source-specific metadata (port/service/secret location/etc.).
        "metadata": finding.get("metadata"),
    }
    finding_view = {k: v for k, v in candidate_view.items() if v not in (None, "", [], {})}

    # The matched template's YAML (when available) is shown separately so the agent
    # can reason about the DETECTION LOGIC itself — i.e. whether a false positive is
    # caused by a weak/incorrect matcher rather than the target being safe.
    template_yaml = finding.get("template_yaml")
    template_block = ""
    if template_yaml:
        template_block = (
            "\n## Matched detection template (analyze its matcher logic)\n"
            "```yaml\n" + str(template_yaml).strip()[:6000] + "\n```\n"
            "If this is a false positive, decide whether the template's own matcher "
            "logic is at fault (e.g. matching a banner/version/login page or assuming "
            "the wrong service/protocol) and, if so, describe the flaw in "
            "`template_logic_issue` so a corrected template can be generated.\n"
        )

    status_note = ""
    if finding.get("status"):
        status_note = (
            f"Platform status of this finding: **{finding.get('status')}**. "
            "Determine whether it is STILL OPEN / reproducible on the live target.\n"
        )

    task = (
        f"Re-validate this SINGLE existing finding by actively re-testing the live target.\n"
        f"Target: {target} (scope: {scope_domain}).\n"
        f"{status_note}"
        f"{_source_guidance(finding)}\n"
        f"{_sanity_guidance(finding, target)}\n"
        f"## Finding under review\n```json\n"
        f"{json.dumps(finding_view, indent=2, default=str)}\n```\n"
        f"{template_block}\n"
        "Re-test with send_http_request, scan_nuclei, probe_http, scan_ports, and/or "
        "fingerprint_tech as appropriate. Catch logical mismatches (wrong service on "
        "this port) and check whether the issue is still open, then output the "
        "structured JSON verdict between the sentinel lines as instructed."
    )

    ctx = {
        "target_url": target,
        "scope_domain": scope_domain,
        "phase": "single_finding_validation",
        "finding": finding_view,
    }

    logger.info("Validating finding template_id=%s on %s (model=%s)",
                finding.get("template_id"), target, model)
    start = time.time()
    try:
        result = runner.run(validator, task=task, context=ctx)
    except Exception as e:
        logger.error("Validator run failed: %s", e, exc_info=True)
        _emit({
            "verdict": "needs_more_evidence",
            "confidence": "low",
            "is_false_positive": False,
            "recommended_severity": str(finding.get("severity", "info")),
            "reasoning": f"Validator run failed: {e}",
            "evidence": "",
            "template_logic_issue": None,
            "error": "validator_exception",
        })
        return 1

    elapsed = time.time() - start
    verdict = _extract_verdict(result.final_text or "")
    if verdict is None:
        verdict = {
            "verdict": "needs_more_evidence",
            "confidence": "low",
            "is_false_positive": False,
            "recommended_severity": str(finding.get("severity", "info")),
            "reasoning": "Validator finished without producing a parseable JSON verdict.",
            "evidence": (result.final_text or "")[:2000],
            "template_logic_issue": None,
            "error": "unparseable_verdict",
        }

    # Normalise a couple of derived fields for the caller's convenience.
    verdict.setdefault("verdict", "needs_more_evidence")
    verdict["is_false_positive"] = bool(
        verdict.get("is_false_positive")
        or verdict.get("verdict") == "false_positive"
    )
    if "still_open" not in verdict:
        verdict["still_open"] = verdict.get("verdict") == "confirmed"
    if "logical_mismatch" not in verdict:
        verdict["logical_mismatch"] = False
    verdict["_meta"] = {
        "template_id": finding.get("template_id"),
        "detected_by": finding.get("detected_by"),
        "source_kind": finding.get("source_kind"),
        "target": target,
        "turns_used": result.turns_used,
        "tool_calls_made": result.tool_calls_made,
        "elapsed_sec": round(elapsed, 1),
        "model": model,
    }

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                json.dump(verdict, fh, indent=2, default=str)
        except Exception as e:
            logger.warning("Could not write --output file: %s", e)

    _emit(verdict)
    return 0


if __name__ == "__main__":
    sys.exit(main())
