"""
Custom Nuclei template AI helpers.

Shared, provider-agnostic building blocks for AI-driven Nuclei template work:
  - generation (a fresh template from a CVE / vuln description)
  - refinement (a *more accurate* template derived from a mis-detection)

Both the `custom_templates` API routes and the scanner worker (auto-refine on a
validated false positive) import from here so the LLM prompts, YAML sanitation,
and re-check logic live in exactly one place.

The refine flow closes the validate → diagnose → refine loop:
  1. The Aegis Vanguard validator re-tests a finding and returns a false-positive
     verdict with a `template_logic_issue` (what about the matcher is wrong).
  2. `refine_template()` feeds the original template + that diagnosis to the LLM
     and produces a tightened template saved as a draft custom template.
  3. `recheck_template_against_target()` re-runs the refined template against the
     known false-positive target; if it still fires, the refinement is flagged
     so it is not blindly trusted.
"""

import asyncio
import json
import logging
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.custom_nuclei_template import CustomNucleiTemplate

logger = logging.getLogger(__name__)


# ── System prompts ────────────────────────────────────────────────────────────

NUCLEI_SYSTEM_PROMPT = """You are an expert security engineer specializing in writing Nuclei vulnerability detection templates.

Nuclei is a fast, customizable vulnerability scanner. Templates are YAML files that define what to look for.

## Nuclei Template Structure

```yaml
id: unique-template-id  # lowercase, hyphens only, no spaces

info:
  name: Product - Vulnerability Description
  author: judah-security-oracle
  severity: critical  # info | low | medium | high | critical
  description: |
    One paragraph explaining what this template detects and why it matters.
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-XXXX-YYYY
  classification:
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    cvss-score: 9.8
    cve-id: CVE-XXXX-YYYY
    cwe-id: CWE-78
  metadata:
    verified: false
    max-request: 3
  tags: cve,cveYYYY,rce,product-name

http:
  - method: GET
    path:
      - "{{BaseURL}}/path/to/vulnerable/endpoint"
    headers:
      User-Agent: Mozilla/5.0

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "specific string that only appears in vulnerable response"
          - "another indicator"
        condition: or
        part: body
      - type: regex
        regex:
          - "version:\\s*([0-9.]+)"
        part: body
```

## Target variables (CRITICAL — templates MUST be portable):
- NEVER hardcode a hostname, IP address, domain, port, or full URL of a specific target
  in the template. Any concrete host provided to you is ONLY an example of where the
  vulnerability was observed — the template will run against thousands of different hosts.
- Use `{{BaseURL}}` for the full target URL (scheme + host + port), e.g. `{{BaseURL}}/path`.
- Use `{{Hostname}}` for the host (with port, no scheme) — required in the `Host:` header
  of `raw:` requests. Use `{{Host}}` for host without port when needed.
- If an example URL like `https://target.example.com/users/sign_in` is given, extract ONLY
  the path (`/users/sign_in`) and express it as `{{BaseURL}}/users/sign_in`.
- Prefer `raw:` requests when you need precise control over headers/method/body. When you do,
  the request line uses a relative path and the Host header MUST be `Host: {{Hostname}}`:

```yaml
http:
  - raw:
      - |
        GET /log.txt HTTP/1.1
        Host: {{Hostname}}
        User-Agent: Mozilla/5.0
```

## Key rules:
1. The `id` field must be globally unique — use format: cve-YYYY-NNNNN or custom-org-description
2. Always use `matchers-condition: and` for multi-matcher logic
3. Matchers should be SPECIFIC — avoid generic strings that would match on non-vulnerable targets
4. For version detection: use `type: regex` with extractors
5. For timing-based detection: use `type: dsl` with `duration > 5`
6. POST requests need a `body` field and appropriate Content-Type header
7. Use `{{BaseURL}}` / `{{Hostname}}` for targets — NEVER a hardcoded host (see above)
8. Mark `verified: false` unless you have tested it manually
9. Add all relevant tags (cve, year, vulnerability type, affected tech)

## Detection strategy:
- PREFER active detection (sending a request that triggers a unique response from vulnerable systems)
- AVOID fingerprinting only (checking version numbers is weak)
- DO NOT include actual exploit payloads that would cause harm
- Use benign detection probes that confirm vulnerability without exploiting it

Return ONLY the raw YAML. No markdown code fences, no explanation, no preamble.
"""


NUCLEI_REFINE_SYSTEM_PROMPT = """You are an expert security engineer who FIXES Nuclei detection templates that produce FALSE POSITIVES.

You are given an existing Nuclei template and a concrete report of WHY it mis-fired
(a false positive confirmed by actively re-testing a real target). Your job is to
produce a corrected template that STILL detects the real vulnerability but NO LONGER
fires on the benign/false-positive case.

## How to tighten a template
- Diagnose the weak matcher: version/banner-only matches, overly generic strings,
  matching an error/login page, wrong protocol/service assumption, or a status-only match.
- Add CONFIRMATION: require a response that proves the vulnerable behavior actually
  occurred, not merely that the endpoint exists or a keyword is present.
- Use `matchers-condition: and` and combine independent signals (status + specific
  body proof + optional negative matcher for the benign case).
- Add a NEGATIVE matcher (`negative: true`) to exclude the known benign response when
  that is the cleanest fix.
- If the service/protocol assumption is wrong (e.g. an LDAP template firing on an
  HTTPS web API), add a guard that confirms the expected service before asserting the vuln.
- If the condition genuinely cannot be actively proven, downgrade `severity` to `info`
  and make it explicitly detection-only rather than emitting a scary false positive.

## Hard rules
- Keep the template PORTABLE: use `{{BaseURL}}` / `{{Hostname}}`, never hardcode the
  example target host/IP/port.
- Preserve the original `id` unless it must change; if you change it, keep it descriptive.
- Preserve real references and classification (cve-id, cwe-id) from the original.
- Do NOT include harmful exploit payloads; benign confirmation only.

Return ONLY the corrected raw YAML. No markdown code fences, no explanation, no preamble.
"""


# ── LLM invocation ─────────────────────────────────────────────────────────────

async def call_llm(system_prompt: str, user_prompt: str, max_tokens: int = 4096) -> str:
    """Call the configured LLM and return the raw text response."""
    ai_provider = getattr(settings, "AI_PROVIDER", "openai")
    model_name = getattr(settings, "AI_MODEL", None)

    try:
        from langchain_anthropic import ChatAnthropic  # noqa: F401
        anthropic_available = True
    except ImportError:
        anthropic_available = False

    try:
        from langchain_openai import ChatOpenAI  # noqa: F401
        openai_available = True
    except ImportError:
        openai_available = False

    if ai_provider == "anthropic" and anthropic_available:
        from langchain_anthropic import ChatAnthropic
        from langchain_core.messages import HumanMessage, SystemMessage
        llm = ChatAnthropic(
            model=model_name or getattr(settings, "ANTHROPIC_MODEL", None) or "claude-sonnet-4-6",
            api_key=getattr(settings, "ANTHROPIC_API_KEY", ""),
            max_tokens=max_tokens,
        )
        response = await llm.ainvoke([
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_prompt),
        ])
        return response.content

    if openai_available:
        from langchain_openai import ChatOpenAI
        from langchain_core.messages import HumanMessage, SystemMessage
        llm = ChatOpenAI(
            model=model_name or getattr(settings, "OPENAI_MODEL", None) or "gpt-4o",
            api_key=getattr(settings, "OPENAI_API_KEY", ""),
            max_tokens=max_tokens,
        )
        response = await llm.ainvoke([
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_prompt),
        ])
        return response.content

    from fastapi import HTTPException
    raise HTTPException(
        status_code=503,
        detail="No LLM provider configured. Set ANTHROPIC_API_KEY or OPENAI_API_KEY.",
    )


def resolved_ai_model() -> str:
    return getattr(settings, "AI_MODEL", None) or (
        getattr(settings, "ANTHROPIC_MODEL", None) or "claude-sonnet-4-6"
        if getattr(settings, "AI_PROVIDER", "openai") == "anthropic"
        else getattr(settings, "OPENAI_MODEL", None) or "gpt-4o"
    )


# ── YAML helpers ───────────────────────────────────────────────────────────────

def extract_yaml_from_response(raw: str) -> str:
    """Strip markdown fences if the model included them despite instructions."""
    raw = (raw or "").strip()
    raw = re.sub(r"^```(?:yaml)?\s*\n?", "", raw, flags=re.MULTILINE)
    raw = re.sub(r"\n?```\s*$", "", raw, flags=re.MULTILINE)
    return raw.strip()


def parse_yaml_metadata(yaml_text: str) -> dict:
    """Extract basic metadata from YAML without importing PyYAML (best-effort)."""
    meta = {"cve_ids": [], "tags": [], "severity": None, "template_id": None, "template_type": "http"}
    for line in (yaml_text or "").splitlines():
        line = line.strip()
        if line.startswith("id:"):
            meta["template_id"] = line.split(":", 1)[1].strip()
        elif line.startswith("severity:"):
            meta["severity"] = line.split(":", 1)[1].strip()
        elif line.startswith("tags:"):
            tags_raw = line.split(":", 1)[1].strip()
            meta["tags"] = [t.strip() for t in tags_raw.split(",") if t.strip()]
        elif line.startswith("cve-id:"):
            cve = line.split(":", 1)[1].strip()
            if cve:
                meta["cve_ids"].append(cve.upper())
        elif line.startswith("network:"):
            meta["template_type"] = "network"
        elif line.startswith("tcp:"):
            meta["template_type"] = "tcp"
        elif line.startswith("dns:"):
            meta["template_type"] = "dns"
    return meta


def url_to_path_pattern(url: str) -> str:
    """Reduce a full URL to just its path (+ query), stripping scheme/host/port."""
    url = (url or "").strip()
    if not url:
        return "/"
    parsed = urlparse(url if "://" in url else f"http://{url}")
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = f"/{path}"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return path


def strip_hardcoded_host(yaml_text: str, example_url: Optional[str]) -> str:
    """Rewrite any hardcoded example host back to Nuclei variables (safety net)."""
    if not example_url or not yaml_text:
        return yaml_text

    parsed = urlparse(example_url if "://" in example_url else f"http://{example_url}")
    host = parsed.hostname
    if not host:
        return yaml_text

    netloc = parsed.netloc  # host[:port]

    yaml_text = re.sub(rf"https?://{re.escape(netloc)}", "{{BaseURL}}", yaml_text)
    yaml_text = re.sub(rf"https?://{re.escape(host)}", "{{BaseURL}}", yaml_text)
    yaml_text = re.sub(rf"(?<![\w.\-]){re.escape(netloc)}(?![\w.\-])", "{{Hostname}}", yaml_text)
    yaml_text = re.sub(rf"(?<![\w.\-]){re.escape(host)}(?![\w.\-])", "{{Hostname}}", yaml_text)
    return yaml_text


# ── Refinement ─────────────────────────────────────────────────────────────────

def lookup_template_yaml(db: Session, organization_id: int, template_id: str) -> Optional[str]:
    """Find the YAML for a template_id: custom DB template first, then local official catalog."""
    if not template_id:
        return None
    t = (
        db.query(CustomNucleiTemplate)
        .filter(
            CustomNucleiTemplate.organization_id == organization_id,
            CustomNucleiTemplate.template_id == template_id,
        )
        .first()
    )
    if t and t.template_yaml:
        return t.template_yaml
    try:
        from app.services.nuclei_template_parser_service import find_matching_nuclei_template
        match = find_matching_nuclei_template(template_id)
        if match and match.template_path and Path(match.template_path).exists():
            return Path(match.template_path).read_text(encoding="utf-8")
    except Exception as e:
        logger.debug("Could not load official template %s from disk: %s", template_id, e)
    return None


def build_refinement_prompt(
    *,
    original_yaml: str,
    template_logic_issue: str,
    target: Optional[str] = None,
    evidence: Optional[str] = None,
    reasoning: Optional[str] = None,
) -> str:
    parts = ["Fix the following Nuclei template so it no longer produces this false positive.\n"]
    parts.append("## Original template\n```yaml\n" + (original_yaml or "").strip() + "\n```\n")
    parts.append("## Why it mis-fired (confirmed by active re-testing)\n" + (template_logic_issue or "").strip())
    if reasoning:
        parts.append("\n## Validator reasoning\n" + reasoning.strip())
    if evidence:
        parts.append("\n## Re-test evidence (benign / false-positive response)\n```\n" + evidence.strip()[:3000] + "\n```")
    if target:
        path = url_to_path_pattern(target)
        parts.append(
            f"\n## Known false-positive target\nThe template wrongly fired at path `{path}` on an example host. "
            "The corrected template MUST NOT fire on that benign response, but MUST still detect the real vulnerability. "
            "Do NOT hardcode the example host — keep `{{BaseURL}}`/`{{Hostname}}`."
        )
    parts.append(
        "\n## Instructions\nReturn ONLY the corrected raw YAML with tightened matchers. "
        "Keep it portable and detection-focused."
    )
    return "\n".join(parts)


async def refine_template(
    db: Session,
    *,
    organization_id: int,
    template_logic_issue: str,
    original_yaml: Optional[str] = None,
    template_id: Optional[str] = None,
    target: Optional[str] = None,
    evidence: Optional[str] = None,
    reasoning: Optional[str] = None,
    cve_ids: Optional[list] = None,
    source: str = "ai_refined",
    created_by_user_id: Optional[int] = None,
    example_vulnerability_id: Optional[int] = None,
) -> CustomNucleiTemplate:
    """Generate a tightened template from a mis-detection and save it as a draft.

    Requires either `original_yaml` or a `template_id` that can be resolved to YAML.
    """
    from datetime import datetime

    if not original_yaml and template_id:
        original_yaml = lookup_template_yaml(db, organization_id, template_id)
    if not original_yaml:
        raise ValueError("refine_template requires original_yaml or a resolvable template_id")

    prompt = build_refinement_prompt(
        original_yaml=original_yaml,
        template_logic_issue=template_logic_issue,
        target=target,
        evidence=evidence,
        reasoning=reasoning,
    )
    raw = await call_llm(NUCLEI_REFINE_SYSTEM_PROMPT, prompt)
    clean_yaml = extract_yaml_from_response(raw)
    clean_yaml = strip_hardcoded_host(clean_yaml, target)
    meta = parse_yaml_metadata(clean_yaml)

    base_id = meta.get("template_id") or template_id or f"refined-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
    new_template_id = base_id if base_id.endswith("-refined") else f"{base_id}-refined"

    existing = (
        db.query(CustomNucleiTemplate)
        .filter(
            CustomNucleiTemplate.organization_id == organization_id,
            CustomNucleiTemplate.template_id == new_template_id,
        )
        .first()
    )
    if existing:
        new_template_id = f"{new_template_id}-{datetime.utcnow().strftime('%H%M%S')}"

    merged_cves = list({c.upper() for c in (meta.get("cve_ids") or []) + (cve_ids or [])})

    context = json.dumps({
        "refined_from_template_id": template_id,
        "template_logic_issue": template_logic_issue,
        "false_positive_target": target,
        "example_vulnerability_id": example_vulnerability_id,
        "reasoning": reasoning,
    }, default=str)[:4000]

    t = CustomNucleiTemplate(
        organization_id=organization_id,
        template_id=new_template_id,
        name=(meta.get("template_id") or new_template_id),
        description=f"Refined from {template_id or 'an existing template'} to fix a validated false positive.",
        template_yaml=clean_yaml,
        cve_ids=merged_cves,
        severity=meta.get("severity"),
        tags=meta.get("tags") or [],
        template_type=meta.get("template_type", "http"),
        source=source,
        ai_model=resolved_ai_model(),
        ai_generation_context=context,
        status="draft",
        created_by_user_id=created_by_user_id,
    )
    db.add(t)
    db.commit()
    db.refresh(t)
    return t


# ── Validation gate ────────────────────────────────────────────────────────────

async def validate_template_yaml(template_yaml: str, timeout_sec: int = 30) -> dict:
    """Validate a template with `nuclei -validate`.

    Returns {"ran": bool, "valid": bool|None, "output": str, "error": str|None}.
    When nuclei is not installed, `ran` is False and callers should decide whether
    to allow activation anyway (fail-open) rather than block on a missing binary.
    """
    result = {"ran": False, "valid": None, "output": "", "error": None}
    if not template_yaml or not template_yaml.strip():
        result["error"] = "empty_template"
        result["valid"] = False
        return result

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as fh:
            fh.write(template_yaml)
            tmp_path = fh.name

        def _run():
            return subprocess.run(
                ["nuclei", "-t", tmp_path, "-validate", "-no-color"],
                capture_output=True, text=True, timeout=timeout_sec,
            )

        try:
            proc = await asyncio.to_thread(_run)
        except FileNotFoundError:
            result["error"] = "nuclei_not_installed"
            return result
        except subprocess.TimeoutExpired:
            result["error"] = "validate_timeout"
            return result

        result["ran"] = True
        output = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
        result["output"] = output[:4000]
        # `-validate` exits non-zero when a template fails validation.
        result["valid"] = proc.returncode == 0
    except Exception as e:
        result["error"] = str(e)[:255]
        logger.warning("Template validation failed to run: %s", e)
    finally:
        if tmp_path:
            try:
                Path(tmp_path).unlink(missing_ok=True)
            except OSError:
                pass
    return result


# ── Re-check guard ─────────────────────────────────────────────────────────────

async def recheck_template_against_target(
    template_yaml: str,
    target: str,
    timeout_sec: int = 60,
) -> dict:
    """Re-run a template against the known false-positive target.

    Returns {"ran": bool, "still_fires": bool, "match_count": int, "error": str|None}.
    A refined template that still fires on the known-FP target should not be trusted.
    """
    result = {"ran": False, "still_fires": None, "match_count": 0, "error": None}
    if not template_yaml or not target:
        result["error"] = "missing_template_or_target"
        return result

    tmp_path = None
    try:
        from app.services.nuclei_service import NucleiService
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as fh:
            fh.write(template_yaml)
            tmp_path = fh.name

        svc = NucleiService()
        if not svc.check_installation():
            result["error"] = "nuclei_not_installed"
            return result

        scan = await svc.scan_targets(
            targets=[target],
            severity=["critical", "high", "medium", "low", "info"],
            templates=[tmp_path],
            timeout=timeout_sec,
        )
        result["ran"] = True
        result["match_count"] = len(scan.findings or [])
        result["still_fires"] = result["match_count"] > 0
    except Exception as e:
        result["error"] = str(e)[:255]
        logger.warning("Template re-check failed for %s: %s", target, e)
    finally:
        if tmp_path:
            try:
                Path(tmp_path).unlink(missing_ok=True)
            except OSError:
                pass
    return result
