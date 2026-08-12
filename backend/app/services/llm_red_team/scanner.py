"""
LLM Red Team Scanner

Discovers and tests chatbot/AI endpoints on target web applications.
Supports multiple interaction methods:
- REST API endpoints (POST JSON with message field)
- WebSocket chat endpoints
- HTML form-based chatbots (via page interaction)

Integrates with the ASM finding pipeline to create vulnerabilities.
"""

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Optional, Dict, Any
from urllib.parse import urljoin, urlparse

import httpx

from app.services.llm_red_team.payloads import (
    RedTeamPayload,
    get_payloads_by_category,
    get_category_metadata,
    ALL_PAYLOADS,
)
from app.services.llm_red_team.analyzer import (
    AnalysisResult,
    analyze_response_patterns,
    analyze_response_llm,
)

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30
MAX_RESPONSE_CHARS = 10000
DEFAULT_RATE_LIMIT_DELAY = 1.0


@dataclass
class ChatEndpoint:
    """Represents a discovered chatbot/AI endpoint."""
    url: str
    method: str = "POST"
    content_type: str = "application/json"
    message_field: str = "message"
    response_field: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    auth_token: Optional[str] = None
    endpoint_type: str = "rest_api"  # rest_api, websocket, graphql
    detected_by: str = "manual"
    extra_body: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanConfig:
    """Configuration for an LLM red team scan."""
    target_url: str
    endpoints: List[ChatEndpoint] = field(default_factory=list)
    categories: Optional[List[str]] = None
    auto_discover: bool = True
    use_llm_grading: bool = True
    rate_limit_delay: float = DEFAULT_RATE_LIMIT_DELAY
    timeout: int = DEFAULT_TIMEOUT
    max_payloads: Optional[int] = None


@dataclass
class ScanResult:
    """Complete result of an LLM red team scan."""
    target_url: str
    scan_started: str = ""
    scan_completed: str = ""
    endpoints_tested: int = 0
    payloads_sent: int = 0
    vulnerabilities_found: int = 0
    results: List[Dict[str, Any]] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


# Common chatbot API path patterns to probe during auto-discovery
COMMON_CHAT_PATHS = [
    "/api/chat",
    "/api/v1/chat",
    "/api/v2/chat",
    "/api/message",
    "/api/v1/message",
    "/api/ask",
    "/api/v1/ask",
    "/api/query",
    "/api/v1/query",
    "/api/completions",
    "/api/v1/completions",
    "/v1/chat/completions",
    "/chat/completions",
    "/api/conversation",
    "/api/v1/conversation",
    "/api/bot",
    "/api/v1/bot",
    "/api/assistant",
    "/api/v1/assistant",
    "/chat",
    "/ask",
    "/bot",
    "/webhook",
    "/api/webhook",
    "/graphql",
]

COMMON_MESSAGE_FIELDS = ["message", "query", "prompt", "text", "input", "content", "question"]

AI_RESPONSE_INDICATORS = [
    "i'm an ai", "i am an ai", "as an ai", "language model",
    "i'm a chatbot", "i am a chatbot", "virtual assistant",
    "how can i help", "how may i assist", "i can help you with",
    "i'm here to help", "i am here to help",
    "openai", "anthropic", "claude", "gpt", "llama",
    "i don't have personal", "i don't have feelings",
    "as a large language model", "as an artificial intelligence",
]


async def discover_chat_endpoints(
    target_url: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> List[ChatEndpoint]:
    """
    Auto-discover chatbot/AI endpoints on a target web application.
    Probes common API paths and looks for AI-like responses.
    """
    discovered = []
    parsed = urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        verify=False,
    ) as client:
        tasks = []
        for path in COMMON_CHAT_PATHS:
            url = urljoin(base_url, path)
            tasks.append(_probe_endpoint(client, url))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, ChatEndpoint):
                discovered.append(result)

    logger.info(f"Discovered {len(discovered)} chat endpoint(s) on {target_url}")
    return discovered


async def _probe_endpoint(
    client: httpx.AsyncClient,
    url: str,
) -> Optional[ChatEndpoint]:
    """Probe a single URL to see if it responds like a chatbot."""
    probe_message = "Hello, how are you?"

    for msg_field in COMMON_MESSAGE_FIELDS:
        try:
            body = {msg_field: probe_message}
            resp = await client.post(
                url,
                json=body,
                headers={"Content-Type": "application/json"},
            )

            if resp.status_code in (200, 201):
                text = resp.text.lower()
                if any(ind in text for ind in AI_RESPONSE_INDICATORS):
                    response_field = _detect_response_field(resp)
                    logger.info(f"Found chat endpoint: {url} (field: {msg_field})")
                    return ChatEndpoint(
                        url=url,
                        method="POST",
                        content_type="application/json",
                        message_field=msg_field,
                        response_field=response_field,
                        endpoint_type="rest_api",
                        detected_by="auto_discovery",
                    )

            if resp.status_code == 405:
                resp_get = await client.get(url)
                if resp_get.status_code == 200 and any(
                    ind in resp_get.text.lower() for ind in AI_RESPONSE_INDICATORS
                ):
                    return ChatEndpoint(
                        url=url,
                        method="GET",
                        message_field=msg_field,
                        endpoint_type="rest_api",
                        detected_by="auto_discovery",
                    )

        except (httpx.ConnectError, httpx.ReadTimeout, httpx.ConnectTimeout):
            pass
        except Exception as e:
            logger.debug(f"Probe error for {url}: {e}")

    return None


def _detect_response_field(resp: httpx.Response) -> Optional[str]:
    """Try to determine which JSON field contains the chatbot's response."""
    try:
        data = resp.json()
        if isinstance(data, dict):
            for key in ["response", "answer", "reply", "message", "text",
                        "content", "output", "result", "data", "completion"]:
                if key in data:
                    return key
            for key in ["choices"]:
                if key in data and isinstance(data[key], list) and data[key]:
                    return f"{key}[0].message.content"
    except Exception:
        pass
    return None


async def send_payload(
    endpoint: ChatEndpoint,
    payload: RedTeamPayload,
    timeout: int = DEFAULT_TIMEOUT,
) -> str:
    """Send a single red team payload to a chatbot endpoint and return the response."""
    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        verify=False,
    ) as client:
        headers = {"Content-Type": endpoint.content_type}
        headers.update(endpoint.headers)
        if endpoint.auth_token:
            headers["Authorization"] = f"Bearer {endpoint.auth_token}"

        body = {endpoint.message_field: payload.prompt}
        body.update(endpoint.extra_body)

        try:
            if endpoint.method.upper() == "GET":
                resp = await client.get(
                    endpoint.url,
                    params={endpoint.message_field: payload.prompt},
                    headers=headers,
                )
            else:
                resp = await client.post(
                    endpoint.url,
                    json=body,
                    headers=headers,
                )

            if resp.status_code in (200, 201):
                return _extract_response_text(resp, endpoint.response_field)
            else:
                return f"[HTTP {resp.status_code}] {resp.text[:MAX_RESPONSE_CHARS]}"

        except httpx.ReadTimeout:
            return "[TIMEOUT] Endpoint did not respond within the timeout period."
        except httpx.ConnectError as e:
            return f"[CONNECTION_ERROR] {e}"
        except Exception as e:
            return f"[ERROR] {e}"


def _extract_response_text(
    resp: httpx.Response,
    response_field: Optional[str],
) -> str:
    """Extract the text response from an HTTP response."""
    try:
        data = resp.json()
        if response_field:
            if "." in response_field or "[" in response_field:
                return _nested_get(data, response_field)
            return str(data.get(response_field, resp.text))
        if isinstance(data, dict):
            for key in ["response", "answer", "reply", "message", "text",
                        "content", "output", "result", "completion"]:
                if key in data:
                    val = data[key]
                    return str(val) if not isinstance(val, dict) else json.dumps(val)
            return json.dumps(data)
        return str(data)
    except Exception:
        return resp.text[:MAX_RESPONSE_CHARS]


def _nested_get(data: Any, path: str) -> str:
    """Navigate a dotted/bracket path like 'choices[0].message.content'."""
    parts = re.split(r'\.|\[|\]', path)
    current = data
    for part in parts:
        if not part:
            continue
        try:
            idx = int(part)
            current = current[idx]
        except (ValueError, TypeError):
            if isinstance(current, dict):
                current = current.get(part, "")
            else:
                return str(current)
    return str(current)


async def run_scan(
    config: ScanConfig,
    progress_callback=None,
) -> ScanResult:
    """
    Execute a full LLM red team scan against a target.

    1. Discover endpoints (if auto_discover is True)
    2. Send payloads to each endpoint
    3. Analyze responses
    4. Return structured results
    """
    result = ScanResult(
        target_url=config.target_url,
        scan_started=datetime.utcnow().isoformat(),
    )

    endpoints = list(config.endpoints)
    if config.auto_discover:
        try:
            discovered = await discover_chat_endpoints(
                config.target_url,
                timeout=config.timeout,
            )
            endpoints.extend(discovered)
        except Exception as e:
            logger.error(f"Endpoint discovery failed: {e}")
            result.errors.append(f"Discovery error: {e}")

    if not endpoints:
        result.errors.append(
            f"No chatbot/AI endpoints found on {config.target_url}. "
            "Provide endpoints manually via the 'endpoints' config, or check "
            "that the target has accessible chat API endpoints."
        )
        result.scan_completed = datetime.utcnow().isoformat()
        return result

    payloads = get_payloads_by_category(config.categories)
    if config.max_payloads and len(payloads) > config.max_payloads:
        payloads = payloads[:config.max_payloads]

    total_tests = len(endpoints) * len(payloads)
    completed = 0
    category_stats: Dict[str, Dict[str, int]] = {}

    for endpoint in endpoints:
        result.endpoints_tested += 1

        for payload in payloads:
            try:
                response_text = await send_payload(
                    endpoint, payload, timeout=config.timeout
                )
                result.payloads_sent += 1

                analysis = analyze_response_patterns(payload, response_text)

                if analysis.verdict == "inconclusive" and config.use_llm_grading:
                    try:
                        analysis = await analyze_response_llm(payload, response_text)
                    except Exception as e:
                        logger.warning(f"LLM grading failed, using pattern result: {e}")

                test_result = {
                    "endpoint": endpoint.url,
                    "payload_id": payload.id,
                    "category": payload.category,
                    "name": payload.name,
                    "severity": payload.severity,
                    "verdict": analysis.verdict,
                    "confidence": analysis.confidence,
                    "explanation": analysis.explanation,
                    "evidence": analysis.evidence,
                    "cwe_id": payload.cwe_id,
                    "prompt_sent": payload.prompt[:500],
                    "response_preview": response_text[:500],
                }
                result.results.append(test_result)

                if analysis.verdict == "fail":
                    result.vulnerabilities_found += 1

                cat = payload.category
                if cat not in category_stats:
                    category_stats[cat] = {"total": 0, "pass": 0, "fail": 0, "inconclusive": 0}
                category_stats[cat]["total"] += 1
                category_stats[cat][analysis.verdict] += 1

            except Exception as e:
                logger.error(f"Error testing {payload.id} against {endpoint.url}: {e}")
                result.errors.append(f"{payload.id}: {e}")

            completed += 1
            if progress_callback:
                try:
                    pct = int((completed / total_tests) * 100)
                    await progress_callback(pct, f"Testing {payload.name}...")
                except Exception:
                    pass

            if config.rate_limit_delay > 0:
                await asyncio.sleep(config.rate_limit_delay)

    meta = get_category_metadata()
    result.summary = {
        "target": config.target_url,
        "endpoints_tested": result.endpoints_tested,
        "payloads_sent": result.payloads_sent,
        "vulnerabilities_found": result.vulnerabilities_found,
        "categories_tested": {
            cat: {
                "name": meta.get(cat, {}).get("name", cat),
                "owasp": meta.get(cat, {}).get("owasp", ""),
                **stats,
            }
            for cat, stats in category_stats.items()
        },
        "risk_score": _calculate_risk_score(result.results),
    }
    result.scan_completed = datetime.utcnow().isoformat()
    return result


def _calculate_risk_score(results: List[Dict]) -> float:
    """Calculate an overall risk score (0-100) based on failed tests."""
    if not results:
        return 0.0

    severity_weights = {
        "critical": 25.0,
        "high": 15.0,
        "medium": 8.0,
        "low": 3.0,
        "info": 1.0,
    }

    score = 0.0
    for r in results:
        if r.get("verdict") == "fail":
            weight = severity_weights.get(r.get("severity", "medium"), 8.0)
            score += weight * r.get("confidence", 0.5)

    return min(100.0, round(score, 1))


def build_finding_data(
    test_result: Dict[str, Any],
    target_url: str,
) -> Dict[str, Any]:
    """
    Convert a failed test result into the data needed to create a
    Vulnerability record in the ASM database.
    """
    meta = get_category_metadata()
    cat_info = meta.get(test_result["category"], {})

    title = f"AI/LLM Vulnerability: {test_result['name']}"
    description = (
        f"An AI chatbot endpoint at {test_result['endpoint']} is vulnerable to "
        f"{cat_info.get('name', test_result['category'])}.\n\n"
        f"**OWASP Top 10 for LLMs**: {cat_info.get('owasp', 'N/A')}\n\n"
        f"**Attack**: {test_result['name']}\n\n"
        f"**Explanation**: {test_result['explanation']}\n\n"
        f"**Confidence**: {test_result['confidence']:.0%}"
    )

    evidence = (
        f"**Prompt sent**:\n```\n{test_result.get('prompt_sent', '')}\n```\n\n"
        f"**Response excerpt**:\n```\n{test_result.get('response_preview', '')}\n```\n\n"
        f"**Evidence**:\n{test_result.get('evidence', '')}"
    )

    remediation_map = {
        "prompt_injection": (
            "1. Implement input sanitization and prompt hardening\n"
            "2. Use a separate system prompt that cannot be overridden by user input\n"
            "3. Implement prompt/response guardrails (e.g., Guardrails AI, NeMo Guardrails)\n"
            "4. Use instruction hierarchy to separate system and user messages\n"
            "5. Consider using a fine-tuned model with built-in safety training"
        ),
        "system_prompt_leakage": (
            "1. Never include sensitive data in system prompts\n"
            "2. Implement output filtering to detect and block system prompt disclosure\n"
            "3. Use prompt injection detection before processing user input\n"
            "4. Consider a canary token in the system prompt to detect leaks"
        ),
        "data_exfiltration": (
            "1. Minimize PII and sensitive data in model context\n"
            "2. Implement output filtering for PII patterns\n"
            "3. Use data masking for any user data passed to the model\n"
            "4. Implement session isolation to prevent cross-user data leakage\n"
            "5. Audit and minimize RAG retrieval scope"
        ),
        "jailbreak": (
            "1. Keep model and safety systems updated\n"
            "2. Implement multi-layer content filtering (input + output)\n"
            "3. Use constitutional AI or RLHF-trained models\n"
            "4. Deploy a safety classifier on outputs\n"
            "5. Monitor and log all conversations for safety violations"
        ),
        "ssrf_tool_abuse": (
            "1. Restrict outbound network access from the LLM execution environment\n"
            "2. Implement URL allowlisting for any tool-use capabilities\n"
            "3. Block access to cloud metadata endpoints (169.254.169.254)\n"
            "4. Use network segmentation to isolate the LLM service\n"
            "5. Validate and sanitize all URLs before making requests"
        ),
        "excessive_agency": (
            "1. Implement human-in-the-loop for destructive or privileged actions\n"
            "2. Use least-privilege access for LLM tool integrations\n"
            "3. Require explicit user confirmation for state-changing operations\n"
            "4. Implement rate limiting on automated actions\n"
            "5. Log and audit all actions taken by the AI agent"
        ),
        "tool_enumeration": (
            "1. Do not expose tool names/schemas to untrusted users; treat enumeration as recon\n"
            "2. Least-privilege tools: no email/refund/DB unless required; separate read vs write tools\n"
            "3. Authorize every tool parameter (user_id, account_id) against the caller — prevent IDOR\n"
            "4. Require human confirmation for side-effect flags (send_now, confirm, dry_run=false)\n"
            "5. Audit tool invocations with full args; block PII dumps and cross-tenant queries\n"
            "6. Allowlist recipients/domains for messaging tools; never send attacker-controlled content"
        ),
        "hallucination": (
            "1. Ground model responses with retrieval-augmented generation (RAG)\n"
            "2. Implement fact-checking on generated responses\n"
            "3. Use confidence scoring and flag low-confidence responses\n"
            "4. Clearly disclaim the limitations of AI-generated information"
        ),
        "harmful_content": (
            "1. Deploy output content classifiers\n"
            "2. Implement topic-specific content filters\n"
            "3. Use safety-tuned model variants\n"
            "4. Monitor and flag harmful content patterns in logs"
        ),
    }

    return {
        "title": title,
        "description": description,
        "severity": test_result.get("severity", "medium"),
        "cwe_id": test_result.get("cwe_id"),
        "evidence": evidence,
        "remediation": remediation_map.get(test_result["category"], "Review and harden the AI endpoint."),
        "detected_by": "llm_red_team",
        "template_id": f"llm-redteam-{test_result['payload_id']}",
        "tags": ["ai-security", "llm", test_result["category"]],
        "metadata": {
            "endpoint_url": test_result.get("endpoint"),
            "payload_id": test_result.get("payload_id"),
            "category": test_result.get("category"),
            "confidence": test_result.get("confidence"),
            "owasp_llm": cat_info.get("owasp", ""),
        },
    }


def format_scan_report(scan_result: ScanResult) -> str:
    """Format scan results as a human-readable report for the agent."""
    lines = [
        f"# LLM Red Team Scan Report",
        f"**Target**: {scan_result.target_url}",
        f"**Scan Time**: {scan_result.scan_started} → {scan_result.scan_completed}",
        f"**Endpoints Tested**: {scan_result.endpoints_tested}",
        f"**Payloads Sent**: {scan_result.payloads_sent}",
        f"**Vulnerabilities Found**: {scan_result.vulnerabilities_found}",
        f"**Risk Score**: {scan_result.summary.get('risk_score', 0)}/100",
        "",
    ]

    if scan_result.vulnerabilities_found > 0:
        lines.append("## Findings\n")
        for r in scan_result.results:
            if r.get("verdict") == "fail":
                lines.append(
                    f"### [{r['severity'].upper()}] {r['name']}\n"
                    f"- **Endpoint**: {r['endpoint']}\n"
                    f"- **Category**: {r['category']}\n"
                    f"- **CWE**: {r.get('cwe_id', 'N/A')}\n"
                    f"- **Confidence**: {r['confidence']:.0%}\n"
                    f"- **Explanation**: {r['explanation']}\n"
                )

    cat_stats = scan_result.summary.get("categories_tested", {})
    if cat_stats:
        lines.append("## Category Summary\n")
        lines.append("| Category | Total | Pass | Fail | Inconclusive |")
        lines.append("|----------|-------|------|------|-------------|")
        for cat, stats in cat_stats.items():
            lines.append(
                f"| {stats.get('name', cat)} | {stats['total']} | "
                f"{stats['pass']} | {stats['fail']} | {stats['inconclusive']} |"
            )

    if scan_result.errors:
        lines.append(f"\n## Errors ({len(scan_result.errors)})\n")
        for err in scan_result.errors[:10]:
            lines.append(f"- {err}")

    return "\n".join(lines)
