"""
OWASP API Security Testing Framework (ASTF) runner.

Complements Judah's human-style API authz methodologies (compare_requests,
OpenAPI mass-assignment / unauth lookup). When crawl/recon detects REST,
OpenAPI, GraphQL, or gRPC surfaces, the agent can run ASTF for OWASP API
Security Top 10 2023 structural checks (BOLA/BFLA, JWT, GraphQL, gRPC, mTLS).

Findings are hypotheses to prove with compare_requests / replay — not auto-
create_finding. See:
  https://github.com/OWASP/www-project-api-security-testing-framework
  docs/TRACEABILITY.md (honest VAmPI/crAPI/DVGA coverage matrix)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import tempfile
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

DEFAULT_JAR = os.environ.get("ASTF_JAR", "").strip() or "/opt/astf/astf.jar"
ASTF_TIMEOUT_SEC = int(os.environ.get("ASTF_TIMEOUT_SEC", "900") or "900")
_MAX_SUMMARY_FINDINGS = 40


def _resolve_java() -> Optional[str]:
    return shutil.which("java")


def _resolve_jar() -> Optional[str]:
    for path in (
        DEFAULT_JAR,
        "/opt/astf/astf-v2.0.1.jar",
        "/opt/astf/astf-v1.0.0.jar",
        os.path.expanduser("~/astf.jar"),
    ):
        if path and os.path.isfile(path):
            return path
    # PATH wrapper may exist without a direct jar env
    if shutil.which("astf"):
        return "astf"
    return None


def _parse_opts(args: Any) -> Dict[str, Any]:
    if isinstance(args, dict):
        return dict(args)
    s = str(args or "").strip()
    if not s:
        return {}
    if s.startswith("{"):
        try:
            return json.loads(s)
        except (json.JSONDecodeError, TypeError):
            return {"url": s}
    # Bare URL
    if s.startswith("http://") or s.startswith("https://") or "://" not in s.split()[0]:
        # Might be full CLI: "-u https://… -f JSON"
        if s.lstrip().startswith("-"):
            return {"cli": s}
        # First token looks like URL/host
        first = s.split()[0]
        if first.startswith("http") or "." in first:
            if " " in s and ("-u" in s or "--token" in s or "-f" in s):
                return {"cli": s if s.lstrip().startswith("-") else f"-u {s}"}
            return {"url": first if first.startswith("http") else f"https://{first}"}
    return {"cli": s}


def _build_argv(opts: Dict[str, Any], out_path: str) -> List[str]:
    """Build java -jar … argv (without java/jar prefix) or wrapper args."""
    if opts.get("cli"):
        import shlex

        extra = shlex.split(str(opts["cli"]))
        # Ensure JSON output for summarization unless caller set -f/-o
        joined = " ".join(extra)
        if "-o" not in joined and "--output" not in joined:
            extra += ["-f", "JSON", "-o", out_path]
        elif "-f" not in joined and "--format" not in joined:
            extra += ["-f", "JSON"]
        return extra

    url = str(opts.get("url") or opts.get("target") or opts.get("-u") or "").strip()
    if not url:
        return []
    if not url.startswith("http"):
        url = f"https://{url}"

    argv = ["-u", url, "-f", "JSON", "-o", out_path]
    token = opts.get("token") or opts.get("bearer") or opts.get("--token")
    if token:
        argv += ["--token", str(token)]
    timeout = opts.get("timeout") or opts.get("--timeout")
    if timeout is not None:
        argv += ["--timeout", str(timeout)]
    test_cases = opts.get("test_cases") or opts.get("--test-cases")
    if test_cases:
        argv += ["--test-cases", str(test_cases)]
    if opts.get("verbose") or opts.get("-v"):
        argv.append("-v")
    return argv


def _summarize_json_report(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        return f"(could not parse ASTF JSON report: {e})"

    findings: List[Dict[str, Any]] = []
    if isinstance(data, list):
        findings = [x for x in data if isinstance(x, dict)]
    elif isinstance(data, dict):
        for key in ("findings", "vulnerabilities", "results", "issues"):
            val = data.get(key)
            if isinstance(val, list):
                findings = [x for x in val if isinstance(x, dict)]
                break
        if not findings and (
            data.get("title") or data.get("name") or data.get("severity")
        ):
            findings = [data]

    if not findings:
        # Dump compact top-level keys for the agent
        keys = list(data.keys())[:20] if isinstance(data, dict) else []
        return f"ASTF finished; no structured findings list parsed (top keys: {keys}). Review raw report."

    lines = [f"ASTF findings: {len(findings)} (showing up to {_MAX_SUMMARY_FINDINGS})"]
    for i, item in enumerate(findings[:_MAX_SUMMARY_FINDINGS]):
        sev = (
            item.get("severity")
            or item.get("Severity")
            or item.get("risk")
            or "?"
        )
        title = (
            item.get("title")
            or item.get("name")
            or item.get("vulnerability")
            or item.get("testCase")
            or item.get("type")
            or "finding"
        )
        endpoint = (
            item.get("endpoint")
            or item.get("url")
            or item.get("path")
            or item.get("location")
            or ""
        )
        evidence = (
            item.get("evidence")
            or item.get("description")
            or item.get("message")
            or ""
        )
        evidence_s = re.sub(r"\s+", " ", str(evidence))[:220]
        lines.append(
            f"{i + 1}. [{sev}] {title}"
            + (f" @ {endpoint}" if endpoint else "")
            + (f" — {evidence_s}" if evidence_s else "")
        )
    if len(findings) > _MAX_SUMMARY_FINDINGS:
        lines.append(f"... +{len(findings) - _MAX_SUMMARY_FINDINGS} more")
    lines.append(
        "Triage: treat CRITICAL/HIGH as hypotheses — prove with compare_requests / "
        "replay_http_request before create_finding. ASTF is complementary structural "
        "coverage (OWASP API Top 10), not a substitute for dual-identity authz proofs."
    )
    return "\n".join(lines)


async def run_astf(args: Any) -> Dict[str, Any]:
    """
    Run OWASP ASTF against a detected API base URL.

    Args: bare URL, CLI string, or JSON:
      {url, token?, timeout?, test_cases?, verbose?}
      or {cli: "-u https://api… --token …"}
    """
    java = _resolve_java()
    jar = _resolve_jar()
    if not java and jar != "astf":
        return {
            "success": False,
            "output": "Java runtime not found. Install Java 21+ (openjdk) for ASTF.",
            "error": "java_not_available",
            "exit_code": -1,
        }
    if not jar:
        return {
            "success": False,
            "output": (
                "ASTF JAR not found. Set ASTF_JAR or install to /opt/astf/astf.jar "
                "(see backend Dockerfile)."
            ),
            "error": "astf_not_available",
            "exit_code": -1,
        }

    opts = _parse_opts(args)
    with tempfile.TemporaryDirectory(prefix="astf_") as tmp:
        out_path = os.path.join(tmp, "astf-report.json")
        argv_flags = _build_argv(opts, out_path)
        if not argv_flags:
            return {
                "success": False,
                "output": (
                    "No API target. Pass a URL or JSON, e.g. "
                    'execute_astf(args="https://api.target.com") or '
                    'execute_astf(args=\'{"url":"https://api.target.com","token":"…"}\').'
                ),
                "error": "no_target",
                "exit_code": 1,
            }

        if jar == "astf":
            cmd = ["astf"] + argv_flags
        else:
            cmd = [java or "java", "-jar", jar] + argv_flags

        # Soft hint in output for the agent
        url_hint = opts.get("url") or ""
        if not url_hint:
            for i, part in enumerate(argv_flags):
                if part in ("-u", "--url") and i + 1 < len(argv_flags):
                    url_hint = argv_flags[i + 1]
                    break
        if url_hint:
            host = urlparse(url_hint if "://" in url_hint else f"https://{url_hint}").netloc
        else:
            host = ""

        timeout = ASTF_TIMEOUT_SEC
        try:
            t = opts.get("timeout_sec") or opts.get("budget_sec")
            if t is not None:
                timeout = max(60, min(int(t), 1800))
        except (TypeError, ValueError):
            pass

        logger.info("ASTF: %s (timeout=%ss)", " ".join(cmd[:6]), timeout)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return {
                    "success": False,
                    "output": f"ASTF timed out after {timeout}s on {host or 'target'}.",
                    "error": "astf_timeout",
                    "exit_code": -1,
                }
        except FileNotFoundError as e:
            return {
                "success": False,
                "output": f"Failed to launch ASTF: {e}",
                "error": "astf_launch_failed",
                "exit_code": -1,
            }
        except Exception as e:
            logger.exception("ASTF failed")
            return {
                "success": False,
                "output": "",
                "error": f"ASTF error: {e}",
                "exit_code": -1,
            }

        out_s = (stdout or b"").decode("utf-8", errors="ignore")
        err_s = (stderr or b"").decode("utf-8", errors="ignore")
        code = proc.returncode if proc.returncode is not None else -1

        summary = ""
        if os.path.isfile(out_path) and os.path.getsize(out_path) > 0:
            summary = _summarize_json_report(out_path)
        elif out_s.strip().startswith("{") or out_s.strip().startswith("["):
            # Some builds print JSON to stdout
            try:
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write(out_s)
                summary = _summarize_json_report(out_path)
            except Exception:
                summary = out_s[:8000]
        else:
            summary = (out_s or err_s or "(no output)")[:8000]

        header = (
            f"OWASP ASTF scan{' of ' + host if host else ''} complete "
            f"(exit={code}). Complementary API Top 10 structural scan — "
            "prove high-severity hits with dual-identity compare_requests.\n\n"
        )
        # Exit 1 often means findings exist — still a successful scan run
        ok = code in (0, 1) and bool(summary.strip())
        return {
            "success": ok,
            "output": header + summary + (f"\n\nstderr:\n{err_s[:2000]}" if err_s and not ok else ""),
            "error": None if ok else (err_s[:500] or f"exit_{code}"),
            "exit_code": code,
        }
