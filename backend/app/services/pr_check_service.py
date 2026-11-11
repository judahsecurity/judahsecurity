"""Pull-request security checks: changed source in, advisory findings + routes out.

The CI client uploads only changed files (no repository credentials reach
Judah). Two passes run on them:

1. Route extraction — HTTP routes and the input names they read, for Flask,
   FastAPI, Django, Express and Spring. These become value-free operations for
   Prowl's live coverage via the ``import_source_routes`` agent tool.
2. Rules — a small built-in high-signal rule set on added lines, plus semgrep
   when its binary is installed on the backend host.

Source-only findings are advisory and capped at medium: matching the agent's
finding gate, a code pattern alone cannot be filed as high/critical without a
live reproduction.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

MAX_FILES = 300
MAX_FILE_BYTES = 256_000
MAX_TOTAL_BYTES = 5_000_000
MAX_FINDINGS = 200
MAX_ROUTES = 500
SOURCE_ONLY_SEVERITY_CAP = "medium"
SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")

_SKIP_PATH = re.compile(
    r"(^|/)(node_modules|vendor|dist|build|\.git|__pycache__|\.venv|venv|coverage)/"
    r"|\.(min\.js|lock|map|png|jpe?g|gif|svg|ico|pdf|zip|gz|woff2?|ttf)$"
    r"|(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock)$",
    re.I,
)
_LANG = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".cjs": "javascript", ".ts": "javascript", ".tsx": "javascript",
    ".java": "java", ".kt": "java", ".go": "go", ".rb": "ruby", ".php": "php",
}


@dataclass
class ChangedFile:
    path: str
    content: str
    added_lines: Optional[set] = None  # None = treat every line as added

    @property
    def language(self) -> str:
        return _LANG.get(os.path.splitext(self.path)[1].lower(), "")


@dataclass
class PrCheckResult:
    findings: List[Dict[str, Any]] = field(default_factory=list)
    routes: List[Dict[str, Any]] = field(default_factory=list)
    skipped_files: List[str] = field(default_factory=list)
    engines: List[str] = field(default_factory=list)

    def conclusion(self, fail_on: str) -> str:
        if fail_on == "never":
            return "success" if not self.findings else "neutral"
        threshold = SEVERITY_ORDER.index(fail_on) if fail_on in SEVERITY_ORDER else 2
        if any(SEVERITY_ORDER.index(f["severity"]) >= threshold for f in self.findings):
            return "failure"
        return "success"

    def summary(self) -> Dict[str, Any]:
        counts: Dict[str, int] = {}
        for finding in self.findings:
            counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
        return {
            "findings": len(self.findings), "by_severity": counts,
            "routes": len(self.routes), "engines": self.engines,
            "skipped_files": len(self.skipped_files),
            "severity_cap": SOURCE_ONLY_SEVERITY_CAP,
        }


def added_lines_from_patch(patch: str) -> set:
    """Line numbers (new side) added by a unified diff hunk set."""
    lines: set = set()
    current = None
    for raw in (patch or "").splitlines():
        header = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", raw)
        if header:
            current = int(header.group(1))
            continue
        if current is None:
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            lines.add(current)
            current += 1
        elif raw.startswith("-") and not raw.startswith("---"):
            continue
        else:
            current += 1
    return lines


def prepare_files(raw_files: Iterable[Dict[str, Any]]) -> Tuple[List[ChangedFile], List[str]]:
    files: List[ChangedFile] = []
    skipped: List[str] = []
    total = 0
    for raw in raw_files:
        if not isinstance(raw, dict):
            continue
        path = str(raw.get("path") or "").lstrip("/")
        content = raw.get("content")
        if (not path or ".." in path.split("/") or not isinstance(content, str)
                or _SKIP_PATH.search(path) or "\x00" in content[:4096]):
            skipped.append(path[:200])
            continue
        size = len(content.encode("utf-8", "ignore"))
        if size > MAX_FILE_BYTES or total + size > MAX_TOTAL_BYTES or len(files) >= MAX_FILES:
            skipped.append(path[:200])
            continue
        total += size
        patch = raw.get("patch")
        files.append(ChangedFile(path[:300], content,
                                 added_lines_from_patch(patch) if isinstance(patch, str) and patch else None))
    return files, skipped


# ---------------------------------------------------------------------------
# Route extraction
# ---------------------------------------------------------------------------

_FLASK_ROUTE = re.compile(
    r"@\w+(?:\.\w+)*\.route\(\s*['\"]([^'\"]+)['\"](?P<rest>[^\n]*)")
_PY_VERB_ROUTE = re.compile(
    r"@\w+(?:\.\w+)*\.(get|post|put|patch|delete)\(\s*['\"]([^'\"]+)['\"]")
_DJANGO_PATH = re.compile(r"\b(?:re_)?path\(\s*r?['\"]\^?([^'\"]*?)\$?['\"]")
_EXPRESS = re.compile(
    r"\b(?:app|router|server|api|\w+Router)\.(get|post|put|patch|delete|all)\(\s*['\"`]([^'\"`]+)['\"`]")
_SPRING_CLASS = re.compile(r"@RequestMapping\(\s*(?:value\s*=\s*|path\s*=\s*)?\"([^\"]*)\"")
_SPRING_METHOD = re.compile(
    r"@(Get|Post|Put|Patch|Delete|Request)Mapping\(\s*(?:value\s*=\s*|path\s*=\s*)?\"([^\"]*)\"([^)]*)\)")

_PY_PARAM_PATTERNS = (
    (re.compile(r"request\.args(?:\.get\(|\[)\s*['\"]([A-Za-z_][\w.-]{0,79})['\"]"), "query"),
    (re.compile(r"request\.(?:form|values)(?:\.get\(|\[)\s*['\"]([A-Za-z_][\w.-]{0,79})['\"]"), "body_form"),
    (re.compile(r"request\.(?:json|get_json\(\)[^\n]*?)(?:\.get\(|\[)\s*['\"]([A-Za-z_][\w.-]{0,79})['\"]"), "body_json"),
    (re.compile(r"request\.GET(?:\.get\(|\[)\s*['\"]([A-Za-z_][\w.-]{0,79})['\"]"), "query"),
    (re.compile(r"request\.POST(?:\.get\(|\[)\s*['\"]([A-Za-z_][\w.-]{0,79})['\"]"), "body_form"),
)
_JS_PARAM_PATTERNS = (
    (re.compile(r"req\.query\.([A-Za-z_$][\w$]{0,79})"), "query"),
    (re.compile(r"req\.query\[\s*['\"]([^'\"]{1,80})['\"]\s*\]"), "query"),
    (re.compile(r"req\.body\.([A-Za-z_$][\w$]{0,79})"), "body_json"),
    (re.compile(r"req\.body\[\s*['\"]([^'\"]{1,80})['\"]\s*\]"), "body_json"),
)
_JS_DESTRUCTURE = re.compile(r"(?:const|let|var)\s*\{([^}]{1,400})\}\s*=\s*req\.(query|body)\b")
_SPRING_PARAM = re.compile(
    r"@RequestParam\(\s*(?:(?:value|name)\s*=\s*)?\"([^\"]+)\"[^)]*\)|@RequestParam(?:\([^)]*\))?\s+\w+(?:<[^>]*>)?\s+(\w+)")
_SPRING_BODY = re.compile(r"@RequestBody\b")
_FASTAPI_SIG = re.compile(r"(?:async\s+)?def\s+\w+\(([^)]*)\)", re.S)
_FASTAPI_SKIP = re.compile(r"Depends\(|Body\(|Header\(|Cookie\(|File\(|Form\(|Request\b|Response\b|Session\b|BackgroundTasks")


def _normalize_route_path(path: str) -> str:
    path = re.sub(r"<(?:[a-z]+:)?([A-Za-z_]\w*)>", r"{\1}", path)          # Flask / Django
    path = re.sub(r"(?<=/):([A-Za-z_]\w*)\??", r"{\1}", path)              # Express
    path = re.sub(r"\(\?P<([A-Za-z_]\w*)>[^)]*\)", r"{\1}", path)          # Django regex
    path = re.sub(r"\{([A-Za-z_]\w*):[^}]*\}", r"{\1}", path)             # Spring regex
    if not path.startswith("/"):
        path = "/" + path
    return re.sub(r"/{2,}", "/", path)[:300]


def _block_end(lines: List[str], start: int, language: str) -> int:
    """Bounded handler body: until the next route declaration or 80 lines."""
    stop = min(len(lines), start + 80)
    for index in range(start + 1, stop):
        line = lines[index]
        if language == "python" and (line.startswith("@") or (line.startswith("def ") and index > start + 1)):
            return index
        if language == "javascript" and _EXPRESS.search(line):
            return index
        if language == "java" and _SPRING_METHOD.search(line):
            return index
    return stop


def _params_in(block: str, language: str) -> List[Tuple[str, str]]:
    found: List[Tuple[str, str]] = []
    if language == "python":
        for pattern, location in _PY_PARAM_PATTERNS:
            found += [(location, m.group(1)) for m in pattern.finditer(block)]
    elif language == "javascript":
        for pattern, location in _JS_PARAM_PATTERNS:
            found += [(location, m.group(1)) for m in pattern.finditer(block)]
        for match in _JS_DESTRUCTURE.finditer(block):
            location = "query" if match.group(2) == "query" else "body_json"
            for part in match.group(1).split(","):
                name = part.split(":")[0].split("=")[0].strip()
                if re.fullmatch(r"[A-Za-z_$][\w$]{0,79}", name):
                    found.append((location, name))
    elif language == "java":
        for match in _SPRING_PARAM.finditer(block):
            found.append(("query", match.group(1) or match.group(2)))
    out: List[Tuple[str, str]] = []
    for item in found:
        if item not in out:
            out.append(item)
    return out[:40]


def _fastapi_query_params(block: str, path_names: Sequence[str]) -> List[Tuple[str, str]]:
    match = _FASTAPI_SIG.search(block)
    if not match:
        return []
    out = []
    depth, current, parts = 0, "", []
    for char in match.group(1):
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        if char == "," and depth == 0:
            parts.append(current)
            current = ""
        else:
            current += char
    parts.append(current)
    for part in parts:
        part = part.strip()
        if not part or part.startswith("*") or _FASTAPI_SKIP.search(part):
            continue
        name = part.split(":")[0].split("=")[0].strip()
        annotation = part.split(":", 1)[1] if ":" in part else ""
        if name in ("self", "cls") or name in path_names or not re.fullmatch(r"[A-Za-z_]\w{0,79}", name):
            continue
        # A capitalized, non-builtin annotation is usually a Pydantic body model.
        base = annotation.split("=")[0].strip()
        if re.match(r"(Optional\[)?[A-Z]", base) and not re.match(
                r"(Optional\[)?(List|Dict|Set|Literal|Annotated)\b", base):
            continue
        out.append(("query", name))
    return out


def extract_routes(files: Sequence[ChangedFile]) -> List[Dict[str, Any]]:
    routes: List[Dict[str, Any]] = []

    def add(method: str, path: str, file: ChangedFile, line: int, framework: str,
            params: List[Tuple[str, str]]) -> None:
        if len(routes) >= MAX_ROUTES:
            return
        method = method.upper()
        if method in ("ALL", "REQUEST"):
            method = "GET"
        if method not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
            return
        norm = _normalize_route_path(path)
        path_names = re.findall(r"\{([A-Za-z_]\w*)\}", norm)
        routes.append({
            "method": method, "path": norm, "framework": framework,
            "file": file.path, "line": line,
            "path_parameters": path_names,
            "parameters": [{"location": loc, "name": name} for loc, name in params
                           if name not in path_names],
        })

    for file in files:
        lines = file.content.splitlines()
        language = file.language
        if language == "python":
            for index, line in enumerate(lines):
                flask = _FLASK_ROUTE.search(line)
                verb = _PY_VERB_ROUTE.search(line)
                django = _DJANGO_PATH.search(line) if "urls" in file.path.rsplit("/", 1)[-1] else None
                if not (flask or verb or django):
                    continue
                block = "\n".join(lines[index:_block_end(lines, index, language)])
                if flask:
                    methods = re.findall(r"['\"](GET|POST|PUT|PATCH|DELETE)['\"]", flask.group("rest"), re.I)
                    params = _params_in(block, language)
                    for method in methods or ["GET"]:
                        add(method, flask.group(1), file, index + 1, "flask", params)
                elif verb:
                    norm = _normalize_route_path(verb.group(2))
                    names = re.findall(r"\{([A-Za-z_]\w*)\}", norm)
                    params = _params_in(block, language) + _fastapi_query_params(block, names)
                    add(verb.group(1), verb.group(2), file, index + 1, "fastapi", params)
                elif django:
                    add("GET", django.group(1), file, index + 1, "django", [])
        elif language == "javascript":
            for index, line in enumerate(lines):
                match = _EXPRESS.search(line)
                if not match or not match.group(2).startswith("/"):
                    continue
                block = "\n".join(lines[index:_block_end(lines, index, language)])
                add(match.group(1), match.group(2), file, index + 1, "express",
                    _params_in(block, language))
        elif language == "java":
            prefix = ""
            for index, line in enumerate(lines):
                cls = _SPRING_CLASS.search(line)
                if cls and re.search(r"\bclass\b", "\n".join(lines[index:index + 4])):
                    prefix = cls.group(1)
                    continue
                match = _SPRING_METHOD.search(line)
                if not match:
                    continue
                verb = match.group(1)
                if verb == "Request":
                    explicit = re.search(r"RequestMethod\.(GET|POST|PUT|PATCH|DELETE)", match.group(3))
                    verb = explicit.group(1) if explicit else "GET"
                block = "\n".join(lines[index:_block_end(lines, index, language)])
                params = _params_in(block, language)
                if _SPRING_BODY.search(block) and verb.upper() != "GET":
                    params.append(("body_json", "*"))
                add(verb, prefix.rstrip("/") + "/" + match.group(2).lstrip("/"), file,
                    index + 1, "spring", [p for p in params if p[1] != "*"])
    return routes


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    languages: Tuple[str, ...]
    pattern: re.Pattern
    severity: str
    cwe: str
    lead: str  # the live test class this suggests
    mask: bool = False


RULES: Tuple[Rule, ...] = (
    Rule("py-sql-format", "SQL built with string formatting", ("python",),
         re.compile(r"\.execute\(\s*(?:f['\"]|['\"][^'\"]*['\"]\s*(?:%|\.format\(|\+))", re.I),
         "medium", "CWE-89", "sqli"),
    Rule("js-sql-template", "SQL built with a template literal", ("javascript",),
         re.compile(r"\.(?:query|execute|raw)\(\s*`[^`]*\$\{", re.I), "medium", "CWE-89", "sqli"),
    Rule("java-sql-concat", "SQL built by string concatenation", ("java",),
         re.compile(r"(?:executeQuery|executeUpdate|prepareStatement|createQuery)\(\s*\"[^\"]*\"\s*\+"),
         "medium", "CWE-89", "sqli"),
    Rule("py-shell-true", "Shell command with shell=True", ("python",),
         re.compile(r"subprocess\.\w+\([^\n]*shell\s*=\s*True|\bos\.system\("), "medium", "CWE-78", "rce"),
    Rule("js-child-exec", "Shell command via child_process.exec", ("javascript",),
         re.compile(r"\bexec(?:Sync)?\(\s*(?:`[^`]*\$\{|[^'\"`\s][^)]*\+)"), "medium", "CWE-78", "rce"),
    Rule("py-unsafe-deserialize", "Unsafe deserialization", ("python",),
         re.compile(r"\bpickle\.loads?\(|\byaml\.load\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)(?![^)]*SafeLoader)"),
         "medium", "CWE-502", "deserialization"),
    Rule("js-eval", "Dynamic code evaluation", ("javascript",),
         re.compile(r"(?<![\w.])eval\(|new\s+Function\("), "medium", "CWE-95", "rce"),
    Rule("js-html-sink", "Raw HTML sink", ("javascript",),
         re.compile(r"dangerouslySetInnerHTML|\.innerHTML\s*=|\.outerHTML\s*=|document\.write\("),
         "low", "CWE-79", "xss"),
    Rule("tls-verify-off", "TLS certificate verification disabled", ("python", "javascript"),
         re.compile(r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED"),
         "low", "CWE-295", ""),
    Rule("jwt-no-verify", "JWT accepted without signature verification", ("python", "javascript"),
         re.compile(r"verify_signature['\"]?\s*:\s*False|algorithms\s*=\s*\[\s*['\"]none['\"]|"
                    r"jwt\.decode\([^)]*verify\s*=\s*False", re.I),
         "medium", "CWE-347", "auth_logic"),
    Rule("open-redirect", "Redirect to a request-controlled URL", ("python", "javascript"),
         re.compile(r"redirect\(\s*(?:request\.(?:args|GET|values)|req\.query)"), "low", "CWE-601", "redirect"),
    Rule("hardcoded-secret", "Hard-coded credential", ("python", "javascript", "java", "go", "ruby", "php"),
         re.compile(r"(?i)\b(api[_-]?key|secret[_-]?key|client[_-]?secret|password|passwd|token)\b"
                    r"['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-+/=]{12,})['\"]"),
         "medium", "CWE-798", "", mask=True),
)
_PLACEHOLDER_SECRET = re.compile(r"(?i)example|changeme|placeholder|your[_-]|xxxx|dummy|test|sample")


def _mask(snippet: str) -> str:
    return re.sub(r"(['\"])([A-Za-z0-9_\-+/=]{4})[A-Za-z0-9_\-+/=]{8,}(['\"])", r"\1\2…\3", snippet)


def _route_for(routes: Sequence[Dict[str, Any]], path: str, line: int) -> Optional[Dict[str, Any]]:
    best = None
    for route in routes:
        if route["file"] == path and route["line"] <= line and (best is None or route["line"] > best["line"]):
            best = route
    if best and line - best["line"] <= 80:
        return {"method": best["method"], "path": best["path"]}
    return None


def _cap(severity: str) -> str:
    if SEVERITY_ORDER.index(severity) > SEVERITY_ORDER.index(SOURCE_ONLY_SEVERITY_CAP):
        return SOURCE_ONLY_SEVERITY_CAP
    return severity


def run_rules(files: Sequence[ChangedFile], routes: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for file in files:
        language = file.language
        if not language:
            continue
        for number, line in enumerate(file.content.splitlines(), start=1):
            if file.added_lines is not None and number not in file.added_lines:
                continue
            if len(line) > 2000:
                continue
            for rule in RULES:
                if language not in rule.languages:
                    continue
                match = rule.pattern.search(line)
                if not match:
                    continue
                if rule.id == "hardcoded-secret" and _PLACEHOLDER_SECRET.search(match.group(2)):
                    continue
                snippet = line.strip()[:240]
                findings.append({
                    "rule_id": rule.id, "engine": "judah-rules", "title": rule.title,
                    "severity": _cap(rule.severity), "cwe": rule.cwe,
                    "file": file.path, "line": number,
                    "snippet": _mask(snippet) if rule.mask else snippet,
                    "live_test_class": rule.lead,
                    "route": _route_for(routes, file.path, number),
                    "verification_level": "source_only", "advisory": True,
                })
                if len(findings) >= MAX_FINDINGS:
                    return findings
    return findings


def run_semgrep(files: Sequence[ChangedFile], routes: Sequence[Dict[str, Any]],
                *, config: str = "p/default", timeout: int = 120) -> Optional[List[Dict[str, Any]]]:
    """Run semgrep on the uploaded files when installed; None when unavailable."""
    binary = shutil.which("semgrep")
    if not binary or not files:
        return None
    findings: List[Dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="prcheck-") as workspace:
        for file in files:
            target = os.path.join(workspace, file.path)
            if not os.path.realpath(target).startswith(os.path.realpath(workspace) + os.sep):
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "w", encoding="utf-8") as handle:
                handle.write(file.content)
        try:
            proc = subprocess.run(
                [binary, "scan", "--config", config, "--json", "--quiet", "--metrics=off",
                 "--disable-version-check", workspace],
                capture_output=True, text=True, timeout=timeout, check=False,
            )
            payload = json.loads(proc.stdout or "{}")
        except (subprocess.TimeoutExpired, ValueError, OSError):
            return None
    by_path = {f.path: f for f in files}
    severity_map = {"ERROR": "medium", "WARNING": "low", "INFO": "info"}
    for result in payload.get("results") or []:
        rel = os.path.relpath(str(result.get("path") or ""), workspace)
        line = int((result.get("start") or {}).get("line") or 0)
        changed = by_path.get(rel)
        if changed is None or (changed.added_lines is not None and line not in changed.added_lines):
            continue
        extra = result.get("extra") or {}
        cwe = (extra.get("metadata") or {}).get("cwe")
        findings.append({
            "rule_id": str(result.get("check_id") or "")[:160], "engine": "semgrep",
            "title": str(extra.get("message") or "")[:300],
            "severity": _cap(severity_map.get(str(extra.get("severity") or ""), "low")),
            "cwe": (cwe[0] if isinstance(cwe, list) and cwe else str(cwe or ""))[:80],
            "file": rel, "line": line, "snippet": "",
            "live_test_class": "", "route": _route_for(routes, rel, line),
            "verification_level": "source_only", "advisory": True,
        })
        if len(findings) >= MAX_FINDINGS:
            break
    return findings


def analyze(raw_files: Iterable[Dict[str, Any]], *, use_semgrep: bool = True) -> PrCheckResult:
    files, skipped = prepare_files(raw_files)
    result = PrCheckResult(skipped_files=skipped)
    result.routes = extract_routes(files)
    result.findings = run_rules(files, result.routes)
    result.engines.append("judah-rules")
    if use_semgrep:
        semgrep = run_semgrep(files, result.routes)
        if semgrep is not None:
            result.engines.append("semgrep")
            seen = {(f["file"], f["line"], f["cwe"]) for f in result.findings}
            result.findings += [f for f in semgrep if (f["file"], f["line"], f["cwe"]) not in seen]
    result.findings.sort(key=lambda f: (-SEVERITY_ORDER.index(f["severity"]), f["file"], f["line"]))
    result.findings = result.findings[:MAX_FINDINGS]
    return result


def synthetic_requests_for_routes(routes: Iterable[Dict[str, Any]], origin: str) -> List[Dict[str, Any]]:
    """Value-free requests for the operation ledger (same shape as spec import)."""
    from urllib.parse import urlencode

    from app.services.api_spec_import import _fill_path, normalize_origin

    origin = normalize_origin(origin)
    if not origin:
        return []
    out = []
    for route in list(routes)[:MAX_ROUTES]:
        path, _ = _fill_path(str(route.get("path") or "/"))
        params = [p for p in route.get("parameters") or [] if isinstance(p, dict)]
        query = {p["name"]: "test" for p in params if p.get("location") == "query"}
        body_json = {p["name"]: "test" for p in params if p.get("location") == "body_json"}
        body_form = {p["name"]: "test" for p in params if p.get("location") == "body_form"}
        headers: Dict[str, str] = {}
        body: Any = ""
        if body_json:
            headers["Content-Type"], body = "application/json", body_json
        elif body_form:
            headers["Content-Type"], body = "application/x-www-form-urlencoded", urlencode(body_form)
        out.append({"url": origin + path + ("?" + urlencode(query) if query else ""),
                    "method": route.get("method", "GET"), "headers": headers, "body": body})
    return out
