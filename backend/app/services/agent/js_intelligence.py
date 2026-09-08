"""Bounded JS intelligence through the existing HTTP transport.

Static extraction is deliberately heuristic. Credentials remain redacted
candidates; opt-in, provider-specific read-only validators cannot publish findings.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from app.services.agent.evidence_store import origin

MAX_SOURCE = 1024 * 1024
_STRINGS = re.compile(r"""["'`]([^"'`\n]{1,2048})["'`]""")
_PROVIDERS = {
    "github": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
    "stripe": re.compile(r"\bsk_live_[A-Za-z0-9]{16,128}\b"),
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "generic": re.compile(
        r"""(?i)(?:api[_-]?key|client[_-]?secret|access[_-]?token)\s*[:=]\s*["']([A-Za-z0-9_./+\-=]{16,256})["']"""
    ),
}


class Scripts(HTMLParser):
    def __init__(self):
        super().__init__()
        self.urls, self.inline = [], []
        self.active = False
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag != "script":
            return
        attrs = dict(attrs)
        self.active = not attrs.get("src")
        if attrs.get("src"):
            self.urls.append(attrs["src"])
        self.parts = []

    def handle_data(self, data):
        if self.active:
            self.parts.append(data)

    def handle_endtag(self, tag):
        if tag == "script":
            if self.active:
                self.inline.append("".join(self.parts))
            self.active = False


@dataclass
class SecretCandidate:
    id: str
    provider: str
    source: str
    fingerprint: str
    value: str = field(repr=False)
    validation: str = "not_validated"
    evidence_id: str = ""

    def public(self):
        return dict(
            id=self.id,
            provider=self.provider,
            source=self.source,
            fingerprint=self.fingerprint,
            validation=self.validation,
            evidence_id=self.evidence_id,
            finding=False,
        )


class JSIntelligence:
    def __init__(self):
        self.candidates: dict[str, SecretCandidate] = {}
        self.validators: dict[str, object] = {}

    def extract(self, source: str, text: str) -> dict:
        text = text[:MAX_SOURCE]
        result = {
            key: []
            for key in (
                "endpoints",
                "graphql_operations",
                "websockets",
                "feature_flags",
                "internal_hosts",
                "storage_references",
                "dependencies",
                "secret_candidates",
            )
        }
        for match in _STRINGS.finditer(text):
            value = match.group(1)
            if value.startswith(("/api/", "/graphql", "/rest/", "/v1/", "/v2/")):
                result["endpoints"].append(value.split("?", 1)[0])
            if value.startswith(("http://", "https://", "ws://", "wss://")):
                parsed = urlsplit(value)
                if parsed.username or parsed.password:
                    continue
                safe = value.split("?", 1)[0].split("#", 1)[0]
                if parsed.scheme in ("ws", "wss"):
                    result["websockets"].append(safe)
                else:
                    result["endpoints"].append(safe)
                host = parsed.hostname or ""
                if (
                    host.endswith((".internal", ".local", ".localhost"))
                    or host == "localhost"
                ):
                    result["internal_hosts"].append(host)
                if any(
                    part in host
                    for part in (
                        ".s3.",
                        ".blob.core.windows.net",
                        "storage.googleapis.com",
                    )
                ):
                    result["storage_references"].append(safe)
            if value.startswith("s3://"):
                result["storage_references"].append(value)
        result["graphql_operations"] = re.findall(
            r"\b(?:query|mutation|subscription)\s+([A-Za-z_]\w*)\s*(?:\(|\{)", text
        )
        result["feature_flags"] = re.findall(
            r"""(?:featureFlags?|flags)\s*(?:\.([\w]+)|\[\s*["']([^"']+)["']\s*\])""",
            text,
        )
        result["feature_flags"] = [a or b for a, b in result["feature_flags"]]
        result["storage_references"] += re.findall(
            r"""(?:localStorage|sessionStorage)\.(?:getItem|setItem)\(\s*["']([^"']+)["']""",
            text,
        )
        deps = re.findall(
            r"""(?:import\s*\(|import\s+[^;\n]*?from\s*|import\s*|require\s*\()\s*["']([^"']+\.(?:js|mjs)(?:\?[^"']*)?)["']""",
            text,
        )
        deps += re.findall(r"[#@]\s*sourceMappingURL=([^\s*]+)", text)
        result["dependencies"] = deps
        for provider, pattern in _PROVIDERS.items():
            for match in pattern.finditer(text):
                value = match.group(1) if provider == "generic" else match.group(0)
                digest = hashlib.sha256(value.encode()).hexdigest()
                cid = hashlib.sha256((provider + ":" + digest).encode()).hexdigest()[
                    :24
                ]
                if cid not in self.candidates and len(self.candidates) >= 2000:
                    continue
                candidate = self.candidates.setdefault(
                    cid, SecretCandidate(cid, provider, source, digest, value)
                )
                if len(result["secret_candidates"]) < 500 and not any(
                    row["id"] == cid for row in result["secret_candidates"]
                ):
                    result["secret_candidates"].append(candidate.public())
        for key in result:
            if key != "secret_candidates":
                result[key] = sorted(set(result[key]))[:500]
        return result

    async def collect(self, url: str, *, fetch, max_files=20) -> dict:
        allowed_origin = origin(url)
        max_files = max(1, min(int(max_files), 50))
        queue, seen, artifacts, analyses, gaps = [url], set(), [], [], []
        while queue and len(seen) < max_files:
            current = queue.pop(0)
            if current in seen:
                continue
            try:
                if origin(current) != allowed_origin:
                    gaps.append(
                        "Cross-origin dependency not fetched: "
                        + current.split("?", 1)[0]
                    )
                    continue
            except ValueError:
                gaps.append("Unsupported dependency URL")
                continue
            seen.add(current)
            try:
                response = await fetch(current)
                status = response.get("response", {}).get("status", 0)
                if not 200 <= status < 300:
                    gaps.append("Dependency fetch failed: " + current)
                    continue
                text = response.get("_body_text", "")
                if len(text) > MAX_SOURCE:
                    gaps.append("Source exceeds byte budget: " + current)
                    continue
                if response.get("evidence_id"):
                    artifacts.append(response["evidence_id"])
                content_type = str(
                    response.get("response", {})
                    .get("headers", {})
                    .get("content-type", "")
                )
                if "html" in content_type or text.lstrip().lower().startswith(
                    ("<!doctype html", "<html")
                ):
                    parser = Scripts()
                    parser.feed(text)
                    queue.extend(urljoin(current, item) for item in parser.urls)
                    sources = [
                        (current + "#inline-" + str(i), src)
                        for i, src in enumerate(parser.inline)
                    ]
                elif urlsplit(current).path.endswith(".map"):
                    data = json.loads(text)
                    sources = [
                        (current + "#source-" + str(i), src)
                        for i, src in enumerate(data.get("sourcesContent", [])[:100])
                        if isinstance(src, str)
                    ]
                    if not sources:
                        gaps.append(
                            "Source map has no embedded source content: " + current
                        )
                else:
                    sources = [(current, text)]
                for source, content in sources:
                    extracted = self.extract(source, content)
                    analyses.append(dict(source=source, **extracted))
                    queue.extend(
                        urljoin(current, item) for item in extracted["dependencies"]
                    )
            except Exception:
                gaps.append(
                    "Source could not be collected or parsed: "
                    + current.split("?", 1)[0]
                )
        if queue:
            gaps.append("File budget reached; dependencies remain uncollected")
        return dict(
            sources=analyses, evidence_ids=artifacts, gaps=gaps, discovery_only=True
        )

    async def validate(
        self, candidate_id: str, *, enabled: bool, allowed_providers: list[str]
    ) -> dict:
        candidate = self.candidates[candidate_id]
        validator = self.validators.get(candidate.provider)
        if (
            not enabled
            or candidate.provider not in allowed_providers
            or validator is None
        ):
            return {
                **candidate.public(),
                "validation": "blocked",
                "reason": "Provider validation is not enabled/configured",
            }
        # Validator plugins are trusted application code with fixed provider endpoints,
        # read-only permissions and timeouts. Never construct a URL from source JS.
        try:
            import asyncio

            result = await asyncio.wait_for(validator(candidate.value), timeout=10)
            status = result.get("status", "inconclusive")
            if status not in ("valid", "invalid", "inconclusive"):
                status = "inconclusive"
            candidate.validation = status
            candidate.evidence_id = str(result.get("evidence_id", ""))
            if status in ("valid", "invalid") and not candidate.evidence_id:
                candidate.validation = "inconclusive"
        except Exception:
            candidate.validation = "inconclusive"
        return candidate.public()
