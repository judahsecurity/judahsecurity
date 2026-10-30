"""
Subdomain takeover scanner.

Stacks three detection engines — any of which can produce a finding — and
cross-dedupes their output:

  1. CNAME fingerprint engine (pure Python, always on):
     Resolves each hostname's CNAME chain and matches against a provider
     fingerprint database (40+ services). For positive CNAME matches the
     engine issues an HTTP GET and looks for the provider's "not found"
     signature to upgrade a ``likely`` verdict to ``confirmed``.

  2. Nuclei takeover templates (optional, runs when nuclei is installed):
     Reuses the existing NucleiService with ``-t http/takeovers/`` and
     ``-t dns/`` for ~60 takeover-focused templates instead of the full
     9,000+ community set.

  3. Subjack binary (optional, runs when ``subjack`` is on PATH):
     Apache-2.0 DNS-first fingerprinting for CNAME / NS / MX / SOA.

Findings are scored 0-100 with an additive rule set and classified as
``confirmed`` / ``likely`` / ``manual_review`` against a configurable
threshold (default 60). Emits persistence-ready records matched against
existing ``Asset`` rows so downstream ingestion stays idempotent.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

import dns.exception
import dns.resolver
import httpx

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Provider fingerprint database
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ProviderFingerprint:
    """A single takeover-vulnerable SaaS/cloud provider fingerprint."""
    provider: str
    cname_patterns: tuple[str, ...]
    http_signatures: tuple[str, ...]
    # ``auto_exploit`` => a dangling CNAME is almost certainly claimable by
    # anyone with a free account on this provider. Bumps the confidence score.
    auto_exploit: bool = False
    # ``dns_only`` => no HTTP signature needed (cloud storage buckets etc.).
    dns_only: bool = False


FINGERPRINTS: tuple[ProviderFingerprint, ...] = (
    ProviderFingerprint(
        "GitHub Pages",
        ("github.io", "github.map.fastly.net"),
        ("There isn't a GitHub Pages site here",),
        auto_exploit=True,
    ),
    ProviderFingerprint(
        "Heroku",
        ("herokuapp.com", "herokudns.com"),
        ("No such app", "herokucdn.com/error-pages/no-such-app.html"),
        auto_exploit=True,
    ),
    ProviderFingerprint(
        "AWS S3",
        ("s3.amazonaws.com", "s3-website", "s3-website-", "amazonaws.com"),
        ("NoSuchBucket", "The specified bucket does not exist"),
        auto_exploit=True,
    ),
    ProviderFingerprint(
        "AWS CloudFront",
        ("cloudfront.net",),
        ("The request could not be satisfied", "Bad request. We can't connect to the server"),
    ),
    ProviderFingerprint(
        "AWS Elastic Beanstalk",
        ("elasticbeanstalk.com", "elb.amazonaws.com"),
        (),
        dns_only=True,
    ),
    ProviderFingerprint(
        "Azure App Service",
        ("azurewebsites.net", "cloudapp.net", "cloudapp.azure.com"),
        ("404 Web Site not found",),
    ),
    ProviderFingerprint(
        "Azure Blob Storage",
        ("blob.core.windows.net",),
        (),
        dns_only=True,
    ),
    ProviderFingerprint(
        "Azure Traffic Manager",
        ("trafficmanager.net",),
        (),
        dns_only=True,
    ),
    ProviderFingerprint(
        "Shopify",
        ("myshopify.com",),
        ("Sorry, this shop is currently unavailable",),
        auto_exploit=True,
    ),
    ProviderFingerprint(
        "Fastly",
        ("fastly.net",),
        ("Fastly error: unknown domain",),
    ),
    ProviderFingerprint(
        "Ghost",
        ("ghost.io",),
        ("The thing you were looking for is no longer here",),
        auto_exploit=True,
    ),
    ProviderFingerprint(
        "Zendesk",
        ("zendesk.com",),
        ("Help Center Closed",),
        auto_exploit=True,
    ),
    ProviderFingerprint(
        "Webflow",
        ("proxy.webflow.com", "proxy-ssl.webflow.com"),
        ("The page you are looking for doesn't exist or has been moved",),
        auto_exploit=True,
    ),
    ProviderFingerprint(
        "Netlify",
        ("netlify.com", "netlifyglobalcdn.com", "netlify.app"),
        ("Not Found - Request ID",),
    ),
    ProviderFingerprint(
        "Vercel",
        ("vercel.app", "now.sh"),
        ("The deployment could not be found on Vercel",),
    ),
    ProviderFingerprint(
        "Surge.sh",
        ("surge.sh",),
        ("project not found",),
        auto_exploit=True,
    ),
    ProviderFingerprint(
        "Tumblr",
        ("domains.tumblr.com",),
        ("Whatever you were looking for doesn't currently exist at this address",),
    ),
    ProviderFingerprint(
        "Statuspage",
        ("statuspage.io",),
        ("You are being redirected", "There is no such page here"),
    ),
    ProviderFingerprint(
        "Unbounce",
        ("unbouncepages.com",),
        ("The requested URL was not found on this server",),
        auto_exploit=True,
    ),
    ProviderFingerprint(
        "Readthedocs",
        ("readthedocs.io",),
        ("unknown to Read the Docs",),
        auto_exploit=True,
    ),
    ProviderFingerprint(
        "Pantheon",
        ("pantheonsite.io",),
        ("The gods are wise", "404 error unknown site"),
    ),
    ProviderFingerprint(
        "Bitbucket",
        ("bitbucket.io",),
        ("Repository not found",),
    ),
    ProviderFingerprint(
        "Intercom",
        ("custom.intercom.help",),
        ("Uh oh. That page doesn't exist.",),
    ),
    ProviderFingerprint(
        "UserVoice",
        ("uservoice.com",),
        ("This UserVoice subdomain is currently available!",),
        auto_exploit=True,
    ),
    ProviderFingerprint(
        "WordPress.com",
        ("wordpress.com",),
        ("Do you want to register",),
    ),
    ProviderFingerprint(
        "Pingdom",
        ("stats.pingdom.com",),
        ("pingdom", "Sorry, couldn't find the status page"),
    ),
    ProviderFingerprint(
        "Tilda",
        ("tilda.ws",),
        ("Please renew your subscription",),
    ),
    ProviderFingerprint(
        "Strikingly",
        ("s.strikinglydns.com", "strikinglydns.com"),
        ("PAGE NOT FOUND",),
    ),
    ProviderFingerprint(
        "HatenaBlog",
        ("hatenablog.com",),
        ("404 Blog is not found",),
    ),
    ProviderFingerprint(
        "LaunchRock",
        ("launchrock.com",),
        ("HTTP 404 Not Found",),
    ),
    ProviderFingerprint(
        "Smugmug",
        ("smugmug.com",),
        (),
        dns_only=True,
    ),
    ProviderFingerprint(
        "Teamwork",
        ("teamwork.com",),
        ("Oops - We didn't find your site.",),
    ),
    ProviderFingerprint(
        "Tictail",
        ("tictail.com",),
        ("to target URL: <no server>",),
    ),
    ProviderFingerprint(
        "Canny",
        ("cannyio.com", "canny.io"),
        ("Company Not Found",),
    ),
    ProviderFingerprint(
        "Kinsta",
        ("kinsta.cloud",),
        ("No site for domain",),
    ),
    ProviderFingerprint(
        "Agile CRM",
        ("agilecrm.com",),
        ("Sorry, this page is no longer available.",),
    ),
    ProviderFingerprint(
        "Anima",
        ("animaapp.io",),
        ("If this is your website and you've just created it",),
    ),
    ProviderFingerprint(
        "Campaign Monitor",
        ("createsend.com",),
        ("Trying to access your account?", "Double check the URL"),
    ),
    ProviderFingerprint(
        "Cargo",
        ("cargocollective.com",),
        ("404 Not Found",),
    ),
    ProviderFingerprint(
        "Feedpress",
        ("feedpress.me",),
        ("The feed has not been found.",),
    ),
)


# ---------------------------------------------------------------------------
# Public data model
# ---------------------------------------------------------------------------


@dataclass
class TakeoverFinding:
    """A single takeover finding emitted by any engine."""
    hostname: str
    provider: str
    verdict: str  # confirmed | likely | manual_review
    confidence: int  # 0-100
    methods: list[str] = field(default_factory=list)  # cname | nuclei | subjack
    cname_chain: list[str] = field(default_factory=list)
    http_status: Optional[int] = None
    http_signature: Optional[str] = None
    nuclei_template: Optional[str] = None
    evidence: Optional[str] = None
    auto_exploit: bool = False

    def as_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "provider": self.provider,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "methods": self.methods,
            "cname_chain": self.cname_chain,
            "http_status": self.http_status,
            "http_signature": self.http_signature,
            "nuclei_template": self.nuclei_template,
            "evidence": self.evidence,
            "auto_exploit": self.auto_exploit,
        }


@dataclass
class TakeoverScanResult:
    targets: int = 0
    findings: list[TakeoverFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    engines_used: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Engines
# ---------------------------------------------------------------------------


def _match_fingerprint(cname_chain: Iterable[str]) -> Optional[ProviderFingerprint]:
    for cname in cname_chain:
        lowered = cname.lower().rstrip(".")
        for fp in FINGERPRINTS:
            if any(pattern in lowered for pattern in fp.cname_patterns):
                return fp
    return None


async def _resolve_cname_chain(hostname: str, timeout: float = 3.0) -> list[str]:
    """Follow the CNAME chain for a hostname, returning each hop."""
    loop = asyncio.get_running_loop()

    def _blocking() -> list[str]:
        chain: list[str] = []
        try:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
            resolver.timeout = timeout
            resolver.lifetime = timeout * 2
            answer = resolver.resolve(hostname, "A", raise_on_no_answer=False)
            canonical = answer.canonical_name.to_text(omit_final_dot=True)
            if canonical and canonical.lower() != hostname.lower():
                chain.append(canonical)
            # Walk CNAME records explicitly too in case A has no answer.
            try:
                cname_ans = resolver.resolve(hostname, "CNAME")
                for rdata in cname_ans:
                    hop = rdata.target.to_text(omit_final_dot=True)
                    if hop not in chain:
                        chain.append(hop)
            except Exception:
                pass
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            pass
        except dns.exception.Timeout:
            logger.debug("DNS timeout resolving CNAME for %s", hostname)
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("CNAME resolution error for %s: %s", hostname, exc)
        return chain

    return await loop.run_in_executor(None, _blocking)


async def _probe_http(hostname: str, timeout: float = 8.0) -> tuple[Optional[int], str]:
    urls = [f"https://{hostname}", f"http://{hostname}"]
    async with httpx.AsyncClient(
        timeout=timeout, follow_redirects=True, verify=False
    ) as client:
        for url in urls:
            try:
                resp = await client.get(url)
                body = resp.text or ""
                return resp.status_code, body[:20000]
            except Exception:
                continue
    return None, ""


def _score_finding(finding: TakeoverFinding, fp: Optional[ProviderFingerprint]) -> None:
    """Apply the additive scoring rules. Mutates the finding in-place."""
    score = 0
    methods = set(finding.methods)

    if "cname" in methods:
        score += 10
    if "nuclei" in methods:
        score += 15
    if "subjack" in methods:
        score += 25
    if len(methods) >= 2:
        score += 30  # Cross-tool confirmation is very strong signal.
    if fp and fp.auto_exploit:
        score += 20
    if not fp:
        score -= 10  # Unknown provider is probabilistic at best.
    if finding.http_signature:
        score += 25

    score = max(0, min(100, score))
    finding.confidence = score


def _classify(confidence: int, threshold: int = 60) -> str:
    if confidence >= threshold + 15:
        return "confirmed"
    if confidence >= threshold:
        return "likely"
    return "manual_review"


async def _cname_engine(
    hostnames: list[str],
    concurrency: int = 20,
    http_timeout: float = 8.0,
) -> dict[tuple[str, str], TakeoverFinding]:
    semaphore = asyncio.Semaphore(concurrency)
    results: dict[tuple[str, str], TakeoverFinding] = {}

    async def _scan_one(host: str) -> Optional[TakeoverFinding]:
        async with semaphore:
            chain = await _resolve_cname_chain(host)
            if not chain:
                return None
            fp = _match_fingerprint(chain)
            if not fp:
                return None
            finding = TakeoverFinding(
                hostname=host,
                provider=fp.provider,
                verdict="manual_review",
                confidence=0,
                methods=["cname"],
                cname_chain=chain,
                auto_exploit=fp.auto_exploit,
            )
            if not fp.dns_only and fp.http_signatures:
                status_code, body = await _probe_http(host, timeout=http_timeout)
                finding.http_status = status_code
                for signature in fp.http_signatures:
                    if signature and signature.lower() in body.lower():
                        finding.http_signature = signature
                        break
            _score_finding(finding, fp)
            finding.verdict = _classify(finding.confidence)
            return finding

    scan_results = await asyncio.gather(*[_scan_one(h) for h in hostnames])
    for finding in scan_results:
        if finding:
            results[(finding.hostname, finding.provider)] = finding
    return results


async def _nuclei_engine(hostnames: list[str]) -> dict[tuple[str, str], TakeoverFinding]:
    """Run Nuclei takeover templates. Returns findings keyed by (host, provider)."""
    if not hostnames:
        return {}
    try:
        from app.services.nuclei_service import NucleiService
    except Exception:
        return {}

    service = NucleiService()
    if not service.check_installation():
        logger.debug("Nuclei not installed — skipping nuclei takeover engine")
        return {}

    try:
        result = await service.scan_targets(
            targets=hostnames,
            templates=["http/takeovers/", "dns/"],
            rate_limit=100,
            bulk_size=25,
            concurrency=25,
            timeout=10,
        )
    except Exception as exc:
        logger.warning("Nuclei takeover scan failed: %s", exc)
        return {}

    out: dict[tuple[str, str], TakeoverFinding] = {}
    for nf in result.findings:
        host = nf.host.split("://", 1)[-1].split("/")[0].split(":")[0]
        provider = _guess_provider_from_template(nf.template_id, nf.template_name)
        finding = TakeoverFinding(
            hostname=host,
            provider=provider,
            verdict="manual_review",
            confidence=0,
            methods=["nuclei"],
            nuclei_template=nf.template_id,
            evidence=nf.template_name,
        )
        # If CNAME engine already flagged this host, merge methods later.
        fp = next(
            (fp for fp in FINGERPRINTS if fp.provider.lower() == provider.lower()),
            None,
        )
        _score_finding(finding, fp)
        finding.verdict = _classify(finding.confidence)
        finding.auto_exploit = bool(fp and fp.auto_exploit)
        out[(host, provider)] = finding
    return out


def _guess_provider_from_template(template_id: str, template_name: str) -> str:
    blob = f"{template_id} {template_name}".lower()
    for fp in FINGERPRINTS:
        if fp.provider.lower().split()[0] in blob:
            return fp.provider
    return "Unknown"


def _subjack_available() -> bool:
    return shutil.which("subjack") is not None


async def _subjack_engine(hostnames: list[str]) -> dict[tuple[str, str], TakeoverFinding]:
    if not hostnames or not _subjack_available():
        return {}

    out: dict[tuple[str, str], TakeoverFinding] = {}
    with tempfile.TemporaryDirectory() as tmp:
        input_path = Path(tmp) / "hosts.txt"
        output_path = Path(tmp) / "out.json"
        input_path.write_text("\n".join(hostnames))
        cmd = [
            "subjack",
            "-w", str(input_path),
            "-o", str(output_path),
            "-ssl",
            "-timeout", "30",
            "-t", "50",
            "-v3",
            "-m",
        ]
        try:
            loop = asyncio.get_running_loop()
            proc = await loop.run_in_executor(
                None,
                lambda: subprocess.run(cmd, capture_output=True, text=True, timeout=900),
            )
        except subprocess.TimeoutExpired:
            logger.warning("subjack timed out")
            return {}
        except Exception as exc:
            logger.warning("subjack failed: %s", exc)
            return {}

        if proc.returncode != 0:
            logger.warning("subjack returned %d: %s", proc.returncode, proc.stderr.strip())

        try:
            text = output_path.read_text()
        except FileNotFoundError:
            text = ""

        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                # Fallback: match "vulnerable" tags on bare lines
                if "vulnerable" in line.lower():
                    m = re.search(r"\s*(\S+)\s+is vulnerable to\s+(.+)$", line, re.IGNORECASE)
                    if m:
                        host, provider = m.group(1), m.group(2)
                        finding = TakeoverFinding(
                            hostname=host,
                            provider=provider,
                            verdict="manual_review",
                            confidence=0,
                            methods=["subjack"],
                        )
                        _score_finding(finding, None)
                        finding.verdict = _classify(finding.confidence)
                        out[(host, provider)] = finding
                continue

            host = row.get("subdomain") or row.get("host") or ""
            provider = row.get("service") or row.get("type") or "Unknown"
            if not host or not (row.get("vulnerable") or row.get("confirmed")):
                continue
            fp = next(
                (fp for fp in FINGERPRINTS if fp.provider.lower() == provider.lower()),
                None,
            )
            finding = TakeoverFinding(
                hostname=host,
                provider=provider,
                verdict="manual_review",
                confidence=0,
                methods=["subjack"],
                evidence=row.get("output") or row.get("error"),
                auto_exploit=bool(fp and fp.auto_exploit),
            )
            _score_finding(finding, fp)
            finding.verdict = _classify(finding.confidence)
            out[(host, provider)] = finding
    return out


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def _merge(
    *engine_outputs: dict[tuple[str, str], TakeoverFinding],
) -> list[TakeoverFinding]:
    merged: dict[tuple[str, str], TakeoverFinding] = {}
    for engine_output in engine_outputs:
        for key, finding in engine_output.items():
            if key not in merged:
                merged[key] = finding
                continue
            existing = merged[key]
            # Merge methods + recompute score with combined signal.
            existing.methods = sorted(set(existing.methods + finding.methods))
            if finding.cname_chain and not existing.cname_chain:
                existing.cname_chain = finding.cname_chain
            if finding.http_signature and not existing.http_signature:
                existing.http_signature = finding.http_signature
            if finding.http_status is not None and existing.http_status is None:
                existing.http_status = finding.http_status
            if finding.nuclei_template and not existing.nuclei_template:
                existing.nuclei_template = finding.nuclei_template
            if finding.evidence and not existing.evidence:
                existing.evidence = finding.evidence
            existing.auto_exploit = existing.auto_exploit or finding.auto_exploit
            fp = next(
                (fp for fp in FINGERPRINTS if fp.provider.lower() == existing.provider.lower()),
                None,
            )
            _score_finding(existing, fp)
            existing.verdict = _classify(existing.confidence)
    return list(merged.values())


async def scan_takeovers(
    hostnames: Iterable[str],
    enable_cname: bool = True,
    enable_nuclei: bool = True,
    enable_subjack: bool = True,
    concurrency: int = 20,
    http_timeout: float = 8.0,
) -> TakeoverScanResult:
    """Run every enabled engine against ``hostnames`` and return merged findings."""
    from datetime import datetime

    start = datetime.utcnow()
    result = TakeoverScanResult()
    hostlist = [h.strip().lower() for h in hostnames if h and h.strip()]
    result.targets = len(hostlist)
    if not hostlist:
        return result

    engine_outputs: list[dict[tuple[str, str], TakeoverFinding]] = []

    if enable_cname:
        try:
            cname_out = await _cname_engine(
                hostlist, concurrency=concurrency, http_timeout=http_timeout
            )
            engine_outputs.append(cname_out)
            result.engines_used.append("cname")
        except Exception as exc:
            logger.warning("CNAME engine failed: %s", exc)
            result.errors.append(f"cname: {exc}")

    if enable_nuclei:
        try:
            nuclei_out = await _nuclei_engine(hostlist)
            if nuclei_out:
                engine_outputs.append(nuclei_out)
                result.engines_used.append("nuclei")
        except Exception as exc:
            logger.warning("Nuclei takeover engine failed: %s", exc)
            result.errors.append(f"nuclei: {exc}")

    if enable_subjack:
        try:
            subjack_out = await _subjack_engine(hostlist)
            if subjack_out:
                engine_outputs.append(subjack_out)
                result.engines_used.append("subjack")
        except Exception as exc:
            logger.warning("Subjack engine failed: %s", exc)
            result.errors.append(f"subjack: {exc}")

    result.findings = _merge(*engine_outputs)
    result.duration_seconds = (datetime.utcnow() - start).total_seconds()
    logger.info(
        "Takeover scan complete: %d targets, %d findings, engines=%s, %.2fs",
        result.targets,
        len(result.findings),
        result.engines_used,
        result.duration_seconds,
    )
    return result


# ---------------------------------------------------------------------------
# Persistence helper
# ---------------------------------------------------------------------------


def persist_takeover_findings(
    db,
    organization_id: int,
    scan_id: Optional[int],
    result: TakeoverScanResult,
) -> dict:
    """Write findings into the vulnerabilities table. Idempotent per host/provider."""
    from app.models.asset import Asset, AssetType
    from app.models.vulnerability import (
        Severity,
        Vulnerability,
        VulnerabilityStatus,
    )
    from app.services.reactivation_service import (
        reactivate_if_closed,
        trigger_jira_reopen_background,
    )

    summary = {"created": 0, "updated": 0, "reactivated": 0, "skipped": 0}
    reactivations: list[tuple[int, str]] = []

    for finding in result.findings:
        asset = (
            db.query(Asset)
            .filter(
                Asset.organization_id == organization_id,
                Asset.value == finding.hostname,
                Asset.asset_type.in_([AssetType.SUBDOMAIN, AssetType.DOMAIN]),
            )
            .first()
        )
        if not asset:
            # Auto-create a subdomain asset so the finding isn't orphaned. Users
            # can clean up false-positive hosts from the UI if needed.
            asset = Asset(
                organization_id=organization_id,
                asset_type=AssetType.SUBDOMAIN,
                name=finding.hostname,
                value=finding.hostname,
                discovery_source="takeover_scanner",
            )
            db.add(asset)
            db.flush()

        title = f"Potential subdomain takeover ({finding.provider})"
        # Deterministic dedup key: one vulnerability row per (asset, provider).
        existing = (
            db.query(Vulnerability)
            .filter(
                Vulnerability.asset_id == asset.id,
                Vulnerability.template_id == f"takeover-{_slug(finding.provider)}",
            )
            .first()
        )

        severity = Severity.HIGH if finding.verdict == "confirmed" else Severity.MEDIUM
        if finding.verdict == "manual_review":
            severity = Severity.LOW

        meta = {
            "verdict": finding.verdict,
            "confidence": finding.confidence,
            "methods": finding.methods,
            "cname_chain": finding.cname_chain,
            "http_status": finding.http_status,
            "http_signature": finding.http_signature,
            "nuclei_template": finding.nuclei_template,
            "auto_exploit": finding.auto_exploit,
        }
        # A confirmed verdict means the CNAME is dangling and the provider's
        # unclaimed-resource signature matched; the DNS misconfiguration IS the
        # vulnerability, so no exploit payload is needed.
        dc = "endpoint_confirmed" if finding.verdict == "confirmed" else "version_only"

        description = (
            f"Hostname `{finding.hostname}` points to {finding.provider} but the "
            f"underlying resource is dangling or unclaimed. An attacker who can "
            f"register the target resource on {finding.provider} may take over "
            f"this subdomain."
        )

        if existing:
            existing.severity = severity
            existing.last_detected = _now()
            existing.metadata_ = meta
            existing.evidence = finding.evidence or existing.evidence
            existing.description = description
            existing.detection_confidence = dc
            # Redetection reopens closed findings; analyst work in progress stays.
            old_status = existing.status.value
            if reactivate_if_closed(existing):
                reactivations.append((existing.id, old_status))
                summary["reactivated"] += 1
            summary["updated"] += 1
        else:
            vuln = Vulnerability(
                title=title,
                description=description,
                severity=severity,
                asset_id=asset.id,
                scan_id=scan_id,
                detected_by="takeover_scanner",
                template_id=f"takeover-{_slug(finding.provider)}",
                matcher_name=",".join(finding.methods),
                detection_confidence=dc,
                status=VulnerabilityStatus.OPEN,
                evidence=finding.evidence,
                tags=["takeover", finding.verdict, _slug(finding.provider)],
                metadata_=meta,
                # CWE-284: Improper Access Control — dangling DNS/CNAME allows
                # an unauthorized party to claim the resource and serve content
                # under the victim's subdomain.
                cwe_id="CWE-284",
                remediation=(
                    f"Reclaim the dangling resource on {finding.provider} or "
                    f"remove the CNAME/DNS record pointing to it."
                ),
            )
            db.add(vuln)
            summary["created"] += 1

    db.commit()
    for vuln_id, old_status in reactivations:
        trigger_jira_reopen_background(vuln_id, old_status)
    return summary


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "unknown"


def _now():
    from datetime import datetime

    return datetime.utcnow()
