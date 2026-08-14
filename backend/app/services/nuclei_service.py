"""
Nuclei vulnerability scanner integration service.

Integrates with ProjectDiscovery's Nuclei scanner:
https://github.com/projectdiscovery/nuclei

Nuclei is a fast, customizable vulnerability scanner powered by the global 
security community and built on a simple YAML-based DSL.
"""

import asyncio
import ipaddress
import json
import logging
import subprocess
import tempfile
import os
from typing import Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


def is_cidr_range(target: str) -> bool:
    """True if target is an IP network with more than one address (e.g. 10.0.0.0/24)."""
    candidate = (target or "").strip()
    if not candidate or "://" in candidate or "/" not in candidate:
        return False
    # Strip optional scheme-less host:port noise; CIDRs look like a.b.c.d/nn
    try:
        network = ipaddress.ip_network(candidate.split()[0], strict=False)
        return network.num_addresses > 1
    except ValueError:
        return False


def filter_nuclei_targets(targets: list[str]) -> tuple[list[str], int]:
    """Drop CIDR/netblock ranges from Nuclei target lists.

    Nuclei against raw CIDRs explodes into tens/hundreds of thousands of hosts,
    saturates worker slots for hours, and never usefully finishes. Domains,
    hostnames, single IPs, and URLs are kept.
    """
    kept: list[str] = []
    skipped = 0
    for target in targets or []:
        target = (target or "").strip()
        if not target:
            continue
        if is_cidr_range(target):
            skipped += 1
            continue
        kept.append(target)
    return kept, skipped


def expand_cidr_targets(targets: list[str], max_hosts: Optional[int] = None) -> tuple[list[str], int]:
    """
    Expand CIDR ranges in targets to individual IPs.

    Args:
        targets: Input targets (URLs, IPs, CIDRs)
        max_hosts: If set, stop expanding once this many hosts are collected.
                   Prevents OOM / multi-minute hangs on /16+ inventories.

    Returns:
        tuple: (expanded_targets, total_ip_count_seen_or_collected)
    """
    expanded = []
    total_count = 0

    for target in targets:
        target = target.strip()
        if not target:
            continue

        if max_hosts is not None and total_count >= max_hosts:
            break

        # Check if it's a CIDR notation
        if '/' in target and "://" not in target:
            try:
                # Try to parse as IP network (CIDR)
                network = ipaddress.ip_network(target, strict=False)

                num_hosts = network.num_addresses

                if num_hosts > 65536:  # /16 or larger
                    logger.warning(
                        f"Large CIDR range {target} has {num_hosts} addresses. "
                        "Consider breaking into smaller ranges for better performance."
                    )

                # Expand hosts, respecting max_hosts cap
                for ip in network.hosts():
                    expanded.append(str(ip))
                    total_count += 1
                    if max_hosts is not None and total_count >= max_hosts:
                        break

                # Also include network and broadcast for /31 and /32
                if network.prefixlen >= 31 and (max_hosts is None or total_count < max_hosts):
                    expanded.append(str(network.network_address))
                    total_count += 1

            except ValueError:
                # Not a valid CIDR, treat as regular target (might be URL with port)
                expanded.append(target)
                total_count += 1
        else:
            # Regular target (IP, domain, URL)
            expanded.append(target)
            total_count += 1

    return expanded, total_count


def count_cidr_targets(targets: list[str]) -> int:
    """
    Count total IPs across all targets, expanding CIDRs.
    
    Use this for quick counting without full expansion.
    """
    total = 0
    for target in targets:
        target = target.strip()
        if not target:
            continue
            
        if '/' in target:
            try:
                network = ipaddress.ip_network(target, strict=False)
                # Count usable hosts (excludes network/broadcast for /30 and larger)
                total += max(network.num_addresses - 2, 1)
            except ValueError:
                total += 1
        else:
            total += 1
    
    return total


@dataclass
class NucleiResult:
    """Single Nuclei scan result."""
    template_id: str
    template_name: str
    severity: str
    host: str
    matched_at: str
    extracted_results: list[str] = field(default_factory=list)
    ip: Optional[str] = None
    timestamp: Optional[datetime] = None
    matcher_name: Optional[str] = None
    matcher_status: bool = True
    description: Optional[str] = None
    reference: list[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    curl_command: Optional[str] = None
    request: Optional[str] = None
    response: Optional[str] = None
    template_path: Optional[str] = None
    template_yaml: Optional[str] = None
    
    @classmethod
    def from_json(cls, data: dict) -> "NucleiResult":
        """Create NucleiResult from Nuclei JSON output."""
        # Ensure data is a dict
        if not isinstance(data, dict):
            logger.warning(f"Nuclei result data is not a dict: {type(data)}")
            data = {}
        
        info = data.get("info", {})
        
        # Ensure info is a dict (some Nuclei results may have different formats)
        if not isinstance(info, dict):
            logger.warning(f"Nuclei info field is not a dict: {type(info)}")
            info = {}
        
        # Extract CVE from tags
        tags = info.get("tags", [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]
        
        cve_id = None
        for tag in tags:
            if tag.upper().startswith("CVE-"):
                cve_id = tag.upper()
                break
        
        # Extract CVSS score and classification data
        cvss_score = None
        classification = info.get("classification", {})
        
        # Ensure classification is a dict (some Nuclei versions return different formats)
        if not isinstance(classification, dict):
            classification = {}
        
        cvss_vector = None
        if classification:
            cvss_metrics = classification.get("cvss-metrics", "")
            if cvss_metrics and isinstance(cvss_metrics, str) and cvss_metrics.startswith("CVSS:"):
                cvss_vector = cvss_metrics
            cvss_score_str = classification.get("cvss-score")
            if cvss_score_str:
                try:
                    cvss_score = float(cvss_score_str)
                except (ValueError, TypeError):
                    pass
        
        # Safely extract CVE-ID (can be string, list, or None)
        extracted_cve_id = None
        if classification:
            cve_id_field = classification.get("cve-id")
            if isinstance(cve_id_field, list) and cve_id_field:
                extracted_cve_id = cve_id_field[0]
            elif isinstance(cve_id_field, str):
                extracted_cve_id = cve_id_field
        
        # Safely extract CWE-ID
        extracted_cwe_id = None
        if classification:
            cwe_id_field = classification.get("cwe-id")
            if isinstance(cwe_id_field, list) and cwe_id_field:
                extracted_cwe_id = cwe_id_field[0]
            elif isinstance(cwe_id_field, str):
                extracted_cwe_id = cwe_id_field
        
        # Safely handle reference (can be list or string)
        reference = info.get("reference", [])
        if isinstance(reference, str):
            reference = [reference]
        elif not isinstance(reference, list):
            reference = []
        
        return cls(
            template_id=data.get("template-id", data.get("templateID", "")),
            template_name=info.get("name", ""),
            severity=info.get("severity", "unknown"),
            host=data.get("host", ""),
            matched_at=data.get("matched-at", data.get("matched", "")),
            extracted_results=data.get("extracted-results", []),
            ip=data.get("ip", ""),
            timestamp=datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00")) 
                if data.get("timestamp") else datetime.utcnow(),
            matcher_name=data.get("matcher-name", ""),
            matcher_status=data.get("matcher-status", True),
            description=info.get("description", ""),
            reference=reference,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cve_id=cve_id or extracted_cve_id,
            cwe_id=extracted_cwe_id,
            tags=tags,
            curl_command=data.get("curl-command", data.get("curl_command", "")),
            request=data.get("request") or data.get("request-raw") or "",
            response=data.get("response") or data.get("response-raw") or "",
            template_path=data.get("template-path") or data.get("template_path") or data.get("template") or "",
            template_yaml="",
        )


@dataclass 
class NucleiScanResult:
    """Complete Nuclei scan result."""
    success: bool
    targets_scanned: int = 0
    targets_original: int = 0  # Original count (e.g., 1 CIDR)
    targets_expanded: int = 0  # Expanded count (e.g., 254 IPs from /24)
    findings: list[NucleiResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0
    summary: dict = field(default_factory=dict)
    timed_out: bool = False


class NucleiService:
    """
    Service for running Nuclei vulnerability scans.
    
    Nuclei is a fast, customizable vulnerability scanner powered by the global
    security community. This service wraps the Nuclei CLI tool to integrate
    it into the ASM platform.
    
    Reference: https://github.com/projectdiscovery/nuclei
    """
    
    def __init__(
        self,
        nuclei_path: str = "nuclei",
        templates_path: Optional[str] = None,
        output_dir: Optional[str] = None
    ):
        """
        Initialize Nuclei service.
        
        Args:
            nuclei_path: Path to nuclei binary (default assumes it's in PATH)
            templates_path: Custom path to nuclei-templates
            output_dir: Directory for scan outputs
        """
        self.nuclei_path = nuclei_path
        self.templates_path = templates_path
        self.output_dir = output_dir or tempfile.gettempdir()
        
    def check_installation(self) -> bool:
        """Check if Nuclei is installed and accessible."""
        try:
            result = subprocess.run(
                [self.nuclei_path, "-version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False
    
    def update_templates(self) -> bool:
        """Update Nuclei templates to latest version."""
        try:
            result = subprocess.run(
                [self.nuclei_path, "-update-templates"],
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes
            )
            logger.info("Nuclei templates updated")
            return result.returncode == 0
        except subprocess.SubprocessError as e:
            logger.error(f"Failed to update templates: {e}")
            return False
    
    async def scan_targets(
        self,
        targets: list[str],
        severity: Optional[list[str]] = None,
        tags: Optional[list[str]] = None,
        exclude_tags: Optional[list[str]] = None,
        templates: Optional[list[str]] = None,
        rate_limit: int = 150,
        bulk_size: int = 25,
        concurrency: int = 25,
        timeout: int = 10,
        max_runtime_seconds: Optional[int] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> NucleiScanResult:
        """
        Run Nuclei scan against targets.
        
        Args:
            targets: List of targets (URLs, IPs, domains)
            severity: Severity levels to scan for ["critical", "high", "medium", "low", "info"]
            tags: Template tags to include
            exclude_tags: Template tags to exclude
            templates: Specific template paths/IDs
            rate_limit: Max requests per second
            bulk_size: Number of hosts to scan in parallel
            concurrency: Number of templates to run in parallel
            timeout: Request timeout in seconds
            progress_callback: Optional callback for progress updates
            
        Returns:
            NucleiScanResult with all findings
        """
        result = NucleiScanResult(success=False)
        start_time = datetime.utcnow()
        
        # Track original target count
        original_count = len(targets)
        
        # Expand CIDR ranges to individual IPs for accurate scanning
        expanded_targets, expanded_count = expand_cidr_targets(targets)
        
        logger.info(
            f"Target expansion: {original_count} input targets -> "
            f"{expanded_count} IPs (including CIDR expansion)"
        )
        
        # Create temporary files for input/output
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as targets_file:
            targets_file.write("\n".join(expanded_targets))
            targets_file_path = targets_file.name
        
        output_file_path = os.path.join(
            self.output_dir, 
            f"nuclei_scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        )
        
        try:
            # Build command
            # Nuclei v3.x: use -je (json-export) to write JSON Lines to a file
            # -o writes plain text, NOT json - so we use -je for JSON output
            cmd = [
                self.nuclei_path,
                "-list", targets_file_path,
                # JSONL export: written incrementally, so if we have to kill the
                # process on timeout we still keep the findings gathered so far.
                "-jle", output_file_path,
                "-rate-limit", str(rate_limit),
                "-bulk-size", str(bulk_size),
                "-concurrency", str(concurrency),
                "-timeout", str(timeout),
                "-no-color",
                # Include raw request/response in JSONL so findings can show
                # Praetorian-style Detection (request, cURL, response).
                "-irr",
            ]
            
            # Add severity filter
            if severity:
                cmd.extend(["-severity", ",".join(severity)])
            
            # Add tags
            if tags:
                cmd.extend(["-tags", ",".join(tags)])
            
            # Add exclude tags
            if exclude_tags:
                cmd.extend(["-exclude-tags", ",".join(exclude_tags)])
            
            # Collect explicit template sources (shipped + org custom).
            #
            # IMPORTANT: As soon as Nuclei is given ANY -t path it runs ONLY the
            # templates found in those paths and ignores its default template
            # directory (~/.config/nuclei/nuclei-templates).
            template_dirs: list[str] = []
            if templates:
                template_dirs.extend([t for t in templates if t])
            if self.templates_path:
                template_dirs.append(self.templates_path)

            # When this service is configured with a shipped custom-templates
            # directory (the broad vulnerability-scan use case) also add the
            # official templates corpus. Because -t restricts Nuclei to ONLY the
            # given paths, without this every scan would run just the handful of
            # shipped templates and finish in seconds with no findings. Targeted
            # callers that construct NucleiService() without templates_path (the
            # takeover engine, single-template recheck) intentionally keep their
            # narrow selection and are left untouched.
            if self.templates_path:
                from app.services.nuclei_template_parser_service import (
                    resolve_official_templates_path,
                )
                official_dir = resolve_official_templates_path()
                if (
                    official_dir
                    and os.path.isdir(official_dir)
                    and official_dir not in template_dirs
                ):
                    template_dirs.append(official_dir)
                    logger.info(f"Including official Nuclei templates from {official_dir}")
                else:
                    logger.warning(
                        "Official Nuclei templates directory not found "
                        f"(resolved: {official_dir!r}); scan will run only "
                        "custom/shipped templates. Run 'nuclei -update-templates'."
                    )

            for template_dir in template_dirs:
                cmd.extend(["-t", template_dir])
            
            # Resolve an overall runtime cap so a single scan can't run for
            # hours and monopolize a worker slot. 0/negative disables the cap.
            # Scale with host count: a flat 15m on 300+ hosts kills Nuclei before
            # templates finish, producing empty "completed" scheduled parts.
            if max_runtime_seconds is None:
                try:
                    base = int(os.getenv("NUCLEI_MAX_RUNTIME_SECONDS", "900"))
                except ValueError:
                    base = 900
                try:
                    per_host = int(os.getenv("NUCLEI_RUNTIME_SECONDS_PER_HOST", "18"))
                except ValueError:
                    per_host = 18
                try:
                    hard_cap = int(os.getenv("NUCLEI_MAX_RUNTIME_CAP_SECONDS", "2700"))
                except ValueError:
                    hard_cap = 2700
                if base <= 0:
                    max_runtime_seconds = 0  # disabled
                else:
                    scaled = max(base, per_host * max(len(targets), 1))
                    max_runtime_seconds = min(hard_cap, scaled) if hard_cap > 0 else scaled

            logger.info(
                f"Starting Nuclei scan on {len(targets)} targets "
                f"(max_runtime={max_runtime_seconds}s)"
            )
            logger.info(f"Nuclei command: {' '.join(cmd)}")

            # Run scan in its own process group so we can kill nuclei + children
            # on timeout (nuclei spawns workers that otherwise outlive the parent).
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )

            timed_out = False
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=max_runtime_seconds if max_runtime_seconds and max_runtime_seconds > 0 else None,
                )
            except asyncio.TimeoutError:
                timed_out = True
                result.timed_out = True
                logger.warning(
                    f"Nuclei exceeded {max_runtime_seconds}s; killing process group and "
                    "parsing partial results collected so far"
                )
                try:
                    import signal as _signal
                    os.killpg(process.pid, _signal.SIGKILL)
                except (ProcessLookupError, PermissionError, OSError):
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                try:
                    stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)
                except Exception:
                    stdout, stderr = b"", b""
                result.errors.append(
                    f"nuclei timed out after {max_runtime_seconds}s (partial results returned)"
                )

            logger.info(
                f"Nuclei process completed with return code: {process.returncode} "
                f"(timed_out={timed_out})"
            )
            
            if stdout:
                stdout_text = stdout.decode()[:1000]  # Limit stdout log
                logger.info(f"Nuclei stdout (first 1000 chars): {stdout_text}")
            
            if stderr:
                stderr_text = stderr.decode()
                # Info messages from Nuclei are normal
                if "[INF]" in stderr_text or "Templates loaded" in stderr_text:
                    logger.info(f"Nuclei info: {stderr_text[:800]}")
                elif process.returncode != 0:
                    if "no templates" not in stderr_text.lower():
                        logger.warning(f"Nuclei stderr: {stderr_text}")
                        result.errors.append(stderr_text)

                # Always parse run stats from stderr when present
                import re as _re
                run_stats: dict = {}
                m = _re.search(r"Templates loaded for current scan:\s*(\d+)", stderr_text)
                if m:
                    run_stats["templates_loaded"] = int(m.group(1))
                m = _re.search(r"Targets loaded for current scan:\s*(\d+)", stderr_text)
                if m:
                    run_stats["targets_loaded"] = int(m.group(1))
                m = _re.search(r"Found\s+(\d+)\s+URL", stderr_text)
                if m:
                    run_stats["httpx_live_urls"] = int(m.group(1))
                m = _re.search(r"Current nuclei-templates version:\s*(\S+)", stderr_text)
                if m:
                    run_stats["templates_version"] = m.group(1)
                if "no templates" in stderr_text.lower():
                    run_stats["no_templates"] = True
                    result.errors.append("nuclei reported no templates loaded")
                if run_stats:
                    result.summary = {"_run_stats": run_stats}
            
            # Parse results
            logger.info(f"Checking for Nuclei output file: {output_file_path}")
            if os.path.exists(output_file_path):
                file_size = os.path.getsize(output_file_path)
                logger.info(f"Nuclei output file exists, size: {file_size} bytes")
                
                with open(output_file_path, 'r') as f:
                    file_content = f.read().strip()
                
                # Handle both JSON Array format and JSON Lines format
                findings_data = []
                if file_content.startswith('['):
                    # JSON Array format (from -je flag)
                    try:
                        parsed = json.loads(file_content)
                        if isinstance(parsed, list):
                            findings_data = parsed
                            logger.info(f"Parsed as JSON array with {len(findings_data)} entries")
                        else:
                            logger.warning(f"Expected JSON array but got {type(parsed)}")
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse as JSON array: {e}")
                else:
                    # JSON Lines format (one JSON object per line)
                    for line_num, line in enumerate(file_content.split('\n'), 1):
                        line = line.strip()
                        if line:
                            try:
                                finding_data = json.loads(line)
                                if isinstance(finding_data, dict):
                                    findings_data.append(finding_data)
                            except json.JSONDecodeError as e:
                                logger.warning(f"Failed to parse JSON on line {line_num}: {e}")
                    logger.info(f"Parsed as JSON Lines with {len(findings_data)} entries")
                
                # Process each finding
                for idx, finding_data in enumerate(findings_data):
                    try:
                        # Skip non-dict entries
                        if not isinstance(finding_data, dict):
                            logger.debug(f"Skipping non-dict finding at index {idx}: {type(finding_data)}")
                            continue
                        
                        # Skip entries that don't have the required fields
                        if not finding_data.get("template-id") and not finding_data.get("templateID"):
                            logger.debug(f"Skipping entry without template-id at index {idx}")
                            continue
                        
                        finding = NucleiResult.from_json(finding_data)
                        result.findings.append(finding)
                        logger.debug(f"Parsed finding: {finding.template_id} on {finding.host}")
                    except (AttributeError, TypeError, KeyError) as e:
                        # Handle malformed data structures in Nuclei output
                        logger.warning(f"Failed to process finding at index {idx}: {e} - data: {str(finding_data)[:200]}")
                    except Exception as e:
                        logger.warning(f"Unexpected error parsing finding at index {idx}: {e}")
                
                logger.info(f"Parsed {len(result.findings)} findings from output file")
            else:
                logger.warning(f"Nuclei output file NOT found at: {output_file_path}")
            
            result.success = True
            result.targets_scanned = expanded_count
            result.targets_original = original_count
            result.targets_expanded = expanded_count
            
            # Generate summary (preserve run stats parsed from stderr)
            run_stats = {}
            if isinstance(result.summary, dict):
                run_stats = dict(result.summary.pop("_run_stats", {}) or {})
            result.summary = {**self._generate_summary(result.findings), **run_stats}
            
        except Exception as e:
            logger.error(f"Nuclei scan failed: {e}")
            result.errors.append(str(e))
            
        finally:
            # Cleanup temporary files
            if os.path.exists(targets_file_path):
                os.unlink(targets_file_path)
            if os.path.exists(output_file_path):
                os.unlink(output_file_path)
            
            result.duration_seconds = (datetime.utcnow() - start_time).total_seconds()
        
        logger.info(
            f"Nuclei scan complete: {len(result.findings)} findings in "
            f"{result.duration_seconds:.2f}s"
        )
        
        return result
    
    async def scan_single_target(
        self,
        target: str,
        severity: Optional[list[str]] = None,
        tags: Optional[list[str]] = None,
        **kwargs
    ) -> NucleiScanResult:
        """Scan a single target."""
        return await self.scan_targets([target], severity, tags, **kwargs)
    
    def scan_targets_sync(
        self,
        targets: list[str],
        **kwargs
    ) -> NucleiScanResult:
        """Synchronous wrapper for scan_targets."""
        return asyncio.run(self.scan_targets(targets, **kwargs))
    
    def _generate_summary(self, findings: list[NucleiResult]) -> dict:
        """Generate summary statistics from findings."""
        by_severity = {}
        by_template = {}
        by_host = {}
        cves_found = set()
        
        for finding in findings:
            # By severity
            sev = finding.severity.lower()
            by_severity[sev] = by_severity.get(sev, 0) + 1
            
            # By template
            tid = finding.template_id
            by_template[tid] = by_template.get(tid, 0) + 1
            
            # By host
            host = finding.host
            by_host[host] = by_host.get(host, 0) + 1
            
            # CVEs
            if finding.cve_id:
                cves_found.add(finding.cve_id)
        
        return {
            "total_findings": len(findings),
            "by_severity": by_severity,
            "unique_templates": len(by_template),
            "unique_hosts": len(by_host),
            "cves_found": list(cves_found),
            "critical_count": by_severity.get("critical", 0),
            "high_count": by_severity.get("high", 0),
            "medium_count": by_severity.get("medium", 0),
            "low_count": by_severity.get("low", 0),
            "info_count": by_severity.get("info", 0),
        }
    
    def get_available_tags(self) -> list[str]:
        """Get list of available Nuclei template tags."""
        # Common Nuclei tags
        return [
            # Vulnerability types
            "cve", "rce", "sqli", "xss", "ssrf", "lfi", "rfi", "xxe", "ssti",
            "idor", "csrf", "auth-bypass", "injection",
            # Technology/Service
            "tech", "apache", "nginx", "iis", "tomcat", "wordpress", "joomla",
            "drupal", "magento", "jenkins", "gitlab", "aws", "azure", "gcp",
            # Severity/Impact  
            "critical", "high", "medium", "low", "info",
            # Discovery type
            "exposure", "misconfig", "default-login", "unauth", "takeover",
            "creds-exposure", "token", "backup", "debug",
            # Protocol
            "http", "https", "ftp", "ssh", "dns", "smtp", "ssl",
            # Categories
            "cisa-kev", "oast", "headless", "fuzzing", "dos",
        ]
    
    def get_severity_levels(self) -> list[str]:
        """Get available severity levels."""
        return ["critical", "high", "medium", "low", "info"]


# Severity to risk score mapping
SEVERITY_RISK_SCORES = {
    "critical": 95,
    "high": 75,
    "medium": 50,
    "low": 25,
    "info": 10,
    "unknown": 0,
}

















