"""
ParamSpider Service for URL parameter discovery.

ParamSpider mines parameters from web archives (Wayback Machine, Common Crawl)
to discover URL parameters that may be vulnerable to testing.

Installation: pip install paramspider
GitHub: https://github.com/devanshbatham/ParamSpider
"""

import asyncio
import ipaddress
import json
import logging
import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)

_HOSTNAME_RE = re.compile(r'^[a-z0-9._-]+$')


def _is_ip_or_cidr(value: str) -> bool:
    """Return True if value is an IP address or CIDR block."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        pass
    return False


def filter_scannable_domains(targets: List[str]) -> Tuple[List[str], dict]:
    """
    Normalize and filter a raw target list down to domains ParamSpider can
    actually mine from web archives.

    ParamSpider queries the Wayback Machine / Common Crawl by hostname, so IPs,
    CIDR blocks, and malformed entries can never return results and only waste
    scan slots. Wildcard entries (``*.example.com``) are collapsed to their base
    domain, and duplicates are removed (order preserved).

    Returns:
        (domains, stats) where ``domains`` is a deduped list of scannable
        hostnames and ``stats`` summarizes what was dropped.
    """
    seen = set()
    domains: List[str] = []
    skipped_ip = 0
    skipped_invalid = 0

    for raw in targets:
        if not raw or not isinstance(raw, str):
            skipped_invalid += 1
            continue

        value = raw.strip().lower()

        # Strip scheme, path, and port if a full URL slipped in
        if '://' in value:
            value = value.split('://', 1)[1]
        value = value.split('/', 1)[0].split('?', 1)[0]
        if value.count(':') == 1:  # host:port (leave IPv6 alone)
            value = value.split(':', 1)[0]

        # Collapse wildcards: *.example.com / .example.com -> example.com
        if value.startswith('*.'):
            value = value[2:]
        elif value.startswith('.'):
            value = value[1:]

        if not value:
            skipped_invalid += 1
            continue

        # Drop IPs and CIDR ranges (including semicolon-joined CIDR lists)
        if _is_ip_or_cidr(value) or ';' in raw or ' ' in value:
            skipped_ip += 1
            continue

        # Must look like a hostname: at least one dot, no wildcards left, and
        # only hostname-legal characters.
        if '.' not in value or '*' in value or not _HOSTNAME_RE.match(value):
            skipped_invalid += 1
            continue

        if value in seen:
            continue
        seen.add(value)
        domains.append(value)

    stats = {
        'input_targets': len(targets),
        'scannable_domains': len(domains),
        'skipped_ip_cidr': skipped_ip,
        'skipped_invalid': skipped_invalid,
        'deduped': len(targets) - len(domains) - skipped_ip - skipped_invalid,
    }
    return domains, stats


@dataclass
class ParamSpiderResult:
    """Result from ParamSpider scan."""
    domain: str
    urls: List[str] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    success: bool = False
    error: Optional[str] = None
    elapsed_time: float = 0.0


def _check_paramspider_available() -> bool:
    """Check if paramspider is installed."""
    return shutil.which("paramspider") is not None


class ParamSpiderService:
    """
    Service for discovering URL parameters using ParamSpider.
    
    ParamSpider finds parameters by mining web archives for a domain,
    extracting unique parameters that may be vulnerable to XSS, SQLi, etc.
    """
    
    def __init__(self, output_dir: Optional[str] = None):
        """
        Initialize ParamSpider service.
        
        Args:
            output_dir: Directory to store output files (temp dir if None)
        """
        self.paramspider_path = shutil.which("paramspider")
        self.output_dir = output_dir or tempfile.gettempdir()
        
    def is_available(self) -> bool:
        """Check if ParamSpider is available."""
        return self.paramspider_path is not None
    
    async def scan_domain(
        self,
        domain: str,
        level: str = "high",
        exclude_extensions: Optional[List[str]] = None,
        timeout: int = 300,
    ) -> ParamSpiderResult:
        """
        Run ParamSpider on a domain to discover parameters.
        
        Args:
            domain: Domain to scan (e.g., example.com)
            level: Unused (kept for API compat); ParamSpider has no level flag
            exclude_extensions: Unused (kept for API compat); ParamSpider uses hardcoded extensions
            timeout: Command timeout in seconds
            
        Returns:
            ParamSpiderResult with discovered parameters
        """
        result = ParamSpiderResult(domain=domain)
        start_time = datetime.utcnow()
        
        if not self.is_available():
            result.error = "ParamSpider not installed. Run: pip install paramspider"
            return result
        
        work_dir = tempfile.mkdtemp(prefix="paramspider_")
        
        try:
            cmd = [
                self.paramspider_path,
                "-d", domain,
                "-s",
            ]
            
            logger.info(f"Running ParamSpider on {domain}: {' '.join(cmd)}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=work_dir,
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                result.error = f"ParamSpider timed out after {timeout}s"
                return result
            
            if process.returncode not in (0, None):
                stderr_text = stderr.decode('utf-8', errors='ignore').strip() if stderr else ''
                logger.warning(f"ParamSpider exited {process.returncode} for {domain}: {stderr_text}")
                result.error = f"ParamSpider exit {process.returncode}: {stderr_text[:240]}"
            
            all_urls: Set[str] = set()
            all_params: Set[str] = set()
            all_endpoints: Set[str] = set()
            all_js_files: Set[str] = set()
            
            # ParamSpider writes output to results/{domain}.txt in its cwd
            output_file = os.path.join(work_dir, "results", f"{domain}.txt")
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        url = line.strip()
                        if url and not url.startswith('#'):
                            all_urls.add(url)
            
            # Also capture URLs from stdout (-s stream mode)
            if stdout:
                for line in stdout.decode('utf-8', errors='ignore').splitlines():
                    url = line.strip()
                    if url and url.startswith(('http://', 'https://')) and '?' in url:
                        all_urls.add(url)
            
            for url in all_urls:
                parsed = urlparse(url)
                if parsed.path and parsed.path != '/':
                    all_endpoints.add(parsed.path)
                if parsed.path.endswith('.js'):
                    all_js_files.add(url)
                if parsed.query:
                    params = parse_qs(parsed.query)
                    for param_name in params.keys():
                        all_params.add(param_name)
            
            result.urls = sorted(list(all_urls))
            result.parameters = sorted(list(all_params))
            result.endpoints = sorted(list(all_endpoints))
            result.js_files = sorted(list(all_js_files))
            # A partial stream can still provide leads, but a failed process
            # with no URLs must not be reported as a successful recon pass.
            result.success = process.returncode == 0 or bool(all_urls)
            
            logger.info(
                f"ParamSpider found {len(result.urls)} URLs, "
                f"{len(result.parameters)} parameters, "
                f"{len(result.endpoints)} endpoints for {domain}"
            )
            
        except Exception as e:
            logger.error(f"ParamSpider error for {domain}: {e}")
            result.error = str(e)
        finally:
            try:
                shutil.rmtree(work_dir, ignore_errors=True)
            except Exception:
                pass
        
        result.elapsed_time = (datetime.utcnow() - start_time).total_seconds()
        return result
    
    async def scan_multiple_domains(
        self,
        domains: List[str],
        max_concurrent: int = 5,
        **kwargs
    ) -> List[ParamSpiderResult]:
        """
        Scan multiple domains concurrently.
        
        Args:
            domains: List of domains to scan
            max_concurrent: Maximum concurrent scans
            **kwargs: Additional arguments for scan_domain
            
        Returns:
            List of ParamSpiderResult
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def scan_with_limit(domain: str) -> ParamSpiderResult:
            async with semaphore:
                return await self.scan_domain(domain, **kwargs)
        
        tasks = [scan_with_limit(d) for d in domains]
        return await asyncio.gather(*tasks)


# Convenience function
async def discover_parameters(domain: str) -> ParamSpiderResult:
    """Quick function to discover parameters for a domain."""
    service = ParamSpiderService()
    return await service.scan_domain(domain)
