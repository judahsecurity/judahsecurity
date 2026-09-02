"""
Unified port scanner service integrating multiple scanning tools.

Supports:
- Naabu: Fast port scanner from ProjectDiscovery (https://github.com/projectdiscovery/naabu)
- Masscan: Mass IP port scanner
- Nmap: Network exploration and security auditing

All results are normalized to a common format for storage in the PortService model.
"""

import asyncio
import json
import logging
import subprocess
import tempfile
import os
import re
import xml.etree.ElementTree as ET
from typing import Optional, List, Callable, Dict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetType
from app.models.port_service import (
    PortService, Protocol, PortState, 
    RISKY_PORTS, SERVICE_NAMES
)

logger = logging.getLogger(__name__)


class ScannerType(str, Enum):
    """Available port scanner types."""
    NAABU = "naabu"
    MASSCAN = "masscan"
    NMAP = "nmap"


@dataclass
class PortResult:
    """Normalized port scan result."""
    host: str
    ip: str
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service_name: Optional[str] = None
    service_product: Optional[str] = None
    service_version: Optional[str] = None
    service_extra_info: Optional[str] = None
    banner: Optional[str] = None
    cpe: Optional[str] = None
    reason: Optional[str] = None
    scanner: str = "unknown"
    # NSE script output captured for this port (script id -> output text).
    scripts: Dict[str, str] = field(default_factory=dict)
    # Parsed OT/ICS device identity (dict form), when an OT NSE script matched.
    ot_identity: Optional[dict] = None

    def to_port_service_dict(self, asset_id: int) -> dict:
        """Convert to PortService creation dict."""
        # Auto-detect service name from port if not provided
        service = self.service_name
        if not service and self.port in SERVICE_NAMES:
            service = SERVICE_NAMES[self.port]
        
        # Determine if risky
        is_risky = self.port in RISKY_PORTS
        risk_reason = RISKY_PORTS.get(self.port) if is_risky else None
        
        # Map state
        state_map = {
            "open": PortState.OPEN,
            "closed": PortState.CLOSED,
            "filtered": PortState.FILTERED,
            "open|filtered": PortState.OPEN_FILTERED,
            "closed|filtered": PortState.CLOSED_FILTERED,
        }
        
        service_product = self.service_product
        service_version = self.service_version
        service_extra_info = self.service_extra_info
        metadata: dict = {}
        tags: List[str] = []

        # Surface parsed OT/ICS device identity so an operator can see, e.g.,
        # that a host is a Rockwell 1769-L36ERM rather than just "port 44818 open".
        if self.ot_identity:
            metadata["ot_device"] = self.ot_identity
            ot_product = self.ot_identity.get("display_name") or None
            if ot_product:
                service_product = ot_product
            if self.ot_identity.get("revision"):
                service_version = service_version or self.ot_identity["revision"]
            extra_bits = [b for b in (
                self.ot_identity.get("device_type"),
                f"S/N {self.ot_identity['serial']}" if self.ot_identity.get("serial") else None,
            ) if b]
            if extra_bits:
                service_extra_info = "; ".join(extra_bits)[:500]
            tags = list(self.ot_identity.get("tags") or [])

        return {
            "asset_id": asset_id,
            "port": self.port,
            "protocol": Protocol(self.protocol.lower()),
            "service_name": service,
            "service_product": service_product,
            "service_version": service_version,
            "service_extra_info": service_extra_info,
            "banner": self.banner,
            "cpe": self.cpe,
            "state": state_map.get(self.state.lower(), PortState.OPEN),
            "reason": self.reason,
            "discovered_by": self.scanner,
            "is_risky": is_risky,
            "risk_reason": risk_reason,
            "tags": tags,
            "metadata_": metadata,
        }


@dataclass
class HostScanResult:
    """Result for a single host."""
    host: str
    ip: str
    is_live: bool = True
    open_ports: List[int] = field(default_factory=list)
    
    @property
    def port_count(self) -> int:
        return len(self.open_ports)


@dataclass
class ScanResult:
    """Complete scan result from any scanner."""
    success: bool
    scanner: ScannerType
    targets_scanned: int = 0
    ports_found: List[PortResult] = field(default_factory=list)
    hosts_scanned: List[str] = field(default_factory=list)  # All targets that were scanned
    hosts_found: List[HostScanResult] = field(default_factory=list)  # Hosts with results (live or with ports)
    errors: List[str] = field(default_factory=list)
    duration_seconds: float = 0
    raw_output: Optional[str] = None
    
    @property
    def live_host_count(self) -> int:
        return len([h for h in self.hosts_found if h.is_live])


class PortScannerService:
    """
    Unified service for running port scans with multiple tools.
    
    Supports Naabu, Masscan, and Nmap with normalized output format.
    """
    
    # Common locations for NSE script files (Debian/Ubuntu + local installs).
    _NSE_SCRIPT_DIRS = (
        "/usr/share/nmap/scripts",
        "/usr/local/share/nmap/scripts",
    )

    def __init__(
        self,
        naabu_path: str = "naabu",
        masscan_path: str = "masscan",
        nmap_path: str = "nmap"
    ):
        """Initialize port scanner service."""
        self.naabu_path = naabu_path
        self.masscan_path = masscan_path
        self.nmap_path = nmap_path
    
    def _filter_available_nse_scripts(self, scripts: List[str]) -> tuple:
        """
        Keep only NSE scripts that exist on this host.

        Nmap aborts the entire scan if any --script name is missing
        (e.g. community scripts like opcua-info / dnp3-info / codesys-v2-discover
        that are not shipped with the distro nmap package).
        """
        if not scripts:
            return [], []

        script_dirs = [d for d in self._NSE_SCRIPT_DIRS if os.path.isdir(d)]
        available = []
        missing = []

        for name in scripts:
            base = name[:-4] if name.endswith(".nse") else name
            # Categories (e.g. "default", "discovery") are not files — pass through.
            if "/" not in base and os.path.sep not in base and "." not in base:
                # Could be a category or a script basename. Prefer file match;
                # if no scripts dir is readable, keep the name and let nmap decide.
                found = False
                for d in script_dirs:
                    if os.path.isfile(os.path.join(d, f"{base}.nse")):
                        available.append(base)
                        found = True
                        break
                if found:
                    continue
                # Known NSE category names — keep without requiring a .nse file
                if base in {
                    "auth", "broadcast", "brute", "default", "discovery",
                    "dos", "exploit", "external", "fuzzer", "intrusive",
                    "malware", "safe", "version", "vuln",
                }:
                    available.append(base)
                    continue
                if script_dirs:
                    missing.append(base)
                else:
                    available.append(base)
            else:
                # Path-like script reference
                if os.path.isfile(name) or any(
                    os.path.isfile(os.path.join(d, name)) for d in script_dirs
                ):
                    available.append(name)
                else:
                    missing.append(name)

        return available, missing

    def _validate_targets(self, targets: List[str], ip_only: bool = False) -> tuple:
        """
        Validate and clean targets, removing invalid entries.
        
        Args:
            targets: Raw target list (IPs, CIDRs, hostnames)
            ip_only: If True, only accept IPv4 addresses/CIDRs (required for masscan,
                     which cannot resolve hostnames and fails the whole -iL file on
                     the first non-IP line).
        
        Returns: (valid_targets, invalid_targets)
        """
        import ipaddress
        import re
        
        valid = []
        invalid = []
        skipped_hostnames = 0
        
        # Domain regex - basic validation
        domain_pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$')
        
        for target in targets:
            target = target.strip()
            if not target:
                continue
            
            # Skip comments
            if target.startswith('#'):
                continue
            
            # Check if it's a valid IP address
            try:
                ip = ipaddress.ip_address(target)
                # Masscan / raw scanners: skip non-routable noise that wastes probes
                if ip_only and (ip.version != 4 or ip.is_unspecified or ip.is_loopback or ip.is_multicast):
                    invalid.append(target)
                    continue
                valid.append(target)
                continue
            except ValueError:
                pass
            
            # Check if it's a valid CIDR
            try:
                network = ipaddress.ip_network(target, strict=False)
                if ip_only and network.version != 4:
                    invalid.append(target)
                    continue
                valid.append(target)
                continue
            except ValueError:
                pass
            
            # Hostnames are valid for naabu/nmap, but masscan cannot resolve them.
            # Passing hostnames to masscan -iL aborts with:
            #   "invalid IP address on line #1" / "FAIL: error reading from include file"
            if domain_pattern.match(target) or (
                re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$', target) and '.' in target
            ):
                if ip_only:
                    skipped_hostnames += 1
                    continue
                valid.append(target)
                continue
            
            # Invalid target
            invalid.append(target)
        
        if skipped_hostnames:
            logger.info(
                f"Skipped {skipped_hostnames} hostnames for masscan "
                f"(masscan requires IPs/CIDRs; use naabu to scan hostnames)"
            )
            # Surface as a skip notice (not a malformed target) for callers
            invalid.append(f"Skipped {skipped_hostnames} hostnames (masscan requires IPs/CIDRs)")
        
        if invalid:
            # Only log true invalids, not the hostname skip summary line
            true_invalid = [t for t in invalid if not str(t).startswith("Skipped ")]
            if true_invalid:
                logger.warning(
                    f"Filtered {len(true_invalid)} invalid targets: "
                    f"{true_invalid[:5]}{'...' if len(true_invalid) > 5 else ''}"
                )
        
        return valid, invalid
    
    def get_port_list(self, db, name: str) -> str:
        """
        Get a port list from the database by name.
        
        Args:
            db: Database session
            name: Port list name (e.g., "critical", "quick", "databases")
        
        Returns:
            Comma-separated port string
        """
        from app.models.scan_config import ScanConfig
        
        config = db.query(ScanConfig).filter(
            ScanConfig.config_type == "port_list",
            ScanConfig.name == name,
            ScanConfig.is_active == True
        ).first()
        
        if config and config.config.get("ports"):
            return ",".join(str(p) for p in config.config["ports"])
        
        # Fallback to hardcoded lists
        if name == "critical":
            from app.models.scan_schedule import ALL_CRITICAL_PORTS
            return ",".join(str(p) for p in ALL_CRITICAL_PORTS)
        elif name == "quick":
            return self.COMMON_PORTS
        elif name == "full":
            return self.TOP_PORTS
        
        return self.COMMON_PORTS
    
    def check_tools(self) -> dict[str, bool]:
        """Check which scanning tools are available."""
        tools = {
            "naabu": self.naabu_path,
            "masscan": self.masscan_path,
            "nmap": self.nmap_path,
        }
        
        status = {}
        for name, path in tools.items():
            try:
                result = subprocess.run(
                    [path, "--version" if name != "naabu" else "-version"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                status[name] = result.returncode == 0
            except (subprocess.SubprocessError, FileNotFoundError):
                status[name] = False
        
        return status
    
    # ==================== NAABU ====================
    
    async def scan_with_naabu(
        self,
        targets: List[str],
        ports: Optional[str] = None,
        top_ports: int = 100,
        rate: int = 500,  # Reduced default rate for reliability
        timeout: int = 30,  # Increased timeout
        exclude_cdn: bool = True,
        retries: int = 2,  # Number of retry attempts
        chunk_size: int = 64,  # Max hosts per chunk for large CIDR scans
    ) -> ScanResult:
        """
        Run port scan using Naabu with improved reliability.
        
        Naabu is a fast port scanner from ProjectDiscovery designed for
        reliability and simplicity. Supports SYN/CONNECT scans.
        
        Reference: https://github.com/projectdiscovery/naabu
        
        Args:
            targets: List of targets (IPs, domains, CIDRs)
            ports: Port specification (e.g., "80,443,8080" or "1-1000" or "-" for all)
            top_ports: Scan top N ports if ports not specified
            rate: Packets per second (default 500 for reliability)
            timeout: Timeout in seconds per host (default 30)
            exclude_cdn: Exclude CDN IPs (only scan 80,443)
            retries: Number of retry attempts on failure
            chunk_size: Max targets per scan chunk (for large CIDR ranges)
        """
        result = ScanResult(success=False, scanner=ScannerType.NAABU)
        start_time = datetime.utcnow()
        
        # Expand CIDR ranges and chunk if needed for large scans
        expanded_targets = self._expand_and_chunk_targets(targets, chunk_size)
        total_chunks = len(expanded_targets)
        
        if total_chunks > 1:
            logger.info(f"Splitting scan into {total_chunks} chunks of ~{chunk_size} targets each")
        
        all_ports_found = []
        chunk_errors = []
        
        for chunk_idx, target_chunk in enumerate(expanded_targets):
            chunk_result = await self._scan_naabu_chunk(
                targets=target_chunk,
                ports=ports,
                top_ports=top_ports,
                rate=rate,
                timeout=timeout,
                exclude_cdn=exclude_cdn,
                retries=retries,
                chunk_num=chunk_idx + 1,
                total_chunks=total_chunks
            )
            
            all_ports_found.extend(chunk_result.ports_found)
            chunk_errors.extend(chunk_result.errors)
            
            # Small delay between chunks to avoid overwhelming the network
            if chunk_idx < total_chunks - 1:
                await asyncio.sleep(1)
        
        result.ports_found = all_ports_found
        result.errors = chunk_errors
        result.success = True
        result.targets_scanned = sum(len(chunk) for chunk in expanded_targets)
        result.duration_seconds = (datetime.utcnow() - start_time).total_seconds()
        
        # Track all scanned hosts and build host results
        all_targets = []
        for chunk in expanded_targets:
            all_targets.extend(chunk)
        result.hosts_scanned = all_targets
        
        # Build host results from port findings
        result.hosts_found = self._build_host_results(all_ports_found, all_targets)
        
        logger.info(f"Naabu found {len(result.ports_found)} open ports across {result.targets_scanned} targets, {len(result.hosts_found)} hosts with open ports")
        return result
    
    def _expand_and_chunk_targets(self, targets: List[str], chunk_size: int) -> List[List[str]]:
        """Expand CIDR ranges and split into manageable chunks."""
        import ipaddress
        
        expanded = []
        for target in targets:
            # Check if it's a CIDR range
            if '/' in target:
                try:
                    network = ipaddress.ip_network(target, strict=False)
                    # Only expand if it's a manageable size (up to /20 = 4096 hosts)
                    if network.num_addresses <= 4096:
                        expanded.extend([str(ip) for ip in network.hosts()])
                    else:
                        # For very large ranges, keep as CIDR and let naabu handle it
                        expanded.append(target)
                except ValueError:
                    expanded.append(target)
            else:
                expanded.append(target)
        
        # Chunk the expanded list
        if len(expanded) <= chunk_size:
            return [expanded]
        
        return [expanded[i:i + chunk_size] for i in range(0, len(expanded), chunk_size)]
    
    async def _scan_naabu_chunk(
        self,
        targets: List[str],
        ports: Optional[str],
        top_ports: int,
        rate: int,
        timeout: int,
        exclude_cdn: bool,
        retries: int,
        chunk_num: int,
        total_chunks: int
    ) -> ScanResult:
        """Scan a single chunk of targets with retry logic."""
        result = ScanResult(success=False, scanner=ScannerType.NAABU)
        
        for attempt in range(retries + 1):
            try:
                chunk_result = await self._execute_naabu_scan(
                    targets, ports, top_ports, rate, timeout, exclude_cdn
                )
                
                if chunk_result.success or not chunk_result.errors:
                    result = chunk_result
                    break
                
                # Check if errors are retryable
                retryable_errors = ['timeout', 'connection refused', 'network unreachable', 'temporary failure']
                is_retryable = any(
                    err_type in ' '.join(chunk_result.errors).lower() 
                    for err_type in retryable_errors
                )
                
                if is_retryable and attempt < retries:
                    wait_time = (attempt + 1) * 2  # Exponential backoff: 2s, 4s, 6s
                    logger.warning(
                        f"Chunk {chunk_num}/{total_chunks} attempt {attempt + 1} failed, "
                        f"retrying in {wait_time}s..."
                    )
                    await asyncio.sleep(wait_time)
                    # Reduce rate on retry
                    rate = max(100, rate // 2)
                else:
                    result = chunk_result
                    break
                    
            except Exception as e:
                logger.error(f"Chunk {chunk_num}/{total_chunks} error: {e}")
                if attempt < retries:
                    await asyncio.sleep((attempt + 1) * 2)
                else:
                    result.errors.append(str(e))
        
        return result
    
    async def _execute_naabu_scan(
        self,
        targets: List[str],
        ports: Optional[str],
        top_ports: int,
        rate: int,
        timeout: int,
        exclude_cdn: bool
    ) -> ScanResult:
        """Execute a single naabu scan."""
        result = ScanResult(success=False, scanner=ScannerType.NAABU)
        
        # Verify naabu binary exists BEFORE creating temp files
        import shutil
        naabu_binary = shutil.which(self.naabu_path)
        if not naabu_binary:
            error_msg = f"Naabu binary not found at '{self.naabu_path}'. Check if naabu is installed."
            logger.error(error_msg)
            result.errors.append(error_msg)
            return result
        
        logger.debug(f"Found naabu at: {naabu_binary}")
        
        # Validate targets before writing to file
        valid_targets, invalid_targets = self._validate_targets(targets)
        if invalid_targets:
            result.errors.append(f"Skipped {len(invalid_targets)} invalid targets")
        
        if not valid_targets:
            result.errors.append("No valid targets to scan")
            return result
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as targets_file:
            targets_file.write("\n".join(valid_targets))
            targets_path = targets_file.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as output_file:
            output_path = output_file.name
        
        try:
            cmd = [
                self.naabu_path,
                "-list", targets_path,
                "-json",
                "-o", output_path,
                "-silent",
                "-rate", str(rate),
                "-timeout", str(timeout),
                "-retries", "2",  # Naabu internal retries
                "-scan-type", "c",  # Use CONNECT scan (doesn't require root privileges)
            ]
            
            # Handle port specification
            if ports:
                if ports == "-" or ports == "all":
                    cmd.extend(["-p", "-"])
                else:
                    cmd.extend(["-p", ports])
            else:
                cmd.extend(["-top-ports", str(top_ports)])
            
            if exclude_cdn:
                cmd.append("-exclude-cdn")
            
            # Log the command for debugging
            cmd_str = ' '.join(cmd)
            logger.info(f"Naabu command: {cmd_str}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                # Add overall timeout for the scan process
                # Minimum 5 minutes (300s), scales up with target count
                scan_timeout = max(300, timeout * len(targets) + 60)
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=scan_timeout
                )
            except asyncio.TimeoutError:
                scan_timeout = max(300, timeout * len(targets) + 60)
                try:
                    process.kill()
                    await process.wait()
                except ProcessLookupError:
                    pass  # Process already terminated
                result.errors.append(f"Scan timed out after {scan_timeout}s")
                return result
            
            # Log any errors from naabu
            if process.returncode != 0:
                stderr_text = stderr.decode().strip() if stderr else ""
                stdout_text = stdout.decode().strip() if stdout else ""
                error_msg = stderr_text or stdout_text or f"Unknown error"
                logger.error(f"Naabu scan failed (exit code {process.returncode}): {error_msg}")
                result.errors.append(f"Exit code {process.returncode}: {error_msg}")
            
            if stderr:
                stderr_text = stderr.decode()
                if "error" in stderr_text.lower() or "failed" in stderr_text.lower():
                    logger.warning(f"Naabu stderr: {stderr_text}")
                    # Don't add to errors if it's just info messages
                    if "fatal" in stderr_text.lower() or process.returncode != 0:
                        result.errors.append(stderr_text)
                else:
                    logger.debug(f"Naabu output: {stderr_text}")
            
            # Parse JSON output
            if os.path.exists(output_path):
                with open(output_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                data = json.loads(line)
                                result.ports_found.append(PortResult(
                                    host=data.get("host", ""),
                                    ip=data.get("ip", data.get("host", "")),
                                    port=data.get("port", 0),
                                    protocol=data.get("protocol", "tcp"),
                                    state="open",
                                    scanner="naabu"
                                ))
                            except json.JSONDecodeError:
                                pass
            
            result.success = True
            result.targets_scanned = len(targets)
            
        except FileNotFoundError as e:
            error_msg = f"Naabu binary not found: {e}. Ensure naabu is installed at {self.naabu_path}"
            logger.error(error_msg)
            result.errors.append(error_msg)
        except PermissionError as e:
            error_msg = f"Permission denied running naabu: {e}"
            logger.error(error_msg)
            result.errors.append(error_msg)
        except Exception as e:
            logger.error(f"Naabu scan failed with {type(e).__name__}: {e}", exc_info=True)
            result.errors.append(f"{type(e).__name__}: {str(e)}")
        
        finally:
            for path in [targets_path, output_path]:
                if os.path.exists(path):
                    os.unlink(path)
        
        return result
    
    # ==================== MASSCAN ====================
    
    # Common ports for quick scans (top 100 most common)
    COMMON_PORTS = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8080,8443"
    
    # Top 1000 ports (nmap default) - for standard scans
    TOP_PORTS = "1,3,7,9,13,17,19,21-23,25-26,37,53,79-82,88,100,106,110-111,113,119,135,139,143-144,179,199,254,255,280,311,389,427,443-445,464-465,497,513-515,543-544,548,554,587,593,625,631,636,646,787,808,873,902,990,993,995,1000,1022,1024-1033,1035-1041,1044,1048-1050,1053-1054,1056,1058-1059,1064-1066,1069,1071,1074,1080,1110,1234,1433,1494,1521,1720,1723,1755,1761,1801,1900,1935,1998,2000-2003,2005,2049,2103,2105,2107,2121,2161,2301,2383,2401,2601,2717,2869,2967,3000-3001,3128,3268,3306,3389,3689-3690,3703,3986,4000-4001,4045,4443,4899,5000-5001,5003,5009,5050-5051,5060,5101,5120,5190,5357,5432,5555,5631,5666,5800,5900-5901,6000-6002,6004,6112,6646,6666,7000,7070,7937-7938,8000,8002,8008-8010,8031,8080-8081,8443,8888,9000-9001,9090,9100,9102,9999-10001,10010,32768,32771,49152-49157"
    
    async def scan_with_masscan(
        self,
        targets: List[str],
        ports: Optional[str] = None,  # None = use top ports, not all
        rate: int = 10000,
        timeout: int = 30,
        banner_grab: bool = True,
        one_port_at_a_time: bool = False
    ) -> ScanResult:
        """
        Run port scan using Masscan.
        
        Masscan is the fastest port scanner, capable of scanning the
        entire internet in under 6 minutes. Supports CIDR notation
        (e.g., 205.175.240.0/24) directly in targets.
        
        NOTE: Masscan requires root privileges for raw socket access.
        In Docker, the container needs CAP_NET_RAW + CAP_NET_ADMIN and run as root.
        
        Args:
            targets: List of targets (IPs, CIDRs like 205.175.240.0/24)
            ports: Port specification (e.g., "80,443", "1-1000")
                   None or empty = top 1000 ports (safer default)
                   "all" or "-" = all 65535 ports (slow!)
            rate: Packets per second (default 10000, reduce for stealth)
            timeout: Wait time after scan completes
            banner_grab: Enable banner grabbing for service detection
            one_port_at_a_time: Scan each port separately (slower but avoids cloud blocks)
        """
        result = ScanResult(success=False, scanner=ScannerType.MASSCAN)
        start_time = datetime.utcnow()
        
        # Handle special port notation - SAFER DEFAULTS
        if ports == "all" or ports == "-":
            ports = "0-65535"
            logger.warning("Scanning ALL 65535 ports - this will be slow for large ranges!")
        elif not ports or ports.strip() == "":
            # Default to top ports instead of all ports for faster scans
            ports = self.TOP_PORTS
            logger.info(f"No ports specified, using top ~1000 common ports")
        
        # Estimate scan time for large scans
        num_ports = self._count_ports(ports)
        num_hosts = self._estimate_hosts(targets)
        total_probes = num_ports * num_hosts
        estimated_seconds = total_probes / rate + timeout
        
        if estimated_seconds > 300:  # More than 5 minutes
            logger.warning(
                f"Large scan detected: {num_hosts} hosts × {num_ports} ports = {total_probes:,} probes. "
                f"Estimated time: {estimated_seconds/60:.1f} minutes at {rate} pps"
            )
        else:
            logger.info(
                f"Scan estimate: {num_hosts} hosts × {num_ports} ports = {total_probes:,} probes, "
                f"~{estimated_seconds:.0f} seconds"
            )
        
        # If one_port_at_a_time mode, scan each port separately (ASM Recon approach)
        # This is slower but less likely to be blocked by cloud providers
        if one_port_at_a_time:
            return await self._scan_masscan_per_port(
                targets, ports, rate, timeout, banner_grab
            )
        
        # Masscan only accepts IPs/CIDRs — hostnames abort the whole -iL file.
        valid_targets, invalid_targets = self._validate_targets(targets, ip_only=True)
        true_invalid = [t for t in invalid_targets if not str(t).startswith("Skipped ")]
        for notice in invalid_targets:
            if str(notice).startswith("Skipped "):
                result.errors.append(notice)
        if true_invalid:
            result.errors.append(f"Skipped {len(true_invalid)} invalid targets")
        
        if not valid_targets:
            result.errors.append(
                "No valid IP/CIDR targets for masscan. "
                "Hostnames were filtered out — masscan cannot resolve DNS. "
                "Use naabu, or target netblocks/IP assets."
            )
            result.duration_seconds = (datetime.utcnow() - start_time).total_seconds()
            return result
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as targets_file:
            # Masscan natively supports CIDR notation in input files
            targets_file.write("\n".join(valid_targets))
            targets_path = targets_file.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as output_file:
            output_path = output_file.name
        
        try:
            cmd = [
                self.masscan_path,
                "-iL", targets_path,
                "-p", ports,
                "--rate", str(rate),
                "--wait", str(timeout),
                "-oJ", output_path,
            ]
            
            # Add banner grabbing for service detection
            if banner_grab:
                cmd.append("--banner")
            
            logger.info(
                f"Running masscan on {len(valid_targets)} IP/CIDR targets "
                f"(from {len(targets)} inputs) with ports={ports}"
            )
            logger.debug(f"Masscan command: {' '.join(cmd)}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Log any errors from masscan
            if process.returncode != 0:
                error_msg = stderr.decode() if stderr else f"Exit code: {process.returncode}"
                logger.error(f"Masscan failed: {error_msg}")
                result.errors.append(error_msg)
                
                # Check for common issues
                if "permission denied" in error_msg.lower() or "operation not permitted" in error_msg.lower():
                    result.errors.append("Masscan requires root privileges. Run container with --privileged or use naabu instead.")
                elif "libpcap" in error_msg.lower():
                    result.errors.append("Masscan requires libpcap. Install with: apt-get install libpcap-dev")
            
            if stderr and process.returncode == 0:
                logger.info(f"Masscan output: {stderr.decode()}")
            
            # Parse JSON output
            if os.path.exists(output_path):
                file_size = os.path.getsize(output_path)
                logger.info(f"Masscan output file size: {file_size} bytes")
                
                with open(output_path, 'r') as f:
                    content = f.read().strip()
                    
                    if not content:
                        logger.warning("Masscan output file is empty")
                    elif content == "[]":
                        logger.info("Masscan found no open ports (empty array)")
                    else:
                        logger.debug(f"Masscan output (first 500 chars): {content[:500]}")
                        
                        # Clean up masscan JSON quirks:
                        # 1. Remove { "finished": ... } lines
                        # 2. Fix trailing commas before ]
                        lines = content.split("\n")
                        clean_lines = []
                        for line in lines:
                            line = line.strip()
                            # Skip finished object and empty lines
                            if not line or '"finished"' in line:
                                continue
                            clean_lines.append(line)
                        
                        # Rejoin and fix trailing commas
                        clean_content = "\n".join(clean_lines)
                        # Remove trailing comma before closing bracket
                        clean_content = re.sub(r',\s*\]', ']', clean_content)
                        # Remove trailing comma at end of array elements
                        clean_content = re.sub(r'},\s*\n\s*\]', '}\n]', clean_content)
                        
                        try:
                            # Try parsing as JSON array
                            data = json.loads(clean_content)
                            logger.info(f"Parsed masscan JSON array with {len(data)} entries")
                            
                            for entry in data:
                                if not isinstance(entry, dict):
                                    continue
                                ip = entry.get("ip", "")
                                ports_data = entry.get("ports", [])
                                for port_info in ports_data:
                                    result.ports_found.append(PortResult(
                                        host=ip,
                                        ip=ip,
                                        port=port_info.get("port", 0),
                                        protocol=port_info.get("proto", "tcp"),
                                        state=port_info.get("status", "open"),
                                        reason=port_info.get("reason", ""),
                                        banner=port_info.get("service", {}).get("banner", "") if isinstance(port_info.get("service"), dict) else "",
                                        scanner="masscan"
                                    ))
                                    
                        except json.JSONDecodeError as e:
                            logger.warning(f"JSON parse failed: {e}, trying line-by-line parsing")
                            # Fallback: line-by-line parsing for malformed JSON
                            for line in content.split("\n"):
                                line = line.strip().rstrip(",")
                                if line and line.startswith("{") and '"ip"' in line:
                                    try:
                                        entry = json.loads(line)
                                        ip = entry.get("ip", "")
                                        for port_info in entry.get("ports", []):
                                            result.ports_found.append(PortResult(
                                                host=ip,
                                                ip=ip,
                                                port=port_info.get("port", 0),
                                                protocol=port_info.get("proto", "tcp"),
                                                state="open",
                                                scanner="masscan"
                                            ))
                                            logger.debug(f"Parsed port from line: {ip}:{port_info.get('port')}")
                                    except json.JSONDecodeError:
                                        pass
            else:
                logger.error(f"Masscan output file not found: {output_path}")
            
            result.success = True
            result.targets_scanned = len(valid_targets)
            result.hosts_scanned = valid_targets
            result.hosts_found = self._build_host_results(result.ports_found, valid_targets)
            
        except Exception as e:
            logger.error(f"Masscan scan failed: {e}")
            result.errors.append(str(e))
        
        finally:
            for path in [targets_path, output_path]:
                if os.path.exists(path):
                    os.unlink(path)
            
            result.duration_seconds = (datetime.utcnow() - start_time).total_seconds()
        
        logger.info(f"Masscan found {len(result.ports_found)} open ports across {len(result.hosts_found)} hosts")
        return result
    
    async def _scan_masscan_per_port(
        self,
        targets: List[str],
        ports: str,
        rate: int,
        timeout: int,
        banner_grab: bool
    ) -> ScanResult:
        """
        Scan one port at a time across all targets (ASM Recon approach).
        
        This is slower but less likely to trigger cloud provider blocks.
        Based on ASM Recon get_masscan script approach.
        """
        result = ScanResult(success=False, scanner=ScannerType.MASSCAN)
        start_time = datetime.utcnow()
        
        # Parse port range
        port_list = self._parse_port_spec(ports)
        
        # Same IP-only filter as the main masscan path
        valid_targets, invalid_targets = self._validate_targets(targets, ip_only=True)
        for notice in invalid_targets:
            if str(notice).startswith("Skipped "):
                result.errors.append(notice)
        true_invalid = [t for t in invalid_targets if not str(t).startswith("Skipped ")]
        if true_invalid:
            result.errors.append(f"Skipped {len(true_invalid)} invalid targets")
        
        if not valid_targets:
            result.errors.append(
                "No valid IP/CIDR targets for masscan. "
                "Hostnames were filtered out — masscan cannot resolve DNS."
            )
            result.duration_seconds = (datetime.utcnow() - start_time).total_seconds()
            return result
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as targets_file:
            targets_file.write("\n".join(valid_targets))
            targets_path = targets_file.name
        
        try:
            logger.info(
                f"Running masscan per-port mode on {len(valid_targets)} IP/CIDR targets, "
                f"{len(port_list)} ports"
            )
            
            for port in port_list:
                with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as output_file:
                    output_path = output_file.name
                
                try:
                    cmd = [
                        self.masscan_path,
                        "-iL", targets_path,
                        "-p", str(port),
                        "--rate", str(rate),
                        "--wait", str(min(timeout, 5)),  # Shorter wait per port
                        "-oJ", output_path,
                    ]
                    
                    if banner_grab:
                        cmd.append("--banner")
                    
                    process = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    
                    await process.communicate()
                    
                    # Parse output for this port
                    if os.path.exists(output_path):
                        with open(output_path, 'r') as f:
                            content = f.read().strip()
                            if content:
                                self._parse_masscan_json(content, result.ports_found)
                    
                finally:
                    if os.path.exists(output_path):
                        os.unlink(output_path)
            
            result.success = True
            result.targets_scanned = len(valid_targets)
            result.hosts_scanned = valid_targets
            result.hosts_found = self._build_host_results(result.ports_found, valid_targets)
            
        except Exception as e:
            logger.error(f"Masscan per-port scan failed: {e}")
            result.errors.append(str(e))
        
        finally:
            if os.path.exists(targets_path):
                os.unlink(targets_path)
            result.duration_seconds = (datetime.utcnow() - start_time).total_seconds()
        
        logger.info(f"Masscan per-port found {len(result.ports_found)} open ports across {len(result.hosts_found)} hosts")
        return result
    
    def _parse_port_spec(self, ports: str) -> List[int]:
        """Parse port specification into list of ports."""
        port_list = []
        
        for part in ports.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                port_list.extend(range(int(start), int(end) + 1))
            else:
                port_list.append(int(part))
        
        return port_list
    
    def _count_ports(self, ports: str) -> int:
        """Count total number of ports in a port specification."""
        if not ports:
            return 0
        
        count = 0
        for part in ports.split(","):
            part = part.strip()
            if "-" in part:
                try:
                    start, end = part.split("-", 1)
                    count += int(end) - int(start) + 1
                except ValueError:
                    count += 1
            else:
                count += 1
        return count
    
    def _estimate_hosts(self, targets: List[str]) -> int:
        """Estimate total number of hosts from targets (including CIDR expansion).
        
        Note: IPv6 targets are skipped as they are not supported for port scanning.
        """
        import ipaddress
        
        total = 0
        for target in targets:
            target = target.strip()
            if "/" in target:
                try:
                    network = ipaddress.ip_network(target, strict=False)
                    # Skip IPv6 - not supported for port scanning and has huge address space
                    if network.version == 6:
                        continue
                    total += network.num_addresses
                except ValueError:
                    # If it looks like IPv6, skip it
                    if ':' in target:
                        continue
                    total += 1
            else:
                # Skip IPv6 addresses
                if ':' in target:
                    continue
                total += 1
        return total
    
    def filter_ipv4_only(self, targets: List[str]) -> tuple[List[str], int]:
        """Filter targets to IPv4 only, returning (ipv4_targets, ipv6_skipped_count)."""
        import ipaddress
        
        ipv4_targets = []
        ipv6_skipped = 0
        
        for target in targets:
            target = target.strip()
            if not target:
                continue
            
            # Quick check for IPv6 indicators
            if ':' in target:
                ipv6_skipped += 1
                continue
            
            # For CIDRs, validate they're IPv4
            if '/' in target:
                try:
                    network = ipaddress.ip_network(target, strict=False)
                    if network.version == 6:
                        ipv6_skipped += 1
                        continue
                except ValueError:
                    pass  # Let it through, scanner will handle invalid
            
            ipv4_targets.append(target)
        
        return ipv4_targets, ipv6_skipped
    
    def _parse_masscan_json(self, content: str, results: List[PortResult]):
        """Parse masscan JSON output and append to results list."""
        try:
            data = json.loads(content)
            for entry in data:
                ip = entry.get("ip", "")
                for port_info in entry.get("ports", []):
                    # Extract banner/service info if available
                    service_info = port_info.get("service", {})
                    banner = service_info.get("banner", "")
                    
                    results.append(PortResult(
                        host=ip,
                        ip=ip,
                        port=port_info.get("port", 0),
                        protocol=port_info.get("proto", "tcp"),
                        state=port_info.get("status", "open"),
                        reason=port_info.get("reason", ""),
                        banner=banner,
                        scanner="masscan"
                    ))
        except json.JSONDecodeError:
            # Try line-by-line parsing for partial JSON
            for line in content.split("\n"):
                line = line.strip().rstrip(",")
                if line and line.startswith("{"):
                    try:
                        entry = json.loads(line)
                        ip = entry.get("ip", "")
                        for port_info in entry.get("ports", []):
                            results.append(PortResult(
                                host=ip,
                                ip=ip,
                                port=port_info.get("port", 0),
                                protocol=port_info.get("proto", "tcp"),
                                state="open",
                                scanner="masscan"
                            ))
                    except json.JSONDecodeError:
                        pass
    
    # ==================== NMAP ====================
    
    async def scan_with_nmap(
        self,
        targets: List[str],
        ports: Optional[str] = None,
        scan_type: str = "-sT",  # TCP connect scan (doesn't require root)
        service_detection: bool = True,
        os_detection: bool = False,
        timing: int = 4,  # T4 aggressive timing
        scripts: Optional[List[str]] = None
    ) -> ScanResult:
        """
        Run port scan using Nmap.
        
        Nmap is the most feature-rich scanner with service detection,
        OS fingerprinting, and scripting capabilities.
        
        NOTE: Uses -sT (connect scan) by default which doesn't require root.
        SYN scan (-sS) is faster but requires root privileges.
        
        Args:
            targets: List of targets
            ports: Port specification (None = top 1000, "-" = all ports)
            scan_type: Nmap scan type (-sS, -sT, -sU, etc.)
            service_detection: Enable service/version detection (-sV)
            os_detection: Enable OS detection (-O)
            timing: Timing template (0-5, higher = faster)
            scripts: NSE scripts to run
        """
        result = ScanResult(success=False, scanner=ScannerType.NMAP)
        start_time = datetime.utcnow()
        
        # Handle special port notation
        if ports == "-" or ports == "all":
            ports = "1-65535"
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as targets_file:
            targets_file.write("\n".join(targets))
            targets_path = targets_file.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as output_file:
            output_path = output_file.name
        
        try:
            cmd = [
                self.nmap_path,
                "-iL", targets_path,
                "-oX", output_path,
                scan_type,
                f"-T{timing}",
                "-Pn",  # Skip host discovery, scan all hosts
            ]
            
            if ports:
                cmd.extend(["-p", ports])
            
            if service_detection:
                cmd.append("-sV")
            
            if os_detection:
                cmd.append("-O")
            
            if scripts:
                available_scripts, missing_scripts = self._filter_available_nse_scripts(scripts)
                if missing_scripts:
                    logger.warning(
                        "Skipping NSE scripts not installed on this host: %s",
                        missing_scripts,
                    )
                    result.errors.append(
                        f"Skipped missing NSE scripts: {', '.join(missing_scripts)}"
                    )
                if available_scripts:
                    cmd.extend(["--script", ",".join(available_scripts)])
                    logger.info("Using available NSE scripts: %s", available_scripts)
                else:
                    logger.warning(
                        "No requested NSE scripts are installed; continuing without --script"
                    )
            
            logger.info(f"Running nmap scan on {len(targets)} targets with ports={ports}")
            logger.debug(f"Nmap command: {' '.join(cmd)}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            stderr_text = stderr.decode() if stderr else ""
            
            # Log any errors from nmap
            if process.returncode != 0:
                error_msg = stderr_text or f"Exit code: {process.returncode}"
                logger.error(f"Nmap scan failed: {error_msg}")
                result.errors.append(error_msg)
                
                # Check for common issues
                if "requires root" in error_msg.lower() or "operation not permitted" in error_msg.lower():
                    result.errors.append("Nmap SYN scan requires root. Using -sT (connect scan) instead.")
            elif stderr_text:
                logger.info(f"Nmap stderr: {stderr_text}")
            
            # Parse XML output
            if os.path.exists(output_path):
                result.ports_found = self._parse_nmap_xml(output_path)
                logger.info(f"Parsed {len(result.ports_found)} ports from nmap XML output")
            else:
                logger.warning(f"Nmap output file not found: {output_path}")
                result.errors.append("Nmap did not produce output file")
            
            # Hard NSE/init failures leave no usable XML — treat as failed.
            nse_fatal = (
                process.returncode != 0
                and (
                    "failed to initialize the script engine" in stderr_text.lower()
                    or "did not match a category" in stderr_text.lower()
                    or "QUITTING" in stderr_text
                )
            )
            result.success = process.returncode == 0 or (
                not nse_fatal and bool(result.ports_found)
            )
            result.targets_scanned = len(targets)
            result.hosts_scanned = targets
            result.hosts_found = self._build_host_results(result.ports_found, targets)
            
        except Exception as e:
            logger.error(f"Nmap scan failed: {e}")
            result.errors.append(str(e))
        
        finally:
            for path in [targets_path, output_path]:
                if os.path.exists(path):
                    os.unlink(path)
            
            result.duration_seconds = (datetime.utcnow() - start_time).total_seconds()
        
        logger.info(f"Nmap found {len(result.ports_found)} open ports across {len(result.hosts_found)} hosts")
        return result
    
    @staticmethod
    def _extract_port_scripts(port_elem) -> Dict[str, str]:
        """Collect NSE ``<script id=.. output=..>`` results for a port element."""
        scripts: Dict[str, str] = {}
        for script_elem in port_elem.findall("script"):
            sid = script_elem.get("id")
            output = script_elem.get("output")
            if sid and output:
                scripts[sid] = output
        return scripts

    @staticmethod
    def _attach_ot_identity(port_result: "PortResult") -> None:
        """Parse and attach OT/ICS device identity from a port's NSE scripts."""
        try:
            from app.services.ot_device_identity import parse_ot_identity
            identity = parse_ot_identity(
                port=port_result.port,
                scripts=port_result.scripts,
                service_product=port_result.service_product,
                service_extra_info=port_result.service_extra_info,
                banner=port_result.banner,
            )
            if identity is not None:
                data = identity.to_dict()
                data["tags"] = identity.tags()
                port_result.ot_identity = data
        except Exception as e:  # never let identity parsing break a scan
            logger.debug("OT identity parse failed for port %s: %s", port_result.port, e)

    def _parse_nmap_xml(self, xml_path: str) -> List[PortResult]:
        """Parse Nmap XML output."""
        results = []
        
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            
            for host in root.findall(".//host"):
                # Get IP address
                addr_elem = host.find("address[@addrtype='ipv4']")
                if addr_elem is None:
                    addr_elem = host.find("address[@addrtype='ipv6']")
                if addr_elem is None:
                    continue
                
                ip = addr_elem.get("addr", "")
                
                # Get hostname if available
                hostname = ip
                hostnames = host.find("hostnames")
                if hostnames is not None:
                    hostname_elem = hostnames.find("hostname")
                    if hostname_elem is not None:
                        hostname = hostname_elem.get("name", ip)
                
                # Get ports
                ports = host.find("ports")
                if ports is None:
                    continue
                
                for port in ports.findall("port"):
                    port_id = int(port.get("portid", 0))
                    protocol = port.get("protocol", "tcp")
                    
                    # State
                    state_elem = port.find("state")
                    state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"
                    reason = state_elem.get("reason", "") if state_elem is not None else ""
                    
                    # Service info
                    service_elem = port.find("service")
                    service_name = None
                    service_product = None
                    service_version = None
                    service_extra = None
                    cpe = None
                    
                    if service_elem is not None:
                        service_name = service_elem.get("name")
                        service_product = service_elem.get("product")
                        service_version = service_elem.get("version")
                        service_extra = service_elem.get("extrainfo")
                        
                        # Get CPE
                        cpe_elem = service_elem.find("cpe")
                        if cpe_elem is not None:
                            cpe = cpe_elem.text

                    port_result = PortResult(
                        host=hostname,
                        ip=ip,
                        port=port_id,
                        protocol=protocol,
                        state=state,
                        service_name=service_name,
                        service_product=service_product,
                        service_version=service_version,
                        service_extra_info=service_extra,
                        cpe=cpe,
                        reason=reason,
                        scanner="nmap",
                        scripts=self._extract_port_scripts(port),
                    )
                    self._attach_ot_identity(port_result)
                    results.append(port_result)

        except ET.ParseError as e:
            logger.error(f"Failed to parse Nmap XML: {e}")

        return results

    # ==================== UNIFIED SCAN ====================
    
    async def scan(
        self,
        targets: List[str],
        scanner: ScannerType = ScannerType.NAABU,
        ports: Optional[str] = None,
        **kwargs
    ) -> ScanResult:
        """
        Run a port scan using the specified scanner.
        
        Args:
            targets: List of targets (IPs, domains, CIDRs like 205.175.240.0/24)
            scanner: Scanner to use (naabu, masscan, nmap)
            ports: Port specification (e.g., "80,443", "1-1000", "-" for all)
            **kwargs: Additional scanner-specific options:
                - For masscan: banner_grab=True, one_port_at_a_time=False
                - For naabu: top_ports=100, rate=1000, exclude_cdn=True
                - For nmap: service_detection=True, os_detection=False
        """
        if scanner == ScannerType.NAABU:
            return await self.scan_with_naabu(targets, ports=ports, **kwargs)
        elif scanner == ScannerType.MASSCAN:
            return await self.scan_with_masscan(targets, ports=ports or "1-65535", **kwargs)
        elif scanner == ScannerType.NMAP:
            return await self.scan_with_nmap(targets, ports=ports, **kwargs)
        else:
            raise ValueError(f"Unknown scanner: {scanner}")
    
    # ==================== IMPORT TO DATABASE ====================
    
    def import_results_to_assets(
        self,
        db: Session,
        scan_result: ScanResult,
        organization_id: int,
        create_assets: bool = True,
        create_all_hosts: bool = True  # Create assets even for hosts with no open ports
    ) -> dict:
        """
        Import scan results into the database, associating with assets.
        
        Args:
            db: Database session
            scan_result: Scan results to import
            organization_id: Organization ID
            create_assets: Create assets if they don't exist
            create_all_hosts: Create assets for ALL scanned hosts (even those with no open ports)
            
        Returns:
            Summary of import results including host details
        """
        summary = {
            "ports_imported": 0,
            "ports_updated": 0,
            "assets_created": 0,
            "hosts_processed": 0,
            "live_hosts": 0,
            "errors": [],
            "host_results": []  # Detailed results per host
        }
        
        # Group port results by host/IP
        by_host = {}
        for port_result in scan_result.ports_found:
            key = port_result.ip or port_result.host
            if key not in by_host:
                by_host[key] = []
            by_host[key].append(port_result)
        
        # Get all hosts to process (either from hosts_found or just ports)
        all_hosts_to_process = set()
        
        # Add hosts with ports
        for host in by_host.keys():
            all_hosts_to_process.add(host)
        
        # Add all scanned hosts if create_all_hosts is enabled
        if create_all_hosts and scan_result.hosts_scanned:
            for host in scan_result.hosts_scanned:
                all_hosts_to_process.add(host)
        
        # Pre-build an ipaddress network lookup for fast CIDR membership checks
        import ipaddress as _ipaddress
        
        # Process each host
        for host in all_hosts_to_process:
            summary["hosts_processed"] += 1
            ports = by_host.get(host, [])
            is_live = len(ports) > 0
            
            if is_live:
                summary["live_hosts"] += 1
            
            host_result = {
                "host": host,
                "ip": host,
                "is_live": is_live,
                "open_ports": [p.port for p in ports],
                "port_count": len(ports),
                "asset_id": None,
                "asset_created": False
            }
            
            # Find or create asset
            asset = db.query(Asset).filter(
                Asset.organization_id == organization_id,
                Asset.value == host
            ).first()
            
            if not asset and create_assets:
                # Skip CIDR ranges - they belong in netblocks table, not assets.
                # BUT if the CIDR asset already exists in the DB it will be found
                # above and updated below with aggregate stats.
                if self._is_cidr(host):
                    logger.debug(f"Skipping CIDR range {host} - belongs in netblocks, not assets")
                    summary["hosts_skipped"] = summary.get("hosts_skipped", 0) + 1
                    continue
                
                # Determine asset type
                asset_type = AssetType.IP_ADDRESS
                if not self._is_ip(host):
                    asset_type = AssetType.SUBDOMAIN  # More likely a subdomain than root domain
                
                # Build discovery chain for traceability
                discovery_chain = [{
                    "step": 1,
                    "source": scan_result.scanner.value if hasattr(scan_result, 'scanner') else "port_scan",
                    "method": "port_scan_discovery",
                    "ports_found": [p.port for p in ports] if ports else [],
                    "timestamp": datetime.utcnow().isoformat()
                }]
                
                # Build association reason
                if asset_type == AssetType.IP_ADDRESS:
                    if ports:
                        services = [p.service_name for p in ports if p.service_name]
                        association_reason = f"IP discovered via port scan with {len(ports)} open port(s)"
                        if services:
                            association_reason += f": {', '.join(set(services))}"
                    else:
                        association_reason = "IP discovered during port scan (no open ports found)"
                else:
                    association_reason = f"Host discovered via port scan"
                
                asset = Asset(
                    organization_id=organization_id,
                    name=host,
                    value=host,
                    asset_type=asset_type,
                    discovery_source=scan_result.scanner.value if hasattr(scan_result, 'scanner') else "port_scan",
                    discovery_chain=discovery_chain,
                    association_reason=association_reason,
                    is_live=is_live,
                    in_scope=True,  # Mark as in-scope since it was scanned from our netblocks
                    # For IP assets, populate the ip_address field with the value
                    ip_address=host if asset_type == AssetType.IP_ADDRESS else None,
                    ip_addresses=[host] if asset_type == AssetType.IP_ADDRESS else []
                )
                db.add(asset)
                db.flush()
                summary["assets_created"] += 1
                host_result["asset_created"] = True
            elif asset:
                # Update existing asset's live status
                asset.is_live = is_live or asset.is_live  # Don't mark as not live if it was previously live
                asset.last_seen = datetime.utcnow()
            
            if asset:
                host_result["asset_id"] = asset.id
                
                # For CIDR block assets, compute aggregate live-IP stats from this scan
                if self._is_cidr(host):
                    try:
                        network = _ipaddress.ip_network(host, strict=False)
                        live_ips_in_cidr: set[str] = set()
                        for pr in scan_result.ports_found:
                            try:
                                ip_obj = _ipaddress.ip_address(pr.ip or pr.host)
                                if ip_obj in network:
                                    live_ips_in_cidr.add(str(ip_obj))
                            except ValueError:
                                pass
                        usable = network.num_addresses - 2 if network.prefixlen < 31 else network.num_addresses
                        host_result["live_hosts_in_cidr"] = len(live_ips_in_cidr)
                        host_result["usable_hosts"] = usable
                        host_result["is_live"] = len(live_ips_in_cidr) > 0
                        host_result["is_cidr"] = True
                        # Persist aggregate data in asset metadata
                        meta = dict(asset.metadata_ or {})
                        meta["last_port_scan"] = datetime.utcnow().isoformat()
                        meta["live_hosts_found"] = len(live_ips_in_cidr)
                        meta["live_ips"] = sorted(live_ips_in_cidr)
                        meta["usable_hosts"] = usable
                        asset.metadata_ = meta
                        asset.last_seen = datetime.utcnow()
                        if len(live_ips_in_cidr) > 0:
                            asset.is_live = True
                    except ValueError:
                        pass
                    summary["host_results"].append(host_result)
                    continue  # Skip port import for CIDR assets
                
                # Track IPs discovered for this asset (for domain assets)
                discovered_ips = set()
                
                # Import ports for this host
                for port_result in ports:
                    try:
                        # Track the IP where port was found
                        scanned_ip = port_result.ip if port_result.ip != port_result.host else None
                        if scanned_ip:
                            discovered_ips.add(scanned_ip)
                        
                        # Check for existing port
                        existing = db.query(PortService).filter(
                            PortService.asset_id == asset.id,
                            PortService.port == port_result.port,
                            PortService.protocol == Protocol(port_result.protocol.lower())
                        ).first()
                        
                        if existing:
                            # Update existing
                            existing.last_seen = datetime.utcnow()
                            # Use actual state from scan result
                            state_map = {
                                "open": PortState.OPEN,
                                "closed": PortState.CLOSED,
                                "filtered": PortState.FILTERED,
                                "open|filtered": PortState.OPEN_FILTERED,
                                "closed|filtered": PortState.CLOSED_FILTERED,
                            }
                            existing.state = state_map.get(port_result.state.lower(), PortState.OPEN)
                            if scanned_ip:
                                existing.scanned_ip = scanned_ip
                            if port_result.service_name:
                                existing.service_name = port_result.service_name
                            if port_result.service_product:
                                existing.service_product = port_result.service_product
                            if port_result.service_version:
                                existing.service_version = port_result.service_version
                            if port_result.banner:
                                existing.banner = port_result.banner
                            if port_result.cpe:
                                existing.cpe = port_result.cpe
                            # Enrich OT/ICS device identity on rescan.
                            if port_result.ot_identity:
                                ot_fields = port_result.to_port_service_dict(asset.id)
                                existing.service_product = ot_fields["service_product"]
                                existing.service_version = (
                                    ot_fields["service_version"] or existing.service_version
                                )
                                existing.service_extra_info = (
                                    ot_fields["service_extra_info"] or existing.service_extra_info
                                )
                                meta = dict(existing.metadata_ or {})
                                meta["ot_device"] = port_result.ot_identity
                                existing.metadata_ = meta
                                merged_tags = list(existing.tags or [])
                                for tag in ot_fields.get("tags", []):
                                    if tag not in merged_tags:
                                        merged_tags.append(tag)
                                existing.tags = merged_tags
                            summary["ports_updated"] += 1
                        else:
                            # Create new
                            port_data = port_result.to_port_service_dict(asset.id)
                            # Add scanned_ip to port data
                            port_data["scanned_ip"] = scanned_ip
                            port_service = PortService(**port_data)
                            db.add(port_service)
                            summary["ports_imported"] += 1
                            
                    except Exception as e:
                        summary["errors"].append(f"Error importing {host}:{port_result.port}: {e}")
                
                # Update asset's IP addresses if this is a domain asset and we have IPs
                if discovered_ips and asset.asset_type in [AssetType.DOMAIN, AssetType.SUBDOMAIN]:
                    try:
                        asset.update_ip_addresses(list(discovered_ips))
                        logger.info(f"Updated IP addresses for {asset.value}: {discovered_ips}")
                    except Exception as e:
                        logger.warning(f"Failed to update IP addresses for {asset.value}: {e}")
                
                # Run device inference to update system_type based on discovered services
                try:
                    from app.services.device_inference_service import get_device_inference_service
                    db.flush()  # Ensure ports are persisted
                    db.refresh(asset)  # Reload asset with new ports
                    inference_service = get_device_inference_service()
                    inference = inference_service.update_asset_device_info(db, asset)
                    if inference.system_type:
                        logger.info(f"Inferred device type for {asset.value}: {inference.system_type}")
                except Exception as e:
                    logger.warning(f"Device inference failed for {asset.value}: {e}")
            else:
                summary["errors"].append(f"No asset found/created for {host}")
            
            summary["host_results"].append(host_result)
        
        db.commit()
        return summary
    
    def _is_ip(self, value: str) -> bool:
        """Check if value is an IP address (not CIDR)."""
        import re
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
        return bool(re.match(ipv4_pattern, value) or re.match(ipv6_pattern, value))
    
    def _is_cidr(self, value: str) -> bool:
        """Check if value is a CIDR range (e.g., 192.168.1.0/24)."""
        import re
        cidr_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
        return bool(re.match(cidr_pattern, value))
    
    def _build_host_results(self, ports_found: List[PortResult], all_targets: List[str]) -> List[HostScanResult]:
        """Build host results from port findings and target list."""
        # Group ports by host
        host_ports = {}
        for port in ports_found:
            key = port.ip or port.host
            if key not in host_ports:
                host_ports[key] = []
            host_ports[key].append(port.port)
        
        results = []
        seen_hosts = set()
        
        # Add hosts with open ports (live)
        for host, ports in host_ports.items():
            results.append(HostScanResult(
                host=host,
                ip=host,
                is_live=True,
                open_ports=sorted(set(ports))
            ))
            seen_hosts.add(host)
        
        # Add remaining targets that were scanned but had no open ports
        for target in all_targets:
            if target not in seen_hosts:
                results.append(HostScanResult(
                    host=target,
                    ip=target,
                    is_live=False,  # No response / no open ports
                    open_ports=[]
                ))
        
        return results
    
    # ==================== PARSE EXISTING OUTPUT ====================
    
    def parse_naabu_output(self, output: str) -> List[PortResult]:
        """Parse Naabu JSON output from string."""
        results = []
        for line in output.strip().split("\n"):
            line = line.strip()
            if line:
                try:
                    data = json.loads(line)
                    results.append(PortResult(
                        host=data.get("host", ""),
                        ip=data.get("ip", data.get("host", "")),
                        port=data.get("port", 0),
                        protocol=data.get("protocol", "tcp"),
                        state="open",
                        scanner="naabu"
                    ))
                except json.JSONDecodeError:
                    pass
        return results
    
    def parse_masscan_output(self, output: str) -> List[PortResult]:
        """
        Parse Masscan output from string.
        
        Supports both JSON format (-oJ) and text format (default).
        
        JSON format example:
            [{"ip": "1.2.3.4", "ports": [{"port": 80, "proto": "tcp"}]}]
        
        Text format example (default masscan output):
            #masscan
            open tcp 443 1.2.3.4 1234567890
            open tcp 80 1.2.3.5 1234567891
        """
        results = []
        output = output.strip()
        
        if not output:
            return results
        
        # Try JSON format first
        try:
            data = json.loads(output)
            for entry in data:
                ip = entry.get("ip", "")
                for port_info in entry.get("ports", []):
                    results.append(PortResult(
                        host=ip,
                        ip=ip,
                        port=port_info.get("port", 0),
                        protocol=port_info.get("proto", "tcp"),
                        state=port_info.get("status", "open"),
                        scanner="masscan"
                    ))
            return results
        except json.JSONDecodeError:
            pass
        
        # Try text format (default masscan output)
        # Format: open <proto> <port> <ip> <timestamp>
        # or: <state> <proto> <port> <ip> <timestamp>
        for line in output.split("\n"):
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue
            
            parts = line.split()
            if len(parts) >= 4:
                # Expected format: open tcp 80 1.2.3.4 [timestamp]
                state = parts[0].lower()
                proto = parts[1].lower() if len(parts) > 1 else "tcp"
                
                try:
                    port = int(parts[2])
                    ip = parts[3]
                    
                    # Validate IP looks like an IP address
                    if not ip or not (ip[0].isdigit() or ip.startswith('[') or ':' in ip):
                        continue
                    
                    results.append(PortResult(
                        host=ip,
                        ip=ip,
                        port=port,
                        protocol=proto,
                        state=state if state in ("open", "closed", "filtered") else "open",
                        scanner="masscan"
                    ))
                except (ValueError, IndexError):
                    continue
        
        logger.info(f"Parsed {len(results)} port results from masscan text format")
        return results
    
    def parse_nmap_output(self, xml_content: str) -> List[PortResult]:
        """Parse Nmap XML output from string."""
        results = []
        try:
            root = ET.fromstring(xml_content)
            
            for host in root.findall(".//host"):
                addr_elem = host.find("address[@addrtype='ipv4']")
                if addr_elem is None:
                    addr_elem = host.find("address[@addrtype='ipv6']")
                if addr_elem is None:
                    continue
                
                ip = addr_elem.get("addr", "")
                hostname = ip
                
                hostnames = host.find("hostnames")
                if hostnames is not None:
                    hostname_elem = hostnames.find("hostname")
                    if hostname_elem is not None:
                        hostname = hostname_elem.get("name", ip)
                
                ports = host.find("ports")
                if ports is None:
                    continue
                
                for port in ports.findall("port"):
                    state_elem = port.find("state")
                    service_elem = port.find("service")

                    port_result = PortResult(
                        host=hostname,
                        ip=ip,
                        port=int(port.get("portid", 0)),
                        protocol=port.get("protocol", "tcp"),
                        state=state_elem.get("state", "unknown") if state_elem is not None else "unknown",
                        service_name=service_elem.get("name") if service_elem is not None else None,
                        service_product=service_elem.get("product") if service_elem is not None else None,
                        service_version=service_elem.get("version") if service_elem is not None else None,
                        service_extra_info=service_elem.get("extrainfo") if service_elem is not None else None,
                        reason=state_elem.get("reason", "") if state_elem is not None else "",
                        scanner="nmap",
                        scripts=self._extract_port_scripts(port),
                    )
                    self._attach_ot_identity(port_result)
                    results.append(port_result)
        except ET.ParseError:
            pass
        return results
    
    # ==================== SYNC WRAPPERS ====================
    
    def scan_sync(self, targets: List[str], scanner: ScannerType = ScannerType.NAABU, **kwargs) -> ScanResult:
        """Synchronous wrapper for scan."""
        return asyncio.run(self.scan(targets, scanner, **kwargs))

















