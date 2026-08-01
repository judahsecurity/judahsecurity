"""
Katana Service for deep web crawling and JS discovery.

Katana (https://github.com/projectdiscovery/katana) is a fast crawler
for discovering endpoints, JS files, and parameters from web applications.

Use case: crawl with -d 5 -jc -fx -ef to strip noise (fonts, images, css),
collect all JS file URLs, then assess them with AI to identify sensitive data.

CLI alignment (see https://github.com/projectdiscovery/katana):
  katana -list live_sites.txt -d 5 -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif -o endpoints.txt
  # or: katana -u https://a.com -u https://b.com ... (same flags)
  # -jc = JS crawl; -fx = form extraction in JSONL; -ef = drop noisy extensions from output
"""

import asyncio
import logging
import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Set, Dict, Any, Union
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)


# Matches ProjectDiscovery README example (noise extensions filtered from *output*)
KATANA_EF_PIPELINE = [
    "woff", "css", "png", "svg", "jpg", "woff2", "jpeg", "gif",
]

# Broader filter (fonts, media, docs) — use preset="extended" in scan config
EXCLUDED_EXTENSIONS_JS_PRESET = [
    "woff", "woff2", "ttf", "eot", "otf",
    "css", "scss", "less",
    "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "bmp",
    "mp4", "mp3", "avi", "mov", "wmv", "flv", "webm",
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
]


def _extension_filter_csv(
    preset: str = "pipeline",
    custom: Optional[Union[str, List[str]]] = None,
) -> str:
    if custom:
        if isinstance(custom, str):
            return custom.strip()
        if isinstance(custom, (list, tuple)):
            return ",".join(str(x).strip() for x in custom if str(x).strip())
    if (preset or "pipeline").lower() == "extended":
        return ",".join(EXCLUDED_EXTENSIONS_JS_PRESET)
    return ",".join(KATANA_EF_PIPELINE)

@dataclass
class KatanaResult:
    """Result from Katana crawl."""
    target: str
    success: bool
    urls: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    forms: List[str] = field(default_factory=list)
    error: Optional[str] = None
    elapsed_time: float = 0.0
    
    # Breakdown by type
    api_endpoints: List[str] = field(default_factory=list)
    static_files: List[str] = field(default_factory=list)


# File extensions to exclude from crawling
EXCLUDED_EXTENSIONS = [
    "woff", "woff2", "ttf", "eot", "otf",  # Fonts
    "css", "scss", "less",                   # Styles
    "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "bmp",  # Images
    "mp4", "mp3", "avi", "mov", "wmv", "flv", "webm",  # Media
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",  # Documents
]

# Patterns for identifying interesting endpoints
API_PATTERNS = [
    r'/api/', r'/v\d+/', r'/graphql', r'/rest/',
    r'/json', r'/xml', r'/rpc', r'/soap',
]

# Patterns for potentially sensitive endpoints
SENSITIVE_PATTERNS = [
    r'/admin', r'/login', r'/auth', r'/oauth',
    r'/config', r'/settings', r'/debug', r'/test',
    r'/backup', r'/dump', r'/export', r'/import',
    r'/upload', r'/download', r'/file',
    r'\.env', r'\.git', r'\.svn',
    r'/phpinfo', r'/wp-admin', r'/wp-content',
]


class KatanaService:
    """
    Service for deep web crawling using Katana.
    
    Discovers:
    - All reachable URLs
    - JavaScript files (for secret scanning)
    - API endpoints
    - Form actions
    - URL parameters
    """
    
    def __init__(self):
        """Initialize the Katana service."""
        self.katana_path = shutil.which('katana')
        
    def is_available(self) -> bool:
        """Check if Katana is installed."""
        return self.katana_path is not None
    
    async def crawl(
        self,
        target: str,
        depth: int = 5,
        js_crawl: bool = True,
        form_extraction: bool = True,
        known_files: bool = False,
        extension_filter_preset: str = "pipeline",
        extension_filter_custom: Optional[Union[str, List[str]]] = None,
        timeout: int = 600,
        rate_limit: int = 150,
        concurrency: int = 10,
        headless: bool = False,
        user_agent: Optional[str] = None,
    ) -> KatanaResult:
        """
        Crawl a target URL/domain with Katana.
        
        Args:
            target: URL or domain to crawl
            depth: Crawl depth (default 5)
            js_crawl: Parse JavaScript for endpoints (-jc)
            form_extraction: Extract forms into JSONL (-fx)
            known_files: If True, add -kf (robots/sitemap; Katana recommends depth>=3)
            extension_filter_preset: "pipeline" (README example ef list) or "extended" (more file types filtered)
            extension_filter_custom: Optional explicit extension list (overrides preset)
            timeout: Total timeout in seconds
            rate_limit: Requests per second
            concurrency: Concurrent requests
            headless: Use headless browser for JS rendering
            
        Returns:
            KatanaResult with discovered URLs, endpoints, and parameters
        """
        result = KatanaResult(target=target, success=False)
        start_time = datetime.utcnow()
        
        if not self.is_available():
            result.error = "Katana not installed. Install: go install github.com/projectdiscovery/katana/cmd/katana@latest"
            return result
        
        # Ensure target has protocol
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        try:
            # Build Katana command
            # Per-request timeout in seconds (Katana expects seconds; 30–120s is reasonable)
            per_request_timeout = min(max(30, timeout // 6), 120)
            cmd = [
                self.katana_path,
                '-u', target,
                '-d', str(depth),
                '-silent',
                '-nc',  # No color
                '-rl', str(rate_limit),
                '-c', str(concurrency),
                '-timeout', str(per_request_timeout),
                '-ef', _extension_filter_csv(extension_filter_preset, extension_filter_custom),
            ]
            
            # JavaScript crawling (-jc); optional -kf for robots/sitemap
            if js_crawl:
                cmd.append('-jc')
                if known_files:
                    cmd.extend(['-kf', 'robotstxt,sitemapxml'])
            
            # Form extraction (-fx → form fields in JSONL when using -json/-jsonl)
            if form_extraction:
                cmd.append('-fx')
            
            # Headless mode for JS-heavy or bot-protected sites (Cloudflare, etc.)
            if headless:
                cmd.append('-hl')
            # Custom User-Agent to reduce bot blocking
            if user_agent:
                cmd.extend(['-H', f'User-Agent: {user_agent}'])
            
            # Log exact command for debugging (same as manual: katana -u <url> -d 5 -jc -fx ...)
            logger.info(
                f"Katana command: {' '.join(cmd)} (timeout={timeout}s)"
            )
            
            # Run Katana
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                result.error = f"Katana timed out after {timeout}s"
                result.elapsed_time = (datetime.utcnow() - start_time).total_seconds()
                return result
            
            if stderr:
                stderr_text = stderr.decode().strip()
                if 'error' in stderr_text.lower():
                    logger.warning(f"Katana stderr for {target}: {stderr_text[:200]}")
            
            # Parse output
            all_urls: Set[str] = set()
            all_endpoints: Set[str] = set()
            all_params: Set[str] = set()
            all_js: Set[str] = set()
            all_forms: Set[str] = set()
            all_api: Set[str] = set()
            
            for line in stdout.decode().strip().split('\n'):
                url = line.strip()
                if not url or not url.startswith('http'):
                    continue
                
                all_urls.add(url)
                
                # Parse the URL
                try:
                    parsed = urlparse(url)
                    path = parsed.path.rstrip('/')
                    
                    # Extract endpoint (path without query)
                    if path and path != '/':
                        all_endpoints.add(path)
                    
                    # Check for JS files — catch modern bundler paths:
                    #   .js / .mjs / .cjs / .jsx / .ts / .tsx extensions
                    #   /js/, /scripts/, /_next/static/, /static/js/, /assets/ dirs
                    _JS_EXTS = ('.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx')
                    _JS_PATHS = ('/js/', '/scripts/', '/_next/static/', '/static/js/', '/assets/', '/bundles/', '/dist/')
                    if path.endswith(_JS_EXTS) or any(p in path for p in _JS_PATHS):
                        all_js.add(url)
                    
                    # Extract parameters
                    if parsed.query:
                        params = parse_qs(parsed.query)
                        for param_name in params.keys():
                            all_params.add(param_name)
                    
                    # Identify API endpoints
                    url_lower = url.lower()
                    for pattern in API_PATTERNS:
                        if re.search(pattern, url_lower):
                            all_api.add(url)
                            break
                    
                    # Check for form actions
                    if 'action=' in url_lower or 'submit' in url_lower:
                        all_forms.add(url)
                        
                except Exception:
                    continue
            
            result.urls = sorted(list(all_urls))
            result.endpoints = sorted(list(all_endpoints))
            result.parameters = sorted(list(all_params))
            result.js_files = sorted(list(all_js))
            result.forms = sorted(list(all_forms))
            result.api_endpoints = sorted(list(all_api))
            result.success = len(all_urls) > 0
            if not result.success and not result.error:
                result.error = (
                    "No URLs discovered (site may block automated crawlers, require auth, or return no links). "
                    "Try re-running the scan with headless crawl enabled (scan config: headless=true) or a browser-like User-Agent for bot-protected sites."
                )
            
            logger.info(
                f"Katana crawl of {target}: {len(result.urls)} URLs, "
                f"{len(result.endpoints)} endpoints, {len(result.parameters)} params, "
                f"{len(result.js_files)} JS files"
            )
            
        except Exception as e:
            logger.error(f"Katana error for {target}: {e}")
            result.error = str(e)
        
        result.elapsed_time = (datetime.utcnow() - start_time).total_seconds()
        return result
    
    async def crawl_multiple(
        self,
        targets: List[str],
        max_concurrent: int = 3,
        **kwargs
    ) -> List[KatanaResult]:
        """
        Crawl multiple targets concurrently.
        
        Args:
            targets: List of URLs/domains to crawl
            max_concurrent: Maximum concurrent crawls
            **kwargs: Additional arguments for crawl()
            
        Returns:
            List of KatanaResult objects
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def crawl_with_limit(target: str) -> KatanaResult:
            async with semaphore:
                return await self.crawl(target, **kwargs)
        
        tasks = [crawl_with_limit(t) for t in targets]
        return await asyncio.gather(*tasks)
    
    async def crawl_from_file(
        self,
        file_path: str,
        **kwargs
    ) -> List[KatanaResult]:
        """
        Crawl targets from a file (one per line).
        
        Args:
            file_path: Path to file with targets
            **kwargs: Additional arguments for crawl_multiple()
            
        Returns:
            List of KatanaResult objects
        """
        with open(file_path, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
        
        return await self.crawl_multiple(targets, **kwargs)

    async def crawl_batch_stdin(
        self,
        targets: List[str],
        depth: int = 5,
        js_crawl: bool = True,
        form_extraction: bool = True,
        known_files: bool = False,
        extension_filter_preset: str = "pipeline",
        extension_filter_custom: Optional[Union[str, List[str]]] = None,
        timeout: int = 600,
        rate_limit: int = 150,
        concurrency: int = 10,
        headless: bool = False,
        user_agent: Optional[str] = None,
    ) -> KatanaResult:
        """
        Run Katana once with all seed URLs in a temp list file (-list), matching:
          katana -list live_sites.txt -d 5 -jc -fx -ef woff,css,...
        (CLI also accepts the same URL list via stdin; -list is clearer for automation.)
        """
        result = KatanaResult(target="stdin_batch", success=False)
        if not self.is_available():
            result.error = "Katana not installed"
            return result
        if not targets:
            result.error = "No targets provided"
            return result
        start_time = datetime.utcnow()
        # Normalize to URLs
        urls = []
        for t in targets:
            t = (t or "").strip()
            if not t:
                continue
            if not t.startswith(("http://", "https://")):
                t = f"https://{t}"
            urls.append(t)
        if not urls:
            result.error = "No valid URLs"
            return result
        per_request_timeout = min(max(30, timeout // 6), 120)
        list_path: Optional[str] = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False, encoding="utf-8",
            ) as lf:
                for u in urls:
                    lf.write(u + "\n")
                list_path = lf.name
            cmd = [
                self.katana_path,
                "-list", list_path,
                "-silent",
                "-nc",
                "-d", str(depth),
                "-rl", str(rate_limit),
                "-c", str(concurrency),
                "-timeout", str(per_request_timeout),
                "-ef", _extension_filter_csv(extension_filter_preset, extension_filter_custom),
            ]
            if js_crawl:
                cmd.append("-jc")
                if known_files:
                    cmd.extend(["-kf", "robotstxt,sitemapxml"])
            if form_extraction:
                cmd.append("-fx")
            if headless:
                cmd.append("-hl")
            if user_agent:
                cmd.extend(["-H", f"User-Agent: {user_agent}"])
            logger.info(
                f"Katana batch command: {' '.join(cmd)} ({len(urls)} seed URLs, timeout={timeout}s)"
            )
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout,
            )
            all_urls = set()
            all_endpoints = set()
            all_params = set()
            all_js = set()
            all_api = set()
            for line in stdout.decode().strip().split("\n"):
                url = line.strip()
                if not url or not url.startswith("http"):
                    continue
                all_urls.add(url)
                try:
                    parsed = urlparse(url)
                    path = parsed.path.rstrip("/")
                    if path and path != "/":
                        all_endpoints.add(path)
                    if path.endswith(".js") or "/js/" in path:
                        all_js.add(url)
                    if parsed.query:
                        for name in parse_qs(parsed.query).keys():
                            all_params.add(name)
                    url_lower = url.lower()
                    for pattern in API_PATTERNS:
                        if re.search(pattern, url_lower):
                            all_api.add(url)
                            break
                except Exception:
                    continue
            result.urls = sorted(all_urls)
            result.endpoints = sorted(all_endpoints)
            result.parameters = sorted(all_params)
            result.js_files = sorted(all_js)
            result.api_endpoints = sorted(all_api)
            result.success = len(all_urls) > 0
            result.elapsed_time = (datetime.utcnow() - start_time).total_seconds()
            logger.info(
                f"Katana batch: {len(urls)} targets -> {len(result.urls)} URLs, "
                f"{len(result.js_files)} JS files (for AI/sensitive-data assessment)"
            )
            return result
        except asyncio.TimeoutError:
            result.error = f"Katana batch timed out after {timeout}s"
            result.elapsed_time = (datetime.utcnow() - start_time).total_seconds()
            return result
        finally:
            if list_path and os.path.isfile(list_path):
                try:
                    os.unlink(list_path)
                except OSError:
                    pass
    
    def extract_secrets_from_js(self, js_content: str) -> Dict[str, List[str]]:
        """
        Extract potential secrets from JavaScript content.
        
        Args:
            js_content: JavaScript file content
            
        Returns:
            Dictionary with potential secrets by type
        """
        secrets = {
            'api_keys': [],
            'tokens': [],
            'passwords': [],
            'urls': [],
            'emails': [],
        }
        
        # API key patterns
        api_patterns = [
            r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'["\']?apikey["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'["\']?secret[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'["\']?access[_-]?token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'["\']?auth[_-]?token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'Bearer\s+([A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)',  # JWT
        ]
        
        for pattern in api_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if len(match) > 8:  # Filter short strings
                    secrets['api_keys'].append(match)
        
        # URL patterns
        url_pattern = r'https?://[^\s"\'<>]+(?:/[^\s"\'<>]*)?'
        urls = re.findall(url_pattern, js_content)
        secrets['urls'] = list(set(urls))[:100]  # Limit
        
        # Email patterns
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = re.findall(email_pattern, js_content)
        secrets['emails'] = list(set(emails))[:50]
        
        return secrets


# Convenience function
async def deep_crawl(target: str, depth: int = 5) -> KatanaResult:
    """Quick function to deep crawl a target."""
    service = KatanaService()
    return await service.crawl(target, depth=depth)
