"""Application configuration settings."""

from pydantic_settings import BaseSettings
from pydantic import field_validator
from functools import lru_cache
from typing import Optional


def _strip_api_key(v: Optional[str]) -> Optional[str]:
    """Strip whitespace and optional surrounding quotes from API keys (avoids 401s)."""
    if v is None or not isinstance(v, str):
        return v
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ('"', "'"):
        v = v[1:-1].strip()
    return v if v else None


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Application
    APP_NAME: str = "Judah Security ASM"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    API_PREFIX: str = "/api/v1"
    
    # Database
    DATABASE_URL: str = "postgresql://asm_user:asm_password@db:5432/asm_db"
    
    # JWT Authentication
    # No default: SECRET_KEY must be supplied via the environment. A missing or
    # placeholder value makes HS256 tokens forgeable, so we fail closed at startup.
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # Registration
    # Public self-registration is disabled by default; admins provision users via
    # POST /users/. Flip to True only for deployments that intentionally allow it.
    ALLOW_PUBLIC_REGISTRATION: bool = False

    # Customer-facing external posture grade. This is an operational kill switch;
    # keep the default on for new deployments and set false to hide it instantly.
    POSTURE_GRADE_ENABLED: bool = True

    # CAPTCHA (bot / brute-force protection on auth endpoints)
    # Disabled by default: with no secret key configured, verification is skipped
    # so local/dev logins keep working. Set CAPTCHA_ENABLED=true + the keys in prod.
    CAPTCHA_ENABLED: bool = False
    CAPTCHA_PROVIDER: str = "turnstile"  # turnstile | hcaptcha | recaptcha
    CAPTCHA_SECRET_KEY: Optional[str] = None
    # Public site key — safe to expose to the browser (served via GET /auth/config).
    CAPTCHA_SITE_KEY: Optional[str] = None

    # Rate limiting (brute-force / abuse protection on auth + expensive endpoints)
    RATE_LIMIT_ENABLED: bool = True
    # slowapi storage backend. "memory://" is per-process (fine for a single
    # worker); use "redis://redis:6379" to share limits across workers/instances.
    RATE_LIMIT_STORAGE_URI: str = "memory://"
    RATE_LIMIT_LOGIN: str = "5/minute"
    RATE_LIMIT_REGISTER: str = "5/hour"
    RATE_LIMIT_REFRESH: str = "20/minute"

    # CORS
    CORS_ORIGINS: list[str] = [
        "http://localhost",
        "http://localhost:80",
        "http://localhost:3000",
        "http://localhost:8080",
        "http://3.88.137.29",
        "http://3.88.137.29:80",
        "http://3.88.137.29:3000",
        "http://3.88.137.29:8000",
        "https://aegis.theforcesecurity.io",
        "https://www.aegis.theforcesecurity.io",
        "https://aegis.judahsecurity.io",
    ]
    # Always allow the production HTTPS frontends even if CORS_ORIGINS in .env
    # is stale (missing theforcesecurity.io). Starlette fullmatch.
    CORS_ORIGIN_REGEX: str = r"https://(.*\.)?(theforcesecurity|judahsecurity)\.io"
    
    # Pagination
    DEFAULT_PAGE_SIZE: int = 20
    MAX_PAGE_SIZE: int = 100
    
    # ProjectDiscovery Cloud API Key (for Chaos subdomain dataset)
    PDCP_API_KEY: str = ""
    
    # AI Agent Configuration (default: Claude)
    # Supported: openai | anthropic | deepseek | kimi | groq | ollama
    AI_PROVIDER: str = "anthropic"
    
    # OpenAI Configuration
    OPENAI_API_KEY: Optional[str] = None
    OPENAI_MODEL: str = "gpt-4o"
    
    # Anthropic/Claude Configuration (default agent)
    # Use key from https://console.anthropic.com (API keys) — NOT Claude Code / Cursor keys
    ANTHROPIC_API_KEY: Optional[str] = None
    ANTHROPIC_MODEL: str = "claude-sonnet-4-6"

    # DeepSeek (OpenAI-compatible). Optional; per-org keys can also be set in the
    # encrypted API-config store. Provider string: "deepseek".
    DEEPSEEK_API_KEY: Optional[str] = None
    DEEPSEEK_MODEL: str = "deepseek-chat"

    # Moonshot / Kimi (OpenAI-compatible). Optional; per-org keys via API-config
    # store (service name "kimi"). Env var matches Moonshot docs: MOONSHOT_API_KEY.
    MOONSHOT_API_KEY: Optional[str] = None
    KIMI_MODEL: str = "kimi-k3"

    # Groq (OpenAI-compatible, free tier). Provider string: "groq".
    GROQ_API_KEY: Optional[str] = None
    GROQ_MODEL: str = "llama-3.3-70b-versatile"

    # Local Ollama (OpenAI-compatible). No cloud key required.
    # Docker Desktop: http://host.docker.internal:11434/v1
    OLLAMA_BASE_URL: str = "http://127.0.0.1:11434/v1"
    OLLAMA_MODEL: str = "qwen2.5:14b"
    # Local Ollama fallback is opt-in (needs a GPU/RAM box). Default off so
    # small app hosts use cloud APIs only.
    OLLAMA_FALLBACK_ENABLED: bool = False

    @field_validator(
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "DEEPSEEK_API_KEY",
        "MOONSHOT_API_KEY",
        "GROQ_API_KEY",
        mode="before",
    )
    @classmethod
    def strip_api_keys(cls, v: Optional[str]) -> Optional[str]:
        return _strip_api_key(v)

    @field_validator("SECRET_KEY")
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        """Refuse to start with a missing, placeholder, or weak signing key.

        A predictable SECRET_KEY lets anyone forge valid JWTs for any user
        (including the superuser), so this is enforced at startup rather than
        left to operator discipline.
        """
        value = (v or "").strip()
        insecure = {
            "your-super-secret-key-change-in-production",
            "please-change-me-locally-only",
            "changeme",
            "change-me",
            "secret",
            "secret-key",
        }
        if not value or value.lower() in insecure:
            raise ValueError(
                "SECRET_KEY is missing or set to a known placeholder. Set a strong, "
                "unique value in the environment (generate one with `openssl rand -hex 32`)."
            )
        if len(value) < 32:
            raise ValueError(
                "SECRET_KEY must be at least 32 characters. Generate one with "
                "`openssl rand -hex 32`."
            )
        return value
    
    # Agent settings (overridable per-org via project_settings.agent)
    AGENT_MAX_ITERATIONS: int = 100
    # Scales every specialist's turn limit (bounded 0.5-4). Use for equal-budget
    # benchmark runs of bigger budgets without editing specialist profiles.
    AGENT_SPECIALIST_TURN_MULTIPLIER: float = 1.0
    # Default assessment depth when a request does not choose one: "standard"
    # (deterministic pipeline) or "deep" (model-led after recon, larger budgets;
    # same scope and publication gates). See services/agent/assessment_depth.py.
    AGENT_ASSESSMENT_MODE: str = "standard"
    AGENT_MAX_OUTPUT_TOKENS: int = 4096  # Max tokens for LLM response (Claude/OpenAI); increase for long answers (e.g. 8192, 16384, 64000)
    AGENT_TOOL_OUTPUT_MAX_CHARS: int = 20000  # RedAmon-style default; truncation for LLM context
    AGENT_ANALYZE_TIMEOUT_SECONDS: int = 90  # Optional tool-output analysis must not stall an assessment.
    AGENT_PLAN_TIMEOUT_SECONDS: int = 90  # Bound a queued planning call before the provider's long timeout.
    AGENT_REST_MAX_ITERATIONS: int = 15  # Cap per REST request to avoid proxy timeouts
    AGENT_WS_MAX_ITERATIONS: int = 160  # Allow a full assessment to continue past the initial recon loop.
    AGENT_REQUEST_TIMEOUT_SECONDS: int = 7200  # Hard timeout for a single agent REST/WS turn (2h).
    # Internal wall-clock budget for one agent turn's ReAct loop. Once exceeded the
    # loop stops picking new tools and wraps up with a partial report. Keep below
    # AGENT_REQUEST_TIMEOUT_SECONDS so the graceful path wins over the hard cutoff.
    # 10 minutes was shorter than Interceptor crawl + fireteam on a live app.
    AGENT_TURN_BUDGET_SECONDS: int = 6900  # Reserve five minutes for the final report.
    # Hard USD spend cap for one agent session (CAI CAI_PRICE_LIMIT analog).
    # 0 disables the cap. Checked before each LLM think so we stop before overspend.
    AGENT_PRICE_LIMIT_USD: float = 20.0
    # Auto-compact the execution trace once it exceeds this many steps.
    AGENT_COMPACT_TRACE_STEPS: int = 24
    # Timeout for attaching an external MCP server (Burp/Caido).
    AGENT_MCP_CONNECT_TIMEOUT_SECONDS: float = 8.0
    # External MCP isolation (mcp_client.py): concurrency limits, the bounded
    # wait for a free slot, and a per-server circuit breaker on transport
    # failures (N consecutive failures -> stop sending for the cooldown).
    AGENT_MCP_MAX_CONCURRENT_PER_SERVER: int = 4
    AGENT_MCP_MAX_CONCURRENT_TOTAL: int = 16
    AGENT_MCP_QUEUE_TIMEOUT_SECONDS: float = 30.0
    AGENT_MCP_BREAKER_FAILURES: int = 5
    AGENT_MCP_BREAKER_COOLDOWN_SECONDS: float = 60.0
    # Node-level ceiling for a single tool call. Bounds any one tool so a hung
    # tool can never block the turn, and guarantees a tool_complete event is
    # emitted (so the UI never dangles on a tool_start).
    AGENT_TOOL_HARD_TIMEOUT_SECONDS: int = 600
    # How the deterministic assessment pipeline (tester_loop.forced_next_step)
    # drives Joshua once the app is mapped. "strict" forces every pipeline step.
    # "advisory" shows the pipeline step as a suggestion and gives the model
    # AGENT_STEERING_FREE_TURNS of its own decisions before the step is forced.
    # Mapping, proof bookkeeping, CVE applicability and pilot steps are always
    # forced, and the completion gate is unchanged in both modes.
    AGENT_STEERING_MODE: str = "strict"
    AGENT_STEERING_FREE_TURNS: int = 2
    # Add hunting-discipline rules (exhaust bypasses, depth over breadth,
    # re-examine negatives, hand off side clues) to Joshua and specialists.
    AGENT_HUNT_DISCIPLINE_PROMPT: bool = False
    # Hunters must attach an adversarial self-review (reachability,
    # preconditions, downstream controls, scope, benign explanation, strongest
    # objection, disproof test) to submit_finding_candidate. The verifier gets
    # it as a checklist; inconclusive candidates with hunter evidence and a
    # challenge are flagged needs_analyst_review instead of disappearing.
    AGENT_SELF_CHALLENGE: bool = False
    # A specialist "killed" verdict backed by one evidence receipt or one
    # testing tool goes back once for a different technique before closing.
    AGENT_RECHECK_WEAK_NEGATIVES: bool = False
    # When a turn ends on its iteration or time budget, one bounded model call
    # lists leads the trace shows but that were never submitted, and saves them
    # as pending, evidence-free candidates for the next run's verifier
    # (services/agent/settlement.py). Never publishes anything.
    AGENT_SETTLEMENT_BACKFILL: bool = False
    AGENT_SETTLEMENT_TIMEOUT_SECONDS: int = 45
    # End a turn after this many planning steps in a row start no tool, instead
    # of letting the model re-plan until the iteration budget runs out. 0 = off.
    AGENT_MAX_IDLE_PLANNING_TURNS: int = 4
    # Hard ceiling on target requests per session (0 = none). An operator's
    # assessment_policy.max_target_requests overrides it. Discovery (kickoff,
    # crawls, maps) may use only (1 - AGENT_TESTING_RESERVE_FRACTION) of it;
    # the rest is reserved for input testing and verification.
    AGENT_MAX_TARGET_REQUESTS: int = 0
    AGENT_TESTING_RESERVE_FRACTION: float = 0.6
    # Run the bounded SQLi/XSS first pass on inputs while execute_deep_crawl is
    # still mapping, instead of only after it returns (streaming_first_pass.py).
    AGENT_STREAMING_FIRST_PASS: bool = False
    # Where run_custom_probe / run_poc_python execute model-written Python.
    # "off": tool disabled. "isolated": sent to the probe-runner container
    # through the scope-enforcing probe-egress relay (AGENT_PROBE_RUNNER_URL).
    # "inprocess": legacy subprocess inside this container; its AST checks are
    # bypassable (shell and file access), so use it only on isolated lab hosts.
    AGENT_CUSTOM_PROBE_MODE: str = "off"
    AGENT_PROBE_RUNNER_URL: str = "http://probe-egress:9000"
    AGENT_PROBE_RUNNER_TOKEN: str = ""
    # Give specialists sandbox_shell (bash + curl/sqlmap/ffuf/python) inside
    # probe-runner. Needs AGENT_CUSTOM_PROBE_MODE=isolated; never runs in-process.
    AGENT_SANDBOX_SHELL: bool = False
    # Long scanners (tool_executions.BACKGROUND_TOOLS) are waited on this many
    # seconds once running; if still running they continue in the background
    # under the hard cap and the agent gets an execution_id. 0 disables.
    AGENT_TOOL_WAIT_SECONDS: int = 120
    # Tool docs in the planner prompt: "full" (every tool's full description,
    # ~15k tokens) or "index" (one line per tool, ~3.6k tokens; the agent calls
    # describe_tools for full docs). Benchmark "index" before making it default.
    AGENT_TOOL_DOCS_MODE: str = "full"
    # Tool guard (tool_guard.py): regex block-list checked before any tool
    # runs, on top of the scope allow-list. The default rule blocks
    # government/military domains; disable it only for engagements that are
    # authorized against them. AGENT_TOOL_GUARD_RULES is a JSON list of
    # {"name", "pattern", "reminder", "enabled"} objects.
    # Chat notifications (chat_notifier.py). The bot token is a platform secret;
    # each org opts in and lists its own chat IDs in the notifications module.
    # Platform audit log (platform_audit.py): who did what. 0 keeps rows forever.
    AUDIT_ENABLED: bool = True
    AUDIT_RETENTION_DAYS: int = 365
    TELEGRAM_BOT_TOKEN: str = ""
    # Base URL of the web app, used for links in notifications (optional).
    PUBLIC_APP_URL: str = ""
    AGENT_TOOL_GUARD_ENABLED: bool = True
    AGENT_TOOL_GUARD_DEFAULT_RULES: bool = True
    AGENT_TOOL_GUARD_RULES: str = ""

    # Private scoped-assessment executor. Aegis remains the agent/model runtime.
    PROWL_ASSESSMENT_URL: str = ""
    PROWL_ADMIN_TOKEN: str = ""
    # Observation -> model-proposed follow-up work (observation_followups.py).
    PROWL_FOLLOWUP_PLANNER_ENABLED: bool = True
    PROWL_FOLLOWUP_MAX_EVENTS_PER_RUN: int = 60

    # ---- Aegis Lictor / Censor / Augur (deterministic guard layer) ----
    # Lictor pre/post tool-execution hooks. Disabling skips ALL guards (not recommended).
    AGENT_LICTOR_ENABLED: bool = True
    # Restrict tool targets to assets in the calling org. Off by default to keep
    # ad-hoc recon usable; flip on for production multi-tenant deployments.
    AGENT_ENFORCE_ORG_SCOPE: bool = False
    # Per-(org, tool) token-bucket rate limit.
    AGENT_TOOL_RATE_CAPACITY: int = 30      # burst size
    AGENT_TOOL_RATE_PER_MINUTE: int = 30    # sustained refill
    # Censor input-validation gate (rejects malformed args before subprocess spawn).
    AGENT_CENSOR_ENABLED: bool = True
    # Augur output interpreter (smart nuclei/nmap/ffuf/etc filtering + next-step pivots).
    AGENT_AUGUR_ENABLED: bool = True
    # Verbose mode keeps the raw scanner output in addition to Augur's reading.
    AGENT_AUGUR_VERBOSE: bool = False

    # Optional: Tavily API for agent web search (CVE/exploit research). Get key at tavily.com
    TAVILY_API_KEY: Optional[str] = None
    
    # Neo4j Graph Database Configuration
    NEO4J_URI: str = "bolt://neo4j:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = "neo4j_password"
    
    # GitHub Secret Scanning Configuration
    GITHUB_TOKEN: Optional[str] = None
    GITHUB_SECRET_SCAN_ENABLED: bool = True
    
    # MITRE ATT&CK Enrichment
    MITRE_ENRICHMENT_ENABLED: bool = True

    # Delphi (CISA KEV + FIRST EPSS) Enrichment
    DELPHI_ENRICHMENT_ENABLED: bool = True
    DELPHI_REFRESH_HOURS: int = 24  # Re-fetch KEV + EPSS after this many hours
    DELPHI_AUTO_ENRICH_ON_INGEST: bool = True  # Enrich CVEs during ingestion pipeline
    # Extended exploitation feeds: VulnCheck KEV, Shadowserver (via CIRCL),
    # KEVIntel attestations (via CIRCL). Disable to keep Delphi on CISA-only.
    DELPHI_EXTENDED_KEV_ENABLED: bool = True
    # Optional operator FIRE export (JSON). See backend/data/breach_intel/fire_cves.json.
    DELPHI_FIRE_CVE_PATH: Optional[str] = None
    DELPHI_BREACH_INTEL_DIR: Optional[str] = None

    # Vulnerability intelligence API keys (also resolvable via api_configs / env)
    VULNCHECK_API_TOKEN: Optional[str] = None
    NVD_API_KEY: Optional[str] = None

    # Oracle (LLM analyst-grade analysis) — background enrichment at ingest.
    # Enabled: every new finding (CVE-backed or not) enqueues a non-blocking
    # background Oracle analysis immediately after Delphi runs. Requires the
    # aegis-oracle service to be running; failures are logged and never block
    # ingestion.
    ORACLE_AUTO_ENRICH_ON_INGEST: bool = True

    # Detection suppression — pattern-based false-positive handling.
    # A template is flagged for suppression review only once false-positive
    # signals (validator verdicts + analyst feedback + manual status) span at
    # least this many distinct hosts. Suppression is enforced only after an
    # analyst approves the recommendation.
    DETECTION_PATTERN_MIN_HOSTS: int = 3
    # How many findings to auto-queue for validator review when suggested.
    DETECTION_PATTERN_VALIDATE_SAMPLE: int = 5

    # Custom Nuclei templates shipped with the platform.
    # Relative to the backend/ directory; resolved to an absolute path at runtime.
    # Set to an empty string or override via env to disable custom templates.
    NUCLEI_CUSTOM_TEMPLATES_PATH: str = "nuclei-templates"

    # Analyst-written / AI-generated custom Nuclei templates are stored in the
    # `custom_nuclei_templates` DB table (source of truth) and materialized to
    # this directory on disk so the scanner can actually run them.
    # Relative to the backend/ directory; resolved to an absolute path at runtime.
    NUCLEI_GENERATED_TEMPLATES_PATH: str = "nuclei-templates-generated"

    # Path to the official Nuclei templates on disk (populated by
    # `nuclei -update-templates`). Used to look up an official template's YAML for
    # the existence check, validator diagnosis, and refinement. Leave empty to
    # auto-detect common locations (~/.config/nuclei/nuclei-templates, ~/nuclei-templates, …).
    NUCLEI_OFFICIAL_TEMPLATES_PATH: str = ""

    # Cloudflare WAF scanner whitelist — egress IPs and dedicated UA used when
    # syncing skip rules (and by scanners identifying themselves to those rules).
    # Comma-separated IPv4/IPv6 addresses or CIDRs, e.g. "203.0.113.10,198.51.100.0/24".
    ASM_SCANNER_EGRESS_IPS: str = ""
    ASM_SCANNER_USER_AGENT: str = "JudahSecurity-ASM-Scanner/1.0"
    # Exact public source IP of the backend worker used for bounded agent
    # pilots. Required before the pilot mode can start; kept separate from the
    # scanner CIDR allowlist above.
    AEGIS_AGENT_EGRESS_IP: str = ""

    # Dual Interceptor workers (Mac desktop + Ubuntu browser host)
    INTERCEPTOR_BIN: Optional[str] = None
    INTERCEPTOR_WORKER_TOKEN: Optional[str] = None
    INTERCEPTOR_WORKER_HEARTBEAT_TTL_SEC: int = 90
    RECON_JOB_TIMEOUT_SEC: int = 900
    # When True, execute_interceptor creates a remote job if any worker is online
    # before trying local CLI / deep_crawl.
    INTERCEPTOR_PREFER_REMOTE_WORKERS: bool = True

    # Optional OTLP HTTP endpoint for redacted agent traces (Phoenix / self-hosted Langfuse).
    OTEL_EXPORTER_OTLP_ENDPOINT: Optional[str] = None
    OTEL_EXPORTER_OTLP_HEADERS: Optional[str] = None
    LANGFUSE_PUBLIC_KEY: Optional[str] = None
    LANGFUSE_SECRET_KEY: Optional[str] = None
    
    class Config:
        env_file = ".env"
        case_sensitive = True
        # Ignore unknown environment variables. The project's .env is shared with
        # docker-compose and carries orchestration-only keys (POSTGRES_USER,
        # DB_PORT, DEFAULT_ADMIN_PASSWORD, …) that are not Settings fields. In
        # Docker the container only receives a curated env list so this never
        # bites, but running the app directly against the full .env must not crash
        # on those extras.
        extra = "ignore"


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


settings = get_settings()



