"""
API Configuration model for storing external service API keys.

Stores encrypted API keys for various external discovery services:
- WhoisXML API
- Whoxy
- VirusTotal
- AlienVault OTX
- And more
"""

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Boolean, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
from cryptography.fernet import Fernet
import os
import base64

from app.db.database import Base


def get_encryption_key():
    """Get encryption key from environment, using SECRET_KEY as fallback."""
    # Try dedicated encryption key first
    key = os.environ.get("API_KEY_ENCRYPTION_KEY")
    if not key:
        # Fall back to SECRET_KEY which is always set in docker-compose
        key = os.environ.get("SECRET_KEY", "your-super-secret-key-change-in-production")
    return key


def get_cipher():
    """Get Fernet cipher for encryption/decryption."""
    key = get_encryption_key()
    key = key.encode() if isinstance(key, str) else key
    # Ensure key is valid Fernet key (32 url-safe base64-encoded bytes)
    if len(key) != 44:
        # Generate a deterministic key from the provided key
        import hashlib
        key = base64.urlsafe_b64encode(hashlib.sha256(key).digest())
    return Fernet(key)


class APIConfig(Base):
    """
    Model for storing API configurations and keys for external services.
    
    API keys are encrypted at rest for security.
    """
    __tablename__ = "api_configs"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Organization this config belongs to
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    organization = relationship("Organization")
    
    # Service identification
    service_name = Column(String(64), nullable=False, index=True)
    # Service names: whoisxml, whoxy, virustotal, otx, shodan, censys, securitytrails, etc.
    
    # Encrypted API key
    api_key_encrypted = Column(Text, nullable=True)
    
    # Optional additional credentials
    api_user = Column(String(256), nullable=True)  # For services requiring username
    api_secret_encrypted = Column(Text, nullable=True)  # For services with separate secret
    
    # Service-specific configuration
    config = Column(JSON, default=dict)
    # Examples:
    # - whoxy: {"registration_emails": ["admin@company.com"]}
    # - whoisxml: {"organization_names": ["Company Inc"]}
    # - virustotal: {"daily_quota_percent": 70}
    
    # Status
    is_active = Column(Boolean, default=True)
    is_valid = Column(Boolean, default=True)  # Set to False if key fails validation
    
    # Usage tracking
    last_used = Column(DateTime, nullable=True)
    usage_count = Column(Integer, default=0)
    last_error = Column(Text, nullable=True)
    
    # Rate limiting
    rate_limit_per_second = Column(Integer, nullable=True)
    rate_limit_per_day = Column(Integer, nullable=True)
    daily_usage = Column(Integer, default=0)
    daily_usage_reset = Column(DateTime, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def set_api_key(self, key: str):
        """Encrypt and store API key."""
        if key:
            cipher = get_cipher()
            self.api_key_encrypted = cipher.encrypt(key.encode()).decode()
    
    def get_api_key(self) -> str:
        """Decrypt and return API key."""
        if self.api_key_encrypted:
            cipher = get_cipher()
            return cipher.decrypt(self.api_key_encrypted.encode()).decode()
        return None
    
    def set_api_secret(self, secret: str):
        """Encrypt and store API secret."""
        if secret:
            cipher = get_cipher()
            self.api_secret_encrypted = cipher.encrypt(secret.encode()).decode()
    
    def get_api_secret(self) -> str:
        """Decrypt and return API secret."""
        if self.api_secret_encrypted:
            cipher = get_cipher()
            return cipher.decrypt(self.api_secret_encrypted.encode()).decode()
        return None
    
    def increment_usage(self):
        """Increment usage counter."""
        self.usage_count += 1
        self.daily_usage += 1
        self.last_used = datetime.utcnow()
    
    def reset_daily_usage(self):
        """Reset daily usage counter."""
        self.daily_usage = 0
        self.daily_usage_reset = datetime.utcnow()
    
    def __repr__(self):
        return f"<APIConfig {self.service_name} for org {self.organization_id}>"


# Service name constants
class ExternalService:
    """Constants for external service names."""
    WHOISXML = "whoisxml"
    WHOXY = "whoxy"
    VIRUSTOTAL = "virustotal"
    OTX = "otx"
    SHODAN = "shodan"
    CENSYS = "censys"
    SECURITYTRAILS = "securitytrails"
    BINARYEDGE = "binaryedge"
    PASSIVETOTAL = "passivetotal"

    # Vulnerability intelligence / exploit signals
    VULNCHECK = "vulncheck"        # VulnCheck KEV + exploit intelligence
    PDCP = "pdcp"                  # ProjectDiscovery Cloud Platform (vulnx, Nuclei templates)
    NVD = "nvd"                    # NVD API key (raises rate limits)

    # LLM providers (bring-your-own-key). Keys are encrypted at rest and are
    # ONLY ever handed to the model SDK client at construction time — they must
    # never be placed into an LLM prompt, tool output, or agent state.
    ANTHROPIC = "anthropic"        # Claude
    OPENAI = "openai"              # GPT / Codex
    DEEPSEEK = "deepseek"          # DeepSeek (OpenAI-compatible)
    KIMI = "kimi"                  # Moonshot / Kimi (OpenAI-compatible)
    GROQ = "groq"                  # Groq (OpenAI-compatible, free tier)
    OLLAMA = "ollama"              # Local Ollama (OpenAI-compatible, no cloud key)
    GEMINI = "gemini"              # Google Gemini (future)
    OPENROUTER = "openrouter"      # OpenRouter aggregator (future)

    # Free services (no API key required)
    WAYBACK = "wayback"
    RAPIDDNS = "rapiddns"
    CRTSH = "crtsh"
    SHODAN_CTL = "shodan_ctl"
    CRT_NAME = "crt_name"
    COMMONCRAWL = "commoncrawl"
    M365 = "m365"


# Default rate limits for services
DEFAULT_RATE_LIMITS = {
    ExternalService.WHOISXML: {"per_second": 2, "per_day": 1000},
    ExternalService.WHOXY: {"per_second": 2, "per_day": 500},
    ExternalService.VIRUSTOTAL: {"per_second": 4, "per_day": 500},
    ExternalService.OTX: {"per_second": 2, "per_day": 10000},
    ExternalService.SHODAN: {"per_second": 1, "per_day": None},
    ExternalService.CENSYS: {"per_second": 0.4, "per_day": 250},
    ExternalService.SECURITYTRAILS: {"per_second": 2, "per_day": 50},
    ExternalService.WAYBACK: {"per_second": 1, "per_day": None},
    ExternalService.RAPIDDNS: {"per_second": 1, "per_day": None},
    ExternalService.SHODAN_CTL: {"per_second": 1, "per_day": None},
    # crt.name free tier: 1000 requests per IP per day
    ExternalService.CRT_NAME: {"per_second": 1, "per_day": 1000},
    ExternalService.M365: {"per_second": 1, "per_day": None},
    ExternalService.VULNCHECK: {"per_second": 10, "per_day": None},
    ExternalService.PDCP: {"per_second": 10, "per_day": None},
    ExternalService.NVD: {"per_second": 5, "per_day": None},
}


# ── Env-var fallbacks for each service ───────────────────────────────────────
# When no DB record exists, these env vars are checked as a fallback.
SERVICE_ENV_FALLBACK: dict[str, str] = {
    ExternalService.VULNCHECK: "VULNCHECK_API_TOKEN",
    ExternalService.PDCP:      "PDCP_API_KEY",
    ExternalService.NVD:       "NVD_API_KEY",
    ExternalService.OTX:       "OTX_API_KEY",
    ExternalService.SHODAN:    "SUBCAT_SHODAN_KEY",
    ExternalService.VIRUSTOTAL: "SUBCAT_VIRUSTOTAL_KEY",
    ExternalService.SECURITYTRAILS: "SUBCAT_SECURITYTRAILS_KEY",
    ExternalService.BINARYEDGE: "SUBCAT_BINARYEDGE_KEY",
    # LLM providers
    ExternalService.ANTHROPIC:  "ANTHROPIC_API_KEY",
    ExternalService.OPENAI:     "OPENAI_API_KEY",
    ExternalService.DEEPSEEK:   "DEEPSEEK_API_KEY",
    ExternalService.KIMI:       "MOONSHOT_API_KEY",
    ExternalService.GROQ:       "GROQ_API_KEY",
    ExternalService.GEMINI:     "GEMINI_API_KEY",
    ExternalService.OPENROUTER: "OPENROUTER_API_KEY",
    # Ollama is local — no cloud key. Optional OLLAMA_API_KEY is unused by
    # default; the router supplies a dummy client key when needed.
}


# Providers that route through the LLM factory. The key `provider` string used
# throughout the model-routing layer matches these service names exactly.
LLM_PROVIDERS: frozenset[str] = frozenset({
    ExternalService.ANTHROPIC,
    ExternalService.OPENAI,
    ExternalService.DEEPSEEK,
    ExternalService.KIMI,
    ExternalService.GROQ,
    ExternalService.OLLAMA,
    ExternalService.GEMINI,
    ExternalService.OPENROUTER,
})

# Providers that can run without a real cloud API key.
KEYLESS_LLM_PROVIDERS: frozenset[str] = frozenset({
    ExternalService.OLLAMA,
})


def resolve_llm_key(db, provider: str, organization_id: int | None = None) -> str | None:
    """Resolve the API key for an LLM `provider` (per-org DB key, then env).

    Thin wrapper over :func:`resolve_api_key` that constrains the lookup to
    known LLM providers. The returned key is meant to be passed straight to the
    model SDK client and must never be logged or placed into an LLM prompt.
    """
    provider = (provider or "").strip().lower()
    if provider not in LLM_PROVIDERS:
        return None
    return resolve_api_key(db, provider, organization_id)


def resolve_api_key(db, service: str, organization_id: int | None = None) -> str | None:
    """
    Resolve an API key for `service` using a two-step lookup:

    1. DB (api_configs table) — scoped to `organization_id` if given, otherwise
       returns the first active record for the service across all orgs.
    2. Environment variable fallback (SERVICE_ENV_FALLBACK map).

    This lets admins configure keys via the Settings UI without needing to
    touch the server's `.env` file. The env-var fallback ensures existing
    deployments keep working without a DB migration step.
    """
    try:
        query = db.query(APIConfig).filter(
            APIConfig.service_name == service,
            APIConfig.is_active == True,
        )
        if organization_id is not None:
            query = query.filter(APIConfig.organization_id == organization_id)
        config = query.first()
        if config:
            key = config.get_api_key()
            if key:
                return key
    except Exception:
        pass

    # Fall back to environment variable
    env_var = SERVICE_ENV_FALLBACK.get(service)
    if env_var:
        return os.environ.get(env_var) or None
    return None















