"""Credential profiles for agentless host checks, and the external secret
stores (password vaults) their secrets can live in.

A profile names the servers it covers (``targets``), how to log in (SSH or
WinRM) and where its secret comes from:

  stored  encrypted in Judah with the API-key cipher
  store   fetched at check time from a SecretStore — HashiCorp Vault, AWS
          Secrets Manager or CyberArk Central Credential Provider — and
          never written to Judah's database

Secrets (profile secrets, a store's Vault token / AppRole secret ID /
CyberArk client key) are write-only through the API; responses only say
whether one is set.
"""

from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint

from app.db.database import Base
from app.models.api_config import get_cipher

STORE_PROVIDERS = ("hashicorp_vault", "aws_secrets_manager", "cyberark_ccp")
PROFILE_KINDS = ("ssh", "winrm")
SECRET_SOURCES = ("stored", "store")


def _encrypt(value: str) -> str:
    return get_cipher().encrypt(value.encode()).decode()


def _decrypt(value: str | None) -> str:
    return get_cipher().decrypt(value.encode()).decode() if value else ""


class HostSecretStore(Base):
    __tablename__ = "host_secret_stores"
    __table_args__ = (UniqueConstraint("organization_id", "name", name="uq_host_secret_store_org_name"),)

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(120), nullable=False)
    provider = Column(String(40), nullable=False)
    # Non-secret settings: address, namespace, auth method, role ID, mount,
    # region, role ARN, CCP URL, AppID, CA / client certificates (public).
    config = Column(JSON, nullable=False, default=dict)
    # Vault token or AppRole secret ID; CyberArk client private key.
    secret_encrypted = Column(Text)
    is_active = Column(Boolean, nullable=False, default=True)
    last_tested_at = Column(DateTime)
    last_test_ok = Column(Boolean)
    last_error = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def set_secret(self, value: str) -> None:
        self.secret_encrypted = _encrypt(value) if value else None

    def get_secret(self) -> str:
        return _decrypt(self.secret_encrypted)


class HostCredentialProfile(Base):
    __tablename__ = "host_credential_profiles"
    __table_args__ = (UniqueConstraint("organization_id", "name", name="uq_host_credential_profile_org_name"),)

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(120), nullable=False)
    kind = Column(String(10), nullable=False)  # ssh | winrm
    username = Column(String(255), nullable=False, default="")
    secret_source = Column(String(20), nullable=False, default="stored")  # stored | store
    secret_encrypted = Column(Text)
    secret_store_id = Column(Integer, ForeignKey("host_secret_stores.id", ondelete="RESTRICT"), index=True)
    # Where the secret lives in the store, e.g. {"path": "judah/linux", "key": "private_key"},
    # {"secret_id": "arn:aws:secretsmanager:...", "key": "password"} or {"safe": "...", "object": "..."}.
    secret_ref = Column(JSON, nullable=False, default=dict)
    targets = Column(JSON, nullable=False, default=list)  # CIDRs and hostname globs; required
    priority = Column(Integer, nullable=False, default=100)  # lower is tried first
    # SSH: auth, port, known_hosts, trust_on_first_use, sudo.
    # WinRM: transport, port, https, ca_cert.
    options = Column(JSON, nullable=False, default=dict)
    is_active = Column(Boolean, nullable=False, default=True)
    last_tested_at = Column(DateTime)
    last_test_ok = Column(Boolean)
    last_error = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def set_secret(self, value: str) -> None:
        self.secret_encrypted = _encrypt(value) if value else None

    def get_secret(self) -> str:
        return _decrypt(self.secret_encrypted)
