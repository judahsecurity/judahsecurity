"""
GitHub Secret Scanning Service

Searches GitHub repositories for exposed secrets such as API keys,
credentials, private keys, and database connection strings.
"""

import re
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime

from github import Github, GithubException
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.database import SessionLocal
from app.models.vulnerability import Vulnerability, Severity, VulnerabilityStatus
from app.models.asset import Asset, AssetType

logger = logging.getLogger(__name__)


# Secret detection patterns
SECRET_PATTERNS = {
    # AWS
    "aws_access_key": {
        "pattern": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "description": "AWS Access Key ID",
        "severity": Severity.CRITICAL,
    },
    "aws_secret_key": {
        "pattern": r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]",
        "description": "AWS Secret Access Key",
        "severity": Severity.CRITICAL,
    },
    
    # Google Cloud
    "gcp_api_key": {
        "pattern": r"AIza[0-9A-Za-z\\-_]{35}",
        "description": "Google Cloud API Key",
        "severity": Severity.HIGH,
    },
    "gcp_service_account": {
        "pattern": r'"type":\s*"service_account"',
        "description": "Google Cloud Service Account JSON",
        "severity": Severity.CRITICAL,
    },
    
    # Azure
    "azure_subscription_key": {
        "pattern": r"(?i)(subscription[_-]?key|api[_-]?key)[\s]*[=:]+[\s]*['\"]?[a-f0-9]{32}['\"]?",
        "description": "Azure Subscription Key",
        "severity": Severity.HIGH,
    },
    
    # GitHub
    "github_token": {
        "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,}",
        "description": "GitHub Personal Access Token",
        "severity": Severity.HIGH,
    },
    "github_oauth": {
        "pattern": r"gho_[A-Za-z0-9_]{36}",
        "description": "GitHub OAuth Token",
        "severity": Severity.HIGH,
    },
    
    # Stripe
    "stripe_secret_key": {
        "pattern": r"sk_live_[0-9a-zA-Z]{24}",
        "description": "Stripe Secret Key (Live)",
        "severity": Severity.CRITICAL,
    },
    "stripe_test_key": {
        "pattern": r"sk_test_[0-9a-zA-Z]{24}",
        "description": "Stripe Secret Key (Test)",
        "severity": Severity.MEDIUM,
    },
    
    # Slack
    "slack_token": {
        "pattern": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
        "description": "Slack Token",
        "severity": Severity.HIGH,
    },
    "slack_webhook": {
        "pattern": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}",
        "description": "Slack Webhook URL",
        "severity": Severity.MEDIUM,
    },
    
    # Database
    "postgres_uri": {
        "pattern": r"postgres(?:ql)?://[^:]+:[^@]+@[^/]+/[^\s]+",
        "description": "PostgreSQL Connection String",
        "severity": Severity.CRITICAL,
    },
    "mysql_uri": {
        "pattern": r"mysql://[^:]+:[^@]+@[^/]+/[^\s]+",
        "description": "MySQL Connection String",
        "severity": Severity.CRITICAL,
    },
    "mongodb_uri": {
        "pattern": r"mongodb(\+srv)?://[^:]+:[^@]+@[^\s]+",
        "description": "MongoDB Connection String",
        "severity": Severity.CRITICAL,
    },
    
    # Private Keys
    "rsa_private_key": {
        "pattern": r"-----BEGIN RSA PRIVATE KEY-----",
        "description": "RSA Private Key",
        "severity": Severity.CRITICAL,
    },
    "ssh_private_key": {
        "pattern": r"-----BEGIN (?:OPENSSH|EC|DSA) PRIVATE KEY-----",
        "description": "SSH Private Key",
        "severity": Severity.CRITICAL,
    },
    "pgp_private_key": {
        "pattern": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "description": "PGP Private Key",
        "severity": Severity.CRITICAL,
    },
    
    # Generic API Keys
    "generic_api_key": {
        "pattern": r"(?i)(api[_-]?key|apikey|api[_-]?secret)['\"]?\s*[=:]\s*['\"]?[a-zA-Z0-9_\-]{20,}['\"]?",
        "description": "Generic API Key",
        "severity": Severity.MEDIUM,
    },
    "generic_secret": {
        "pattern": r"(?i)(secret|password|passwd|pwd)['\"]?\s*[=:]\s*['\"][^\s'\"]{8,}['\"]",
        "description": "Hardcoded Secret/Password",
        "severity": Severity.HIGH,
    },
    
    # JWT
    "jwt_token": {
        "pattern": r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/]*",
        "description": "JWT Token",
        "severity": Severity.MEDIUM,
    },
    
    # Twilio
    "twilio_api_key": {
        "pattern": r"SK[a-f0-9]{32}",
        "description": "Twilio API Key",
        "severity": Severity.HIGH,
    },
    
    # SendGrid
    "sendgrid_api_key": {
        "pattern": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
        "description": "SendGrid API Key",
        "severity": Severity.HIGH,
    },
    
    # Mailgun
    "mailgun_api_key": {
        "pattern": r"key-[0-9a-zA-Z]{32}",
        "description": "Mailgun API Key",
        "severity": Severity.HIGH,
    },
}


_PLACEHOLDERS = (
    "example", "placeholder", "your_", "xxx", "123", "abc",
    "test", "sample", "demo", "dummy", "fake", "mock",
    "todo", "fixme", "changeme", "insert", "replace",
)


def is_likely_secret(text: str, secret_type: str) -> bool:
    """Check if a match is likely a real secret (not a placeholder)."""
    text_lower = text.lower()
    if any(placeholder in text_lower for placeholder in _PLACEHOLDERS):
        return False
    # Repeated characters (e.g. "AKIAAAAAAAAAAAAAAAAA") are not real keys.
    return len(set(text)) >= 5


class GitHubSecretService:
    """
    Service for scanning GitHub repositories for exposed secrets.
    """
    
    def __init__(self):
        self.github = None
        if settings.GITHUB_TOKEN:
            self.github = Github(settings.GITHUB_TOKEN)
    
    def is_available(self) -> bool:
        """Check if the service is available."""
        return self.github is not None and settings.GITHUB_SECRET_SCAN_ENABLED
    
    def scan_organization(
        self,
        org_name: str,
        organization_id: int,
        max_repos: int = 100
    ) -> Dict[str, Any]:
        """
        Scan all public repositories of a GitHub organization.
        
        Args:
            org_name: GitHub organization name
            organization_id: Internal organization ID for storing findings
            max_repos: Maximum number of repositories to scan
        
        Returns:
            Scan results with found secrets
        """
        if not self.is_available():
            return {"error": "GitHub scanning not available", "secrets": []}
        
        try:
            org = self.github.get_organization(org_name)
        except GithubException as e:
            logger.error(f"Failed to get organization {org_name}: {e}")
            return {"error": str(e), "secrets": []}
        
        secrets_found = []
        repos_scanned = 0
        
        for repo in org.get_repos(type="public")[:max_repos]:
            try:
                repo_secrets = self._scan_repository(repo)
                secrets_found.extend(repo_secrets)
                repos_scanned += 1
            except Exception as e:
                logger.warning(f"Error scanning repo {repo.name}: {e}")
        
        # Store findings as vulnerabilities
        if secrets_found:
            self._store_findings(secrets_found, org_name, organization_id)
        
        return {
            "organization": org_name,
            "repos_scanned": repos_scanned,
            "secrets_found": len(secrets_found),
            "secrets": secrets_found,
        }
    
    def scan_repository(
        self,
        repo_url: str,
        organization_id: int
    ) -> Dict[str, Any]:
        """
        Scan a specific GitHub repository.
        
        Args:
            repo_url: Full GitHub repository URL
            organization_id: Internal organization ID
        
        Returns:
            Scan results with found secrets
        """
        if not self.is_available():
            return {"error": "GitHub scanning not available", "secrets": []}
        
        # Extract owner/repo from URL
        match = re.search(r"github\.com/([^/]+)/([^/]+)", repo_url)
        if not match:
            return {"error": "Invalid GitHub URL", "secrets": []}
        
        owner, repo_name = match.groups()
        repo_name = repo_name.rstrip(".git")
        
        try:
            repo = self.github.get_repo(f"{owner}/{repo_name}")
        except GithubException as e:
            logger.error(f"Failed to get repository {owner}/{repo_name}: {e}")
            return {"error": str(e), "secrets": []}
        
        secrets_found = self._scan_repository(repo)
        
        # Store findings
        if secrets_found:
            self._store_findings(secrets_found, f"{owner}/{repo_name}", organization_id)
        
        return {
            "repository": f"{owner}/{repo_name}",
            "secrets_found": len(secrets_found),
            "secrets": secrets_found,
        }
    
    def scan_user(
        self,
        username: str,
        organization_id: int,
        max_repos: int = 50
    ) -> Dict[str, Any]:
        """
        Scan all public repositories of a GitHub user.
        
        Args:
            username: GitHub username
            organization_id: Internal organization ID
            max_repos: Maximum repositories to scan
        
        Returns:
            Scan results
        """
        if not self.is_available():
            return {"error": "GitHub scanning not available", "secrets": []}
        
        try:
            user = self.github.get_user(username)
        except GithubException as e:
            logger.error(f"Failed to get user {username}: {e}")
            return {"error": str(e), "secrets": []}
        
        secrets_found = []
        repos_scanned = 0
        
        for repo in user.get_repos(type="public")[:max_repos]:
            try:
                repo_secrets = self._scan_repository(repo)
                secrets_found.extend(repo_secrets)
                repos_scanned += 1
            except Exception as e:
                logger.warning(f"Error scanning repo {repo.name}: {e}")
        
        if secrets_found:
            self._store_findings(secrets_found, username, organization_id)
        
        return {
            "user": username,
            "repos_scanned": repos_scanned,
            "secrets_found": len(secrets_found),
            "secrets": secrets_found,
        }
    
    def _scan_repository(self, repo) -> List[Dict[str, Any]]:
        """Scan a repository for secrets."""
        secrets = []
        
        # Files to scan
        sensitive_files = [
            ".env", ".env.local", ".env.production",
            "config.json", "config.yaml", "config.yml",
            "settings.json", "settings.py",
            "credentials.json", "secrets.json",
            "docker-compose.yml", "docker-compose.yaml",
            ".npmrc", ".pypirc",
        ]
        
        # Scan repository files
        try:
            contents = repo.get_contents("")
            files_to_scan = []
            
            while contents:
                file_content = contents.pop(0)
                if file_content.type == "dir":
                    # Skip common non-interesting directories
                    if file_content.name not in ["node_modules", "vendor", ".git", "__pycache__"]:
                        try:
                            contents.extend(repo.get_contents(file_content.path))
                        except:
                            pass
                else:
                    # Check if file should be scanned
                    if (file_content.name in sensitive_files or
                        file_content.name.endswith((".env", ".json", ".yaml", ".yml", ".py", ".js", ".ts"))):
                        files_to_scan.append(file_content)
            
            # Limit files to scan
            for file_content in files_to_scan[:100]:
                try:
                    file_secrets = self._scan_file(repo, file_content)
                    secrets.extend(file_secrets)
                except Exception as e:
                    logger.debug(f"Error scanning file {file_content.path}: {e}")
        
        except GithubException as e:
            logger.warning(f"Error accessing repository contents: {e}")
        
        # Scan recent commits
        try:
            for commit in repo.get_commits()[:20]:
                commit_secrets = self._scan_commit(repo, commit)
                secrets.extend(commit_secrets)
        except Exception as e:
            logger.debug(f"Error scanning commits: {e}")
        
        return secrets
    
    def _scan_file(self, repo, file_content) -> List[Dict[str, Any]]:
        """Scan a file for secrets."""
        secrets = []
        
        try:
            # Get file content
            if file_content.size > 1000000:  # Skip files larger than 1MB
                return []
            
            content = file_content.decoded_content.decode("utf-8", errors="ignore")
            
            for secret_type, config in SECRET_PATTERNS.items():
                matches = re.finditer(config["pattern"], content)
                for match in matches:
                    # Avoid false positives
                    matched_text = match.group()
                    if self._is_likely_secret(matched_text, secret_type):
                        secrets.append({
                            "type": secret_type,
                            "description": config["description"],
                            "severity": config["severity"].value,
                            "repository": repo.full_name,
                            "file": file_content.path,
                            "line": content[:match.start()].count("\n") + 1,
                            "match": self._redact_secret(matched_text),
                            "url": file_content.html_url,
                            "found_at": datetime.utcnow().isoformat(),
                        })
        
        except Exception as e:
            logger.debug(f"Error scanning file content: {e}")
        
        return secrets
    
    def _scan_commit(self, repo, commit) -> List[Dict[str, Any]]:
        """Scan a commit for secrets."""
        secrets = []
        
        try:
            for file in commit.files:
                if file.patch:
                    for secret_type, config in SECRET_PATTERNS.items():
                        matches = re.finditer(config["pattern"], file.patch)
                        for match in matches:
                            matched_text = match.group()
                            if self._is_likely_secret(matched_text, secret_type):
                                secrets.append({
                                    "type": secret_type,
                                    "description": config["description"],
                                    "severity": config["severity"].value,
                                    "repository": repo.full_name,
                                    "file": file.filename,
                                    "commit": commit.sha[:8],
                                    "commit_url": commit.html_url,
                                    "match": self._redact_secret(matched_text),
                                    "found_at": datetime.utcnow().isoformat(),
                                })
        
        except Exception as e:
            logger.debug(f"Error scanning commit: {e}")
        
        return secrets
    
    def _is_likely_secret(self, text: str, secret_type: str) -> bool:
        """Check if a match is likely a real secret (not a placeholder)."""
        return is_likely_secret(text, secret_type)
    
    def _redact_secret(self, text: str) -> str:
        """Redact the middle of a secret for safe storage/display."""
        if len(text) <= 8:
            return text[:2] + "*" * (len(text) - 2)
        
        return text[:4] + "*" * (len(text) - 8) + text[-4:]
    
    def _store_findings(
        self,
        secrets: List[Dict[str, Any]],
        source: str,
        organization_id: int
    ):
        """Store findings as vulnerabilities in the database."""
        db = SessionLocal()
        try:
            # Find or create an asset for the GitHub source
            asset = db.query(Asset).filter(
                Asset.value == f"github:{source}",
                Asset.organization_id == organization_id
            ).first()
            
            if not asset:
                asset = Asset(
                    value=f"github:{source}",
                    asset_type=AssetType.URL,
                    organization_id=organization_id,
                    is_active=True,
                    first_seen=datetime.utcnow(),
                )
                db.add(asset)
                db.commit()
                db.refresh(asset)
            
            # Create vulnerabilities for each secret
            for secret in secrets:
                vuln = Vulnerability(
                    title=f"Exposed {secret['description']} in GitHub",
                    description=(
                        f"Found exposed {secret['description']} in repository {secret['repository']}.\n\n"
                        f"File: {secret.get('file', 'N/A')}\n"
                        f"Match (redacted): {secret['match']}\n"
                        f"URL: {secret.get('url', secret.get('commit_url', 'N/A'))}"
                    ),
                    severity=Severity(secret["severity"]),
                    asset_id=asset.id,
                    detected_by="github_secret_scanner",
                    status=VulnerabilityStatus.OPEN,
                    evidence=f"Pattern matched: {secret['type']}",
                    remediation=(
                        "1. Immediately rotate or revoke the exposed credential\n"
                        "2. Remove the secret from the repository history (use git filter-branch or BFG)\n"
                        "3. Add the file to .gitignore to prevent future commits\n"
                        "4. Use environment variables or secret management tools instead"
                    ),
                    first_detected=datetime.utcnow(),
                    last_detected=datetime.utcnow(),
                    metadata_={
                        "secret_type": secret["type"],
                        "repository": secret["repository"],
                        "file": secret.get("file"),
                        "line": secret.get("line"),
                    },
                )
                db.add(vuln)
            
            db.commit()
            logger.info(f"Stored {len(secrets)} GitHub secret findings for {source}")
        
        except Exception as e:
            logger.error(f"Error storing findings: {e}")
            db.rollback()
        finally:
            db.close()


# Global service instance
_github_service: Optional[GitHubSecretService] = None


def get_github_secret_service() -> GitHubSecretService:
    """Get or create the global GitHub secret service."""
    global _github_service
    if _github_service is None:
        _github_service = GitHubSecretService()
    return _github_service
