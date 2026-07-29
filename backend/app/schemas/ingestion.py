"""
Ingestion API Schemas

Schemas for the external agent findings ingestion API.
Used by Aegis Vanguard agents and other external scanners to submit
findings back to the ASM platform.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field

from app.schemas.unified_results import UnifiedFinding, Severity, ResultType, ConfidenceLevel


class AgentType(str, Enum):
    AEGIS_VANGUARD = "aegis_vanguard"
    EXTERNAL_SCANNER = "external_scanner"
    CI_CD = "ci_cd"
    CUSTOM = "custom"


class IngestionBatchRequest(BaseModel):
    """Batch submission of findings from an external agent."""

    agent_id: str = Field(..., description="Unique agent identifier")
    agent_type: AgentType = Field(default=AgentType.AEGIS_VANGUARD)
    agent_version: Optional[str] = Field(None, description="Agent software version")

    organization_slug: Optional[str] = Field(None, description="Organization slug (alternative to org ID in API key)")
    scan_context: Optional[str] = Field(None, description="What triggered this scan (e.g., 'scheduled', 'on-demand', 'aegis-chat')")

    findings: List[UnifiedFinding] = Field(..., min_length=1, max_length=5000)
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional context from the agent")

    class Config:
        json_schema_extra = {
            "example": {
                "agent_id": "aegis-vanguard-prod-01",
                "agent_type": "aegis_vanguard",
                "scan_context": "scheduled",
                "findings": [
                    {
                        "type": "subdomain",
                        "source": "subfinder",
                        "target": "example.com",
                        "host": "api.example.com",
                        "title": "Subdomain: api.example.com",
                        "severity": "info",
                    }
                ],
            }
        }


class IngestionFindingResult(BaseModel):
    """Result for a single ingested finding."""
    index: int
    status: str  # "created", "updated", "duplicate", "error"
    asset_id: Optional[int] = None
    finding_id: Optional[int] = None
    message: Optional[str] = None


class IngestionBatchResponse(BaseModel):
    """Response from a batch ingestion request."""
    batch_id: str
    total_submitted: int
    created: int
    updated: int
    duplicates: int
    errors: int
    results: List[IngestionFindingResult]
    processing_time_ms: float


class IngestionHeartbeat(BaseModel):
    """Agent heartbeat for monitoring."""
    agent_id: str
    agent_type: AgentType = AgentType.AEGIS_VANGUARD
    status: str = "healthy"
    uptime_seconds: Optional[float] = None
    findings_sent_total: Optional[int] = None
    last_scan_at: Optional[datetime] = None
    capabilities: List[str] = Field(default_factory=list)


class IngestionHeartbeatResponse(BaseModel):
    """Response to agent heartbeat."""
    ack: bool = True
    server_time: datetime
    agent_id: str
    config: Optional[Dict[str, Any]] = Field(None, description="Dynamic config updates for the agent")


class AgentAPIKeyCreate(BaseModel):
    """Request to create an API key for an external agent."""
    name: str = Field(..., min_length=1, max_length=100, description="Human-readable name for this key")
    agent_type: AgentType = Field(default=AgentType.AEGIS_VANGUARD)
    scopes: List[str] = Field(default=["ingest:findings", "ingest:heartbeat"], description="Permitted scopes")
    expires_in_days: Optional[int] = Field(None, ge=1, le=3650, description="Days until expiration (None = no expiry)")


class AgentAPIKeyResponse(BaseModel):
    """Response containing the generated API key (shown only once)."""
    key_id: str
    api_key: str = Field(..., description="The full API key - store this securely, it won't be shown again")
    name: str
    agent_type: AgentType
    scopes: List[str]
    organization_id: int
    expires_at: Optional[datetime]
    created_at: datetime
