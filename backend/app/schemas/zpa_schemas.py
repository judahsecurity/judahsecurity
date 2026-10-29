"""API shapes for ZPA Log Streaming Service ingestion."""

from datetime import datetime

from pydantic import BaseModel, Field


class ZpaIntegrationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)


class ZpaIntegrationUpdate(BaseModel):
    is_active: bool


class ZpaIntegrationResponse(BaseModel):
    id: int
    organization_id: int
    name: str
    is_active: bool
    created_at: datetime
    last_ingest_at: datetime | None

    model_config = {"from_attributes": True}


class ZpaIntegrationSecret(ZpaIntegrationResponse):
    ingest_token: str = Field(description="Shown once. Send as X-ZPA-Ingest-Token from the collector.")


class ZpaIngestResult(BaseModel):
    received: int
    accepted: int
    duplicates: int
    ignored: int
    assets_created: int
