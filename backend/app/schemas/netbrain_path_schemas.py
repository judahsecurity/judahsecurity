"""Request and response shapes for NetBrain path evidence."""

from datetime import datetime

from pydantic import BaseModel, Field, model_validator


class NetBrainPathCreate(BaseModel):
    source_asset_id: int = Field(gt=0)
    target_asset_id: int = Field(gt=0)
    source_ip: str | None = None
    target_ip: str | None = None
    gateway_ip: str | None = None
    gateway_device: str | None = None
    gateway_interface: str | None = None
    protocol: int = Field(default=4, description="NetBrain path protocol; 4 IPv4 or 6 TCP.")
    destination_port: int = Field(default=0, ge=0, le=65535)
    is_live: bool = False

    @model_validator(mode="after")
    def validate_protocol(self):
        if self.protocol not in (4, 6):
            raise ValueError("Choose IPv4 (4) or TCP (6).")
        if self.protocol == 4 and self.destination_port:
            raise ValueError("IPv4 path calculations cannot specify a destination port.")
        fields = (self.gateway_ip, self.gateway_device, self.gateway_interface)
        if any(fields) and not all(fields):
            raise ValueError("Specify all gateway fields, or leave all blank for automatic selection.")
        return self


class NetBrainPathResponse(BaseModel):
    id: int
    organization_id: int
    source_integration_id: int
    source_asset_id: int
    target_asset_id: int
    source_ip: str
    target_ip: str
    source_scope_id: str
    target_scope_id: str
    tenant_id: str
    domain_id: str
    gateway_ip: str
    gateway_device: str
    gateway_interface: str
    protocol: int
    destination_port: int
    is_live: bool
    status: str
    hop_list: list[dict]
    error: str | None
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None
    graph_projected_at: datetime | None

    model_config = {"from_attributes": True}
