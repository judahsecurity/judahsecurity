"""Public schema for the typed CVE intelligence timeline."""

from typing import Any, Literal

from pydantic import BaseModel, Field


class IntelEventSource(BaseModel):
    id: str
    label: str
    url: str | None = None


class IntelTimelineEvent(BaseModel):
    id: str
    kind: Literal[
        "cve_published",
        "cve_modified",
        "public_exploit_released",
        "known_exploited_added",
        "ransomware_activity_reported",
        "detection_authored",
        "detection_available",
        "detection_enabled",
        "first_asset_detected",
        "remediation_due",
    ]
    category: Literal[
        "publication",
        "modification",
        "exploitation",
        "threat_activity",
        "deadline",
        "detection_authored",
        "detection_available",
        "detection_enabled",
        "asset_detected",
    ]
    timestamp: str
    title: str
    description: str | None = None
    source: IntelEventSource
    deadline: bool = False
    scope: Literal["global", "organization"]
    metadata: dict[str, Any] = Field(default_factory=dict)


class CveDetailResponse(BaseModel):
    cve_id: str
    pdcp: dict[str, Any]
    otx_pulse_count: int
    otx_active_campaign: bool
    detection_tier: str
    is_template: bool
    is_poc: bool
    is_remote: bool
    catalog: dict[str, Any]
    oracle: dict[str, Any]
    intel_updates: list[IntelTimelineEvent]
    exploitation_timeline: list[IntelTimelineEvent]
