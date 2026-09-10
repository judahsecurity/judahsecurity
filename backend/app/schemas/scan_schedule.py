"""Scan Schedule schemas for request/response validation."""

from datetime import datetime
from typing import Optional, List, Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from pydantic import BaseModel, Field, field_validator, model_validator

from app.models.scan_schedule import ScheduleFrequency


class ScanScheduleBase(BaseModel):
    """Base scan schedule schema."""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    scan_type: str
    frequency: ScheduleFrequency = ScheduleFrequency.DAILY


class ScanScheduleCreate(ScanScheduleBase):
    """Schema for creating a new scan schedule."""
    organization_id: int
    targets: List[str] = []
    label_ids: List[int] = []
    match_all_labels: bool = False
    config: dict[str, Any] = {}
    
    run_at_hour: int = Field(default=2, ge=0, le=23)
    run_on_day: Optional[int] = Field(default=None, ge=0, le=31)
    cron_expression: Optional[str] = None
    timezone: str = "UTC"
    
    is_enabled: bool = True
    notify_on_completion: bool = False
    notify_on_findings: bool = True
    notification_emails: List[str] = []

    @field_validator("timezone")
    @classmethod
    def validate_timezone(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except ZoneInfoNotFoundError as exc:
            raise ValueError(f"Unknown timezone '{value}'") from exc
        return value

    @model_validator(mode="after")
    def validate_frequency_fields(self):
        if self.frequency == ScheduleFrequency.WEEKLY and self.run_on_day is not None and self.run_on_day > 6:
            raise ValueError("Weekly run_on_day must be between 0 and 6")
        if self.frequency == ScheduleFrequency.MONTHLY and self.run_on_day == 0:
            raise ValueError("Monthly run_on_day must be between 1 and 31")
        if self.frequency == ScheduleFrequency.CUSTOM and not self.cron_expression:
            raise ValueError("Custom schedules require a cron_expression")
        return self


class ScanScheduleUpdate(BaseModel):
    """Schema for updating a scan schedule."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    scan_type: Optional[str] = None
    targets: Optional[List[str]] = None
    label_ids: Optional[List[int]] = None
    match_all_labels: Optional[bool] = None
    config: Optional[dict[str, Any]] = None
    
    frequency: Optional[ScheduleFrequency] = None
    run_at_hour: Optional[int] = Field(None, ge=0, le=23)
    run_on_day: Optional[int] = Field(None, ge=0, le=31)
    cron_expression: Optional[str] = None
    timezone: Optional[str] = None
    
    is_enabled: Optional[bool] = None
    notify_on_completion: Optional[bool] = None
    notify_on_findings: Optional[bool] = None
    notification_emails: Optional[List[str]] = None

    @field_validator("timezone")
    @classmethod
    def validate_timezone(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        try:
            ZoneInfo(value)
        except ZoneInfoNotFoundError as exc:
            raise ValueError(f"Unknown timezone '{value}'") from exc
        return value


class ScanScheduleResponse(ScanScheduleBase):
    """Schema for scan schedule response."""
    id: int
    organization_id: int
    targets: List[str] = []
    label_ids: List[int] = []
    match_all_labels: bool = False
    config: dict[str, Any] = {}
    
    run_at_hour: int
    run_on_day: Optional[int] = None
    cron_expression: Optional[str] = None
    timezone: str
    
    is_enabled: bool
    last_run_at: Optional[datetime] = None
    next_run_at: Optional[datetime] = None
    last_scan_id: Optional[int] = None
    run_count: int = 0
    
    consecutive_failures: int = 0
    last_error: Optional[str] = None
    
    notify_on_completion: bool
    notify_on_findings: bool
    notification_emails: List[str] = []
    
    created_at: datetime
    updated_at: datetime
    created_by: Optional[str] = None
    
    class Config:
        from_attributes = True


class ScanScheduleSummary(BaseModel):
    """Summary of scan schedules."""
    total_schedules: int = 0
    enabled_schedules: int = 0
    disabled_schedules: int = 0
    schedules_by_type: dict[str, int] = {}
    schedules_by_frequency: dict[str, int] = {}
    upcoming_scans: List[dict] = []


class ManualTriggerRequest(BaseModel):
    """Request to manually trigger a scheduled scan."""
    override_targets: Optional[List[str]] = None
    override_config: Optional[dict[str, Any]] = None


