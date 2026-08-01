"""Pydantic schemas for screenshot management."""

from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class ScreenshotBase(BaseModel):
    """Base schema for screenshot data."""
    url: str


class ScreenshotCreate(ScreenshotBase):
    """Schema for creating a screenshot request."""
    asset_id: int


class ScreenshotResponse(BaseModel):
    """Schema for screenshot response."""
    id: int
    asset_id: int
    url: str
    status: str
    file_path: Optional[str] = None
    thumbnail_path: Optional[str] = None
    source_path: Optional[str] = None
    http_status: Optional[int] = None
    page_title: Optional[str] = None
    server_header: Optional[str] = None
    response_headers: Optional[Dict[str, str]] = None
    default_creds_detected: bool = False
    default_creds_info: Optional[Dict[str, Any]] = None
    category: Optional[str] = None
    width: Optional[int] = None
    height: Optional[int] = None
    file_size: Optional[int] = None
    image_hash: Optional[str] = None
    has_changed: bool = False
    change_percentage: Optional[int] = None
    captured_at: Optional[datetime] = None
    error_message: Optional[str] = None
    
    class Config:
        from_attributes = True


class ScreenshotHistoryResponse(BaseModel):
    """Schema for screenshot history."""
    asset_id: int
    asset_value: str
    total_screenshots: int
    screenshots: List[ScreenshotResponse]
    
    class Config:
        from_attributes = True


# Bulk screenshot request
class BulkScreenshotRequest(BaseModel):
    """Request schema for capturing screenshots of multiple assets."""
    organization_id: int
    asset_ids: Optional[List[int]] = Field(default=None, description="Specific asset IDs to screenshot")
    asset_types: Optional[List[str]] = Field(
        default=["domain", "subdomain", "url"],
        description="Asset types to include"
    )
    include_tags: Optional[List[str]] = Field(default=None, description="Only assets with these tags")
    exclude_tags: Optional[List[str]] = Field(default=None, description="Skip assets with these tags")
    
    # EyeWitness options
    timeout: int = Field(default=30, ge=5, le=120, description="Timeout per URL in seconds")
    threads: int = Field(default=5, ge=1, le=20, description="Number of concurrent threads")
    delay: int = Field(default=0, ge=0, le=30, description="Delay between requests")
    jitter: int = Field(default=0, ge=0, le=10, description="Random jitter")


class BulkScreenshotResponse(BaseModel):
    """Response schema for bulk screenshot operation."""
    scan_id: int
    total_urls: int
    successful: int
    failed: int
    results: List[ScreenshotResponse]


# Schedule schemas
class ScreenshotScheduleCreate(BaseModel):
    """Schema for creating a screenshot schedule."""
    organization_id: int
    name: str
    description: Optional[str] = None
    frequency: str = Field(default="daily", pattern="^(daily|weekly|monthly|custom)$")
    cron_expression: Optional[str] = None
    
    asset_types: List[str] = Field(default=["domain", "subdomain", "url"])
    include_tags: Optional[List[str]] = None
    exclude_tags: Optional[List[str]] = None
    
    timeout: int = Field(default=30, ge=5, le=120)
    threads: int = Field(default=5, ge=1, le=20)
    delay: int = Field(default=0, ge=0, le=30)
    jitter: int = Field(default=0, ge=0, le=10)


class ScreenshotScheduleUpdate(BaseModel):
    """Schema for updating a screenshot schedule."""
    name: Optional[str] = None
    description: Optional[str] = None
    frequency: Optional[str] = None
    cron_expression: Optional[str] = None
    is_active: Optional[bool] = None
    
    asset_types: Optional[List[str]] = None
    include_tags: Optional[List[str]] = None
    exclude_tags: Optional[List[str]] = None
    
    timeout: Optional[int] = None
    threads: Optional[int] = None
    delay: Optional[int] = None
    jitter: Optional[int] = None


class ScreenshotScheduleResponse(BaseModel):
    """Response schema for screenshot schedule."""
    id: int
    organization_id: int
    name: str
    description: Optional[str] = None
    frequency: str
    cron_expression: Optional[str] = None
    is_active: bool
    
    asset_types: List[str]
    include_tags: Optional[List[str]] = None
    exclude_tags: Optional[List[str]] = None
    
    timeout: int
    threads: int
    delay: int
    jitter: int
    
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    total_runs: int
    successful_captures: int
    failed_captures: int
    
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


# Report schemas
class ScreenshotSummaryResponse(BaseModel):
    """Summary of screenshots for an organization."""
    organization_id: int
    total_screenshots: int
    total_assets_with_screenshots: int
    successful_screenshots: int
    failed_screenshots: int
    screenshots_today: int
    screenshots_this_week: int
    assets_with_changes: int
    storage_used_mb: float
    categories: Dict[str, int]


class ScreenshotChangeReport(BaseModel):
    """Report of visual changes detected."""
    asset_id: int
    asset_value: str
    previous_screenshot_id: int
    current_screenshot_id: int
    change_percentage: int
    previous_captured_at: datetime
    current_captured_at: datetime
    previous_file_path: str
    current_file_path: str


class ScreenshotChangesResponse(BaseModel):
    """Response with list of detected changes."""
    organization_id: int
    since: datetime
    total_changes: int
    changes: List[ScreenshotChangeReport]


# EyeWitness status
class EyeWitnessStatusResponse(BaseModel):
    """Status of screenshot capture tooling (Playwright preferred, EyeWitness fallback)."""
    installed: bool
    version: Optional[str] = None
    path: str
    venv_path: str
    error: Optional[str] = None
    # Expanded capture-health fields (backward compatible)
    capture_available: bool = False
    preferred_engine: Optional[str] = None  # "playwright" | "eyewitness" | None
    playwright_available: bool = False
    eyewitness_installed: bool = False
    screenshots_dir: Optional[str] = None
    screenshots_dir_writable: Optional[bool] = None















