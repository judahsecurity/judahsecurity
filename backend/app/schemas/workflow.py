"""Pydantic schemas for the workflow builder API."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from app.models.workflow import (
    WorkflowKind,
    WorkflowRunStatus,
    WorkflowNodeRunStatus,
    ScriptLanguage,
)


# ── Ports / graph ────────────────────────────────────────────────────────────

class PortDef(BaseModel):
    name: str
    type: str = "STRING"  # STRING | BOOLEAN | URL | JSON | FILE | FILE_LIST
    required: bool = False
    description: Optional[str] = None


class GraphDocument(BaseModel):
    nodes: List[Dict[str, Any]] = Field(default_factory=list)
    edges: List[Dict[str, Any]] = Field(default_factory=list)
    viewport: Optional[Dict[str, Any]] = None


# ── Workflow ─────────────────────────────────────────────────────────────────

class WorkflowCreate(BaseModel):
    name: str
    description: Optional[str] = None
    kind: WorkflowKind = WorkflowKind.WORKFLOW
    organization_id: int
    graph: Optional[GraphDocument] = None
    input_ports: Optional[List[PortDef]] = None
    output_ports: Optional[List[PortDef]] = None


class WorkflowUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None


class WorkflowVersionCreate(BaseModel):
    graph: GraphDocument
    input_ports: Optional[List[PortDef]] = None
    output_ports: Optional[List[PortDef]] = None


class WorkflowVersionResponse(BaseModel):
    id: int
    workflow_id: int
    version: int
    graph: Dict[str, Any]
    input_ports: List[Any] = []
    output_ports: List[Any] = []
    created_by: Optional[str] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class WorkflowResponse(BaseModel):
    id: int
    organization_id: int
    name: str
    description: Optional[str] = None
    kind: WorkflowKind
    latest_version_id: Optional[int] = None
    is_library: bool = False
    created_by: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    latest_version: Optional[WorkflowVersionResponse] = None

    class Config:
        from_attributes = True


class WorkflowSummary(BaseModel):
    id: int
    organization_id: int
    name: str
    description: Optional[str] = None
    kind: WorkflowKind
    latest_version_id: Optional[int] = None
    is_library: bool = False
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ── Scripts ──────────────────────────────────────────────────────────────────

class WorkflowScriptCreate(BaseModel):
    name: str
    description: Optional[str] = None
    language: ScriptLanguage = ScriptLanguage.PYTHON
    source: str = ""
    organization_id: int
    input_ports: Optional[List[PortDef]] = None
    output_ports: Optional[List[PortDef]] = None
    params_schema: Optional[Dict[str, Any]] = None


class WorkflowScriptUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    language: Optional[ScriptLanguage] = None
    source: Optional[str] = None
    input_ports: Optional[List[PortDef]] = None
    output_ports: Optional[List[PortDef]] = None
    params_schema: Optional[Dict[str, Any]] = None


class WorkflowScriptResponse(BaseModel):
    id: int
    organization_id: int
    name: str
    description: Optional[str] = None
    language: ScriptLanguage
    source: str
    input_ports: List[Any] = []
    output_ports: List[Any] = []
    params_schema: Dict[str, Any] = {}
    created_by: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ── Runs ─────────────────────────────────────────────────────────────────────

class WorkflowRunCreate(BaseModel):
    inputs: Dict[str, Any] = Field(default_factory=dict)
    continue_on_error: bool = False
    version_id: Optional[int] = None


class WorkflowArtifactResponse(BaseModel):
    id: int
    run_id: int
    node_id: str
    port: str
    path: str
    filename: Optional[str] = None
    content_type: Optional[str] = None
    byte_size: int = 0
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class WorkflowNodeRunResponse(BaseModel):
    id: int
    run_id: int
    node_id: str
    node_type: str
    node_label: Optional[str] = None
    status: WorkflowNodeRunStatus
    inputs: Dict[str, Any] = {}
    outputs: Dict[str, Any] = {}
    logs: Optional[str] = None
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class WorkflowRunResponse(BaseModel):
    id: int
    workflow_id: int
    version_id: int
    organization_id: int
    status: WorkflowRunStatus
    inputs: Dict[str, Any] = {}
    continue_on_error: bool = False
    progress: int = 0
    current_step: Optional[str] = None
    error_message: Optional[str] = None
    started_by: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    node_runs: List[WorkflowNodeRunResponse] = []
    artifacts: List[WorkflowArtifactResponse] = []

    class Config:
        from_attributes = True


class WorkflowRunSummary(BaseModel):
    id: int
    workflow_id: int
    version_id: int
    organization_id: int
    status: WorkflowRunStatus
    progress: int = 0
    current_step: Optional[str] = None
    error_message: Optional[str] = None
    started_by: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ── Tool catalog ─────────────────────────────────────────────────────────────

class ToolParamSchema(BaseModel):
    name: str
    type: str = "string"
    default: Optional[Any] = None
    description: Optional[str] = None
    required: bool = False


class ToolDefinition(BaseModel):
    id: str
    name: str
    description: str
    category: str
    input_ports: List[PortDef]
    output_ports: List[PortDef]
    params: List[ToolParamSchema] = []
