"""Judah Loom API — CRUD, versions, scripts, runs, artifacts."""

from __future__ import annotations

import json
import logging
import mimetypes
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user, require_analyst
from app.db.database import get_db
from app.models.user import User
from app.models.workflow import (
    Workflow,
    WorkflowVersion,
    WorkflowScript,
    WorkflowRun,
    WorkflowNodeRun,
    WorkflowArtifact,
    WorkflowKind,
    WorkflowRunStatus,
)
from app.schemas.workflow import (
    WorkflowCreate,
    WorkflowUpdate,
    WorkflowResponse,
    WorkflowSummary,
    WorkflowVersionCreate,
    WorkflowVersionResponse,
    WorkflowScriptCreate,
    WorkflowScriptUpdate,
    WorkflowScriptResponse,
    WorkflowRunCreate,
    WorkflowRunResponse,
    WorkflowRunSummary,
    WorkflowArtifactResponse,
    ToolDefinition,
)
from app.services.workflow.tool_catalog import list_tools, get_tool
from app.services.workflow.seed import seed_library_workflows

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Workflows"])

SQS_QUEUE_URL = os.getenv("SQS_QUEUE_URL")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
_sqs_client = None


def get_sqs_client():
    global _sqs_client
    if _sqs_client is None and SQS_QUEUE_URL:
        try:
            import boto3

            _sqs_client = boto3.client("sqs", region_name=AWS_REGION)
        except Exception as e:
            logger.error("Failed to initialize SQS client: %s", e)
    return _sqs_client


def check_org_access(user: User, org_id: int) -> bool:
    if user.is_superuser:
        return True
    return user.organization_id == org_id


def _require_org(user: User, org_id: int) -> None:
    if not check_org_access(user, org_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")


def _port_dump(ports) -> List[Any]:
    if not ports:
        return []
    out = []
    for p in ports:
        if hasattr(p, "model_dump"):
            out.append(p.model_dump())
        elif isinstance(p, dict):
            out.append(p)
        else:
            out.append(p)
    return out


def _version_response(v: WorkflowVersion) -> WorkflowVersionResponse:
    return WorkflowVersionResponse(
        id=v.id,
        workflow_id=v.workflow_id,
        version=v.version,
        graph=v.graph or {},
        input_ports=v.input_ports or [],
        output_ports=v.output_ports or [],
        created_by=v.created_by,
        created_at=v.created_at,
    )


def _workflow_response(wf: Workflow, db: Session, include_version: bool = True) -> WorkflowResponse:
    latest = None
    if include_version and wf.latest_version_id:
        ver = db.query(WorkflowVersion).filter(WorkflowVersion.id == wf.latest_version_id).first()
        if ver:
            latest = _version_response(ver)
    return WorkflowResponse(
        id=wf.id,
        organization_id=wf.organization_id,
        name=wf.name,
        description=wf.description,
        kind=wf.kind,
        latest_version_id=wf.latest_version_id,
        is_library=bool(wf.is_library),
        created_by=wf.created_by,
        created_at=wf.created_at,
        updated_at=wf.updated_at,
        latest_version=latest,
    )


def send_workflow_run_to_sqs(run: WorkflowRun) -> bool:
    """Notify worker of a pending workflow run."""
    if not SQS_QUEUE_URL:
        logger.debug("SQS_QUEUE_URL not configured; worker will poll DB for workflow runs")
        return False
    sqs = get_sqs_client()
    if not sqs:
        return False
    body = {
        "job_type": "WORKFLOW_RUN",
        "workflow_run_id": run.id,
        "organization_id": run.organization_id,
        "workflow_id": run.workflow_id,
        "version_id": run.version_id,
    }
    try:
        sqs.send_message(
            QueueUrl=SQS_QUEUE_URL,
            MessageBody=json.dumps(body),
            MessageAttributes={
                "job_type": {"StringValue": "WORKFLOW_RUN", "DataType": "String"},
                "workflow_run_id": {"StringValue": str(run.id), "DataType": "Number"},
            },
        )
        logger.info("Sent workflow run %s to SQS", run.id)
        return True
    except Exception as e:
        logger.error("Failed to send workflow run %s to SQS: %s", run.id, e)
        return False


# ── Tools ────────────────────────────────────────────────────────────────────

@router.get("/workflow-tools", response_model=List[ToolDefinition])
def get_workflow_tools(current_user: User = Depends(get_current_active_user)):
    return list_tools()


@router.get("/workflow-tools/{tool_id}", response_model=ToolDefinition)
def get_workflow_tool(tool_id: str, current_user: User = Depends(get_current_active_user)):
    tool = get_tool(tool_id)
    if not tool:
        raise HTTPException(status_code=404, detail="Tool not found")
    return tool


# ── Workflows ────────────────────────────────────────────────────────────────

@router.get("/workflows", response_model=List[WorkflowSummary])
def list_workflows(
    organization_id: Optional[int] = None,
    kind: Optional[WorkflowKind] = None,
    seed_library: bool = Query(False, description="Ensure library templates exist for org"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    org_id = organization_id or current_user.organization_id
    if not org_id:
        raise HTTPException(status_code=400, detail="organization_id required")
    _require_org(current_user, org_id)

    if seed_library:
        seed_library_workflows(db, org_id)

    q = db.query(Workflow).filter(Workflow.organization_id == org_id)
    if kind:
        q = q.filter(Workflow.kind == kind)
    rows = q.order_by(Workflow.updated_at.desc()).all()
    return rows


@router.post("/workflows", response_model=WorkflowResponse, status_code=status.HTTP_201_CREATED)
def create_workflow(
    body: WorkflowCreate,
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
):
    _require_org(current_user, body.organization_id)

    wf = Workflow(
        organization_id=body.organization_id,
        name=body.name,
        description=body.description,
        kind=body.kind,
        created_by=current_user.email or current_user.username,
    )
    db.add(wf)
    db.flush()

    graph = body.graph.model_dump() if body.graph else {"nodes": [], "edges": [], "viewport": {"x": 0, "y": 0, "zoom": 1}}
    version = WorkflowVersion(
        workflow_id=wf.id,
        version=1,
        graph=graph,
        input_ports=_port_dump(body.input_ports),
        output_ports=_port_dump(body.output_ports),
        created_by=current_user.email or current_user.username,
    )
    db.add(version)
    db.flush()
    wf.latest_version_id = version.id
    db.commit()
    db.refresh(wf)
    return _workflow_response(wf, db)


@router.get("/workflows/{workflow_id}", response_model=WorkflowResponse)
def get_workflow(
    workflow_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    wf = db.query(Workflow).filter(Workflow.id == workflow_id).first()
    if not wf:
        raise HTTPException(status_code=404, detail="Workflow not found")
    _require_org(current_user, wf.organization_id)
    return _workflow_response(wf, db)


@router.patch("/workflows/{workflow_id}", response_model=WorkflowResponse)
def update_workflow(
    workflow_id: int,
    body: WorkflowUpdate,
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
):
    wf = db.query(Workflow).filter(Workflow.id == workflow_id).first()
    if not wf:
        raise HTTPException(status_code=404, detail="Workflow not found")
    _require_org(current_user, wf.organization_id)
    if body.name is not None:
        wf.name = body.name
    if body.description is not None:
        wf.description = body.description
    wf.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(wf)
    return _workflow_response(wf, db)


@router.delete("/workflows/{workflow_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_workflow(
    workflow_id: int,
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
):
    wf = db.query(Workflow).filter(Workflow.id == workflow_id).first()
    if not wf:
        raise HTTPException(status_code=404, detail="Workflow not found")
    _require_org(current_user, wf.organization_id)
    db.delete(wf)
    db.commit()
    return None


@router.post(
    "/workflows/{workflow_id}/versions",
    response_model=WorkflowVersionResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_version(
    workflow_id: int,
    body: WorkflowVersionCreate,
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
):
    wf = db.query(Workflow).filter(Workflow.id == workflow_id).first()
    if not wf:
        raise HTTPException(status_code=404, detail="Workflow not found")
    _require_org(current_user, wf.organization_id)

    latest_num = (
        db.query(WorkflowVersion.version)
        .filter(WorkflowVersion.workflow_id == workflow_id)
        .order_by(WorkflowVersion.version.desc())
        .first()
    )
    next_ver = (latest_num[0] if latest_num else 0) + 1

    version = WorkflowVersion(
        workflow_id=workflow_id,
        version=next_ver,
        graph=body.graph.model_dump(),
        input_ports=_port_dump(body.input_ports),
        output_ports=_port_dump(body.output_ports),
        created_by=current_user.email or current_user.username,
    )
    db.add(version)
    db.flush()
    wf.latest_version_id = version.id
    wf.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(version)
    return _version_response(version)


@router.get(
    "/workflows/{workflow_id}/versions/{version_id}",
    response_model=WorkflowVersionResponse,
)
def get_version(
    workflow_id: int,
    version_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    wf = db.query(Workflow).filter(Workflow.id == workflow_id).first()
    if not wf:
        raise HTTPException(status_code=404, detail="Workflow not found")
    _require_org(current_user, wf.organization_id)
    ver = (
        db.query(WorkflowVersion)
        .filter(WorkflowVersion.id == version_id, WorkflowVersion.workflow_id == workflow_id)
        .first()
    )
    if not ver:
        raise HTTPException(status_code=404, detail="Version not found")
    return _version_response(ver)


@router.post("/workflows/seed-library", response_model=List[WorkflowSummary])
def seed_library_for_org(
    organization_id: Optional[int] = None,
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
):
    org_id = organization_id or current_user.organization_id
    if not org_id:
        raise HTTPException(status_code=400, detail="organization_id required")
    _require_org(current_user, org_id)
    return seed_library_workflows(db, org_id)


# ── Scripts ──────────────────────────────────────────────────────────────────

@router.get("/workflow-scripts", response_model=List[WorkflowScriptResponse])
def list_scripts(
    organization_id: Optional[int] = None,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    org_id = organization_id or current_user.organization_id
    if not org_id:
        raise HTTPException(status_code=400, detail="organization_id required")
    _require_org(current_user, org_id)
    return (
        db.query(WorkflowScript)
        .filter(WorkflowScript.organization_id == org_id)
        .order_by(WorkflowScript.name.asc())
        .all()
    )


@router.post(
    "/workflow-scripts",
    response_model=WorkflowScriptResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_script(
    body: WorkflowScriptCreate,
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
):
    _require_org(current_user, body.organization_id)
    script = WorkflowScript(
        organization_id=body.organization_id,
        name=body.name,
        description=body.description,
        language=body.language,
        source=body.source or "",
        input_ports=_port_dump(body.input_ports),
        output_ports=_port_dump(body.output_ports),
        params_schema=body.params_schema or {},
        created_by=current_user.email or current_user.username,
    )
    db.add(script)
    db.commit()
    db.refresh(script)
    return script


@router.get("/workflow-scripts/{script_id}", response_model=WorkflowScriptResponse)
def get_script(
    script_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    script = db.query(WorkflowScript).filter(WorkflowScript.id == script_id).first()
    if not script:
        raise HTTPException(status_code=404, detail="Script not found")
    _require_org(current_user, script.organization_id)
    return script


@router.patch("/workflow-scripts/{script_id}", response_model=WorkflowScriptResponse)
def update_script(
    script_id: int,
    body: WorkflowScriptUpdate,
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
):
    script = db.query(WorkflowScript).filter(WorkflowScript.id == script_id).first()
    if not script:
        raise HTTPException(status_code=404, detail="Script not found")
    _require_org(current_user, script.organization_id)
    for field in ("name", "description", "language", "source", "params_schema"):
        val = getattr(body, field)
        if val is not None:
            setattr(script, field, val)
    if body.input_ports is not None:
        script.input_ports = _port_dump(body.input_ports)
    if body.output_ports is not None:
        script.output_ports = _port_dump(body.output_ports)
    script.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(script)
    return script


@router.delete("/workflow-scripts/{script_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_script(
    script_id: int,
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
):
    script = db.query(WorkflowScript).filter(WorkflowScript.id == script_id).first()
    if not script:
        raise HTTPException(status_code=404, detail="Script not found")
    _require_org(current_user, script.organization_id)
    db.delete(script)
    db.commit()
    return None


# ── Runs ─────────────────────────────────────────────────────────────────────

@router.post(
    "/workflows/{workflow_id}/run",
    response_model=WorkflowRunResponse,
    status_code=status.HTTP_201_CREATED,
)
def run_workflow(
    workflow_id: int,
    body: WorkflowRunCreate,
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
):
    wf = db.query(Workflow).filter(Workflow.id == workflow_id).first()
    if not wf:
        raise HTTPException(status_code=404, detail="Workflow not found")
    _require_org(current_user, wf.organization_id)

    version_id = body.version_id or wf.latest_version_id
    if not version_id:
        raise HTTPException(status_code=400, detail="Workflow has no version to run")
    ver = (
        db.query(WorkflowVersion)
        .filter(WorkflowVersion.id == version_id, WorkflowVersion.workflow_id == workflow_id)
        .first()
    )
    if not ver:
        raise HTTPException(status_code=404, detail="Version not found")

    run = WorkflowRun(
        workflow_id=workflow_id,
        version_id=version_id,
        organization_id=wf.organization_id,
        status=WorkflowRunStatus.PENDING,
        inputs=body.inputs or {},
        continue_on_error=body.continue_on_error,
        started_by=current_user.email or current_user.username,
    )
    db.add(run)
    db.commit()
    db.refresh(run)

    send_workflow_run_to_sqs(run)

    return WorkflowRunResponse(
        id=run.id,
        workflow_id=run.workflow_id,
        version_id=run.version_id,
        organization_id=run.organization_id,
        status=run.status,
        inputs=run.inputs or {},
        continue_on_error=bool(run.continue_on_error),
        progress=run.progress or 0,
        current_step=run.current_step,
        error_message=run.error_message,
        started_by=run.started_by,
        started_at=run.started_at,
        completed_at=run.completed_at,
        created_at=run.created_at,
        node_runs=[],
        artifacts=[],
    )


@router.get("/workflow-runs", response_model=List[WorkflowRunSummary])
def list_runs(
    organization_id: Optional[int] = None,
    workflow_id: Optional[int] = None,
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    org_id = organization_id or current_user.organization_id
    if not org_id:
        raise HTTPException(status_code=400, detail="organization_id required")
    _require_org(current_user, org_id)
    q = db.query(WorkflowRun).filter(WorkflowRun.organization_id == org_id)
    if workflow_id:
        q = q.filter(WorkflowRun.workflow_id == workflow_id)
    return q.order_by(WorkflowRun.created_at.desc()).limit(limit).all()


@router.get("/workflow-runs/{run_id}", response_model=WorkflowRunResponse)
def get_run(
    run_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    run = db.query(WorkflowRun).filter(WorkflowRun.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    _require_org(current_user, run.organization_id)

    node_runs = (
        db.query(WorkflowNodeRun)
        .filter(WorkflowNodeRun.run_id == run_id)
        .order_by(WorkflowNodeRun.id.asc())
        .all()
    )
    artifacts = (
        db.query(WorkflowArtifact)
        .filter(WorkflowArtifact.run_id == run_id)
        .order_by(WorkflowArtifact.id.asc())
        .all()
    )
    return WorkflowRunResponse(
        id=run.id,
        workflow_id=run.workflow_id,
        version_id=run.version_id,
        organization_id=run.organization_id,
        status=run.status,
        inputs=run.inputs or {},
        continue_on_error=bool(run.continue_on_error),
        progress=run.progress or 0,
        current_step=run.current_step,
        error_message=run.error_message,
        started_by=run.started_by,
        started_at=run.started_at,
        completed_at=run.completed_at,
        created_at=run.created_at,
        node_runs=node_runs,
        artifacts=artifacts,
    )


@router.post("/workflow-runs/{run_id}/cancel", response_model=WorkflowRunSummary)
def cancel_run(
    run_id: int,
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
):
    run = db.query(WorkflowRun).filter(WorkflowRun.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    _require_org(current_user, run.organization_id)
    if run.status in (WorkflowRunStatus.COMPLETED, WorkflowRunStatus.FAILED, WorkflowRunStatus.CANCELLED):
        raise HTTPException(status_code=400, detail=f"Run already {run.status.value}")
    run.status = WorkflowRunStatus.CANCELLED
    run.completed_at = datetime.utcnow()
    run.current_step = "cancelled"
    db.commit()
    db.refresh(run)
    return run


@router.get("/workflow-artifacts/{artifact_id}", response_model=WorkflowArtifactResponse)
def get_artifact_meta(
    artifact_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    art = db.query(WorkflowArtifact).filter(WorkflowArtifact.id == artifact_id).first()
    if not art:
        raise HTTPException(status_code=404, detail="Artifact not found")
    _require_org(current_user, art.organization_id)
    return art


@router.get("/workflow-artifacts/{artifact_id}/content")
def download_artifact(
    artifact_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    art = db.query(WorkflowArtifact).filter(WorkflowArtifact.id == artifact_id).first()
    if not art:
        raise HTTPException(status_code=404, detail="Artifact not found")
    _require_org(current_user, art.organization_id)
    if not art.path or not os.path.isfile(art.path):
        raise HTTPException(status_code=404, detail="Artifact file missing")
    media = art.content_type or mimetypes.guess_type(art.path)[0] or "application/octet-stream"
    return FileResponse(
        art.path,
        media_type=media,
        filename=art.filename or os.path.basename(art.path),
    )
