"""Seed library workflows/modules for an organization."""

from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.models.workflow import Workflow, WorkflowKind, WorkflowVersion


def _external_recon_graph() -> Dict[str, Any]:
    return {
        "nodes": [
            {
                "id": "in_domain",
                "type": "primitive",
                "position": {"x": 80, "y": 180},
                "data": {
                    "label": "Seed Domain",
                    "port": {"name": "domain", "type": "STRING", "required": True},
                    "value_key": "domain",
                },
            },
            {
                "id": "discover",
                "type": "tool",
                "position": {"x": 320, "y": 160},
                "data": {
                    "label": "Domain Discovery",
                    "tool_id": "subfinder_discovery",
                    "params": {},
                },
            },
            {
                "id": "probe",
                "type": "tool",
                "position": {"x": 580, "y": 160},
                "data": {
                    "label": "HTTP Probe",
                    "tool_id": "http_probe",
                    "params": {},
                },
            },
            {
                "id": "nuclei",
                "type": "tool",
                "position": {"x": 840, "y": 160},
                "data": {
                    "label": "Nuclei Scan",
                    "tool_id": "nuclei",
                    "params": {"severity": "critical,high,medium"},
                },
            },
        ],
        "edges": [
            {
                "id": "e1",
                "source": "in_domain",
                "sourceHandle": "domain",
                "target": "discover",
                "targetHandle": "domain",
            },
            {
                "id": "e2",
                "source": "discover",
                "sourceHandle": "hosts",
                "target": "probe",
                "targetHandle": "hosts",
            },
            {
                "id": "e3",
                "source": "probe",
                "sourceHandle": "urls",
                "target": "nuclei",
                "targetHandle": "urls",
            },
        ],
        "viewport": {"x": 0, "y": 0, "zoom": 0.9},
    }


def _live_host_probe_graph() -> Dict[str, Any]:
    return {
        "nodes": [
            {
                "id": "in_hosts",
                "type": "primitive",
                "position": {"x": 80, "y": 140},
                "data": {
                    "label": "Hosts",
                    "port": {"name": "hosts", "type": "FILE_LIST", "required": True},
                    "value_key": "hosts",
                },
            },
            {
                "id": "probe",
                "type": "tool",
                "position": {"x": 360, "y": 140},
                "data": {
                    "label": "HTTP Probe",
                    "tool_id": "http_probe",
                    "params": {},
                },
            },
            {
                "id": "out_urls",
                "type": "sink",
                "position": {"x": 640, "y": 140},
                "data": {
                    "label": "Live URLs",
                    "port": {"name": "urls", "type": "FILE_LIST"},
                },
            },
        ],
        "edges": [
            {
                "id": "e1",
                "source": "in_hosts",
                "sourceHandle": "hosts",
                "target": "probe",
                "targetHandle": "hosts",
            },
            {
                "id": "e2",
                "source": "probe",
                "sourceHandle": "urls",
                "target": "out_urls",
                "targetHandle": "urls",
            },
        ],
        "viewport": {"x": 0, "y": 0, "zoom": 1},
    }


def _ensure_library(
    db: Session,
    organization_id: int,
    *,
    name: str,
    description: str,
    kind: WorkflowKind,
    graph: Dict[str, Any],
    input_ports: List[Dict[str, Any]],
    output_ports: Optional[List[Dict[str, Any]]] = None,
) -> Workflow:
    existing = (
        db.query(Workflow)
        .filter(
            Workflow.organization_id == organization_id,
            Workflow.name == name,
            Workflow.is_library.is_(True),
        )
        .first()
    )
    if existing:
        return existing

    wf = Workflow(
        organization_id=organization_id,
        name=name,
        description=description,
        kind=kind,
        is_library=True,
        created_by="system",
    )
    db.add(wf)
    db.flush()

    version = WorkflowVersion(
        workflow_id=wf.id,
        version=1,
        graph=graph,
        input_ports=input_ports,
        output_ports=output_ports or [],
        created_by="system",
    )
    db.add(version)
    db.flush()
    wf.latest_version_id = version.id
    db.commit()
    db.refresh(wf)
    return wf


def seed_library_workflows(db: Session, organization_id: int) -> List[Workflow]:
    """Create default library workflow + module for an org if missing."""
    recon = _ensure_library(
        db,
        organization_id,
        name="External Recon",
        description="Seed domain → discovery → HTTP probe → Nuclei.",
        kind=WorkflowKind.WORKFLOW,
        graph=_external_recon_graph(),
        input_ports=[{"name": "domain", "type": "STRING", "required": True}],
    )
    probe = _ensure_library(
        db,
        organization_id,
        name="Live Host Probe",
        description="Reusable module: hosts → HTTP probe → live URLs.",
        kind=WorkflowKind.MODULE,
        graph=_live_host_probe_graph(),
        input_ports=[{"name": "hosts", "type": "FILE_LIST", "required": True}],
        output_ports=[{"name": "urls", "type": "FILE_LIST"}],
    )
    return [recon, probe]
