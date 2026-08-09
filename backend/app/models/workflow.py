"""Judah Loom models — DAG workflows, scripts, runs, and artifacts."""

import enum
from datetime import datetime

from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    Enum,
    ForeignKey,
    Text,
    JSON,
    Boolean,
    BigInteger,
)
from sqlalchemy.orm import relationship

from app.db.database import Base


class WorkflowKind(str, enum.Enum):
    WORKFLOW = "workflow"
    MODULE = "module"


class WorkflowRunStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class WorkflowNodeRunStatus(str, enum.Enum):
    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


class ScriptLanguage(str, enum.Enum):
    PYTHON = "python"
    BASH = "bash"


class Workflow(Base):
    """Org-scoped workflow or reusable module."""

    __tablename__ = "workflows"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    kind = Column(Enum(WorkflowKind), default=WorkflowKind.WORKFLOW, nullable=False, index=True)
    latest_version_id = Column(Integer, nullable=True)
    is_library = Column(Boolean, default=False)
    created_by = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    versions = relationship(
        "WorkflowVersion",
        back_populates="workflow",
        cascade="all, delete-orphan",
        foreign_keys="WorkflowVersion.workflow_id",
    )
    runs = relationship(
        "WorkflowRun",
        back_populates="workflow",
        cascade="all, delete-orphan",
    )

    def __repr__(self):
        return f"<Workflow {self.kind.value}:{self.name}>"


class WorkflowVersion(Base):
    """Immutable-once-run graph snapshot for a workflow."""

    __tablename__ = "workflow_versions"

    id = Column(Integer, primary_key=True, index=True)
    workflow_id = Column(Integer, ForeignKey("workflows.id", ondelete="CASCADE"), nullable=False, index=True)
    version = Column(Integer, nullable=False, default=1)
    graph = Column(JSON, default=dict)  # {nodes, edges, viewport}
    input_ports = Column(JSON, default=list)
    output_ports = Column(JSON, default=list)
    created_by = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    workflow = relationship("Workflow", back_populates="versions", foreign_keys=[workflow_id])
    runs = relationship("WorkflowRun", back_populates="version")

    def __repr__(self):
        return f"<WorkflowVersion wf={self.workflow_id} v={self.version}>"


class WorkflowScript(Base):
    """Org-scoped Python/Bash script library entry."""

    __tablename__ = "workflow_scripts"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    language = Column(Enum(ScriptLanguage), default=ScriptLanguage.PYTHON, nullable=False)
    source = Column(Text, nullable=False, default="")
    input_ports = Column(JSON, default=list)
    output_ports = Column(JSON, default=list)
    params_schema = Column(JSON, default=dict)
    created_by = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<WorkflowScript {self.name}>"


class WorkflowRun(Base):
    """One execution of a workflow version."""

    __tablename__ = "workflow_runs"

    id = Column(Integer, primary_key=True, index=True)
    workflow_id = Column(Integer, ForeignKey("workflows.id", ondelete="CASCADE"), nullable=False, index=True)
    version_id = Column(Integer, ForeignKey("workflow_versions.id"), nullable=False, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    status = Column(
        Enum(WorkflowRunStatus),
        default=WorkflowRunStatus.PENDING,
        nullable=False,
        index=True,
    )
    inputs = Column(JSON, default=dict)
    continue_on_error = Column(Boolean, default=False)
    progress = Column(Integer, default=0)
    current_step = Column(String(255), nullable=True)
    error_message = Column(Text, nullable=True)
    started_by = Column(String(255), nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    workflow = relationship("Workflow", back_populates="runs")
    version = relationship("WorkflowVersion", back_populates="runs")
    node_runs = relationship(
        "WorkflowNodeRun",
        back_populates="run",
        cascade="all, delete-orphan",
    )
    artifacts = relationship(
        "WorkflowArtifact",
        back_populates="run",
        cascade="all, delete-orphan",
    )

    def __repr__(self):
        return f"<WorkflowRun {self.id} {self.status.value}>"


class WorkflowNodeRun(Base):
    """Per-node execution record within a workflow run."""

    __tablename__ = "workflow_node_runs"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("workflow_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    node_id = Column(String(128), nullable=False, index=True)
    node_type = Column(String(64), nullable=False)
    node_label = Column(String(255), nullable=True)
    status = Column(
        Enum(WorkflowNodeRunStatus),
        default=WorkflowNodeRunStatus.PENDING,
        nullable=False,
        index=True,
    )
    inputs = Column(JSON, default=dict)
    outputs = Column(JSON, default=dict)
    logs = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    run = relationship("WorkflowRun", back_populates="node_runs")

    def __repr__(self):
        return f"<WorkflowNodeRun {self.node_id} {self.status.value}>"


class WorkflowArtifact(Base):
    """File artifact produced by a node during a run."""

    __tablename__ = "workflow_artifacts"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("workflow_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    node_id = Column(String(128), nullable=False, index=True)
    port = Column(String(128), nullable=False)
    path = Column(String(1024), nullable=False)
    filename = Column(String(255), nullable=True)
    content_type = Column(String(128), nullable=True)
    byte_size = Column(BigInteger, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

    run = relationship("WorkflowRun", back_populates="artifacts")

    def __repr__(self):
        return f"<WorkflowArtifact {self.node_id}:{self.port}>"
