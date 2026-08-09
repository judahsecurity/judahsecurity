"""Workflow artifact storage under /app/outputs/workflows."""

from __future__ import annotations

import json
import mimetypes
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from sqlalchemy.orm import Session

from app.models.workflow import WorkflowArtifact

WORKFLOW_OUTPUT_ROOT = os.getenv("WORKFLOW_OUTPUT_DIR", "/app/outputs/workflows")
MAX_ARTIFACT_BYTES = int(os.getenv("WORKFLOW_MAX_ARTIFACT_BYTES", str(50 * 1024 * 1024)))


def run_root(organization_id: int, run_id: int) -> Path:
    return Path(WORKFLOW_OUTPUT_ROOT) / str(organization_id) / str(run_id)


def node_dir(organization_id: int, run_id: int, node_id: str) -> Path:
    safe = node_id.replace("/", "_").replace("..", "_")
    path = run_root(organization_id, run_id) / safe
    path.mkdir(parents=True, exist_ok=True)
    (path / "in").mkdir(exist_ok=True)
    (path / "out").mkdir(exist_ok=True)
    return path


def write_text_list(path: Path, lines: List[str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(line.strip() for line in lines if line and str(line).strip())
    if content:
        content += "\n"
    data = content.encode("utf-8")
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ValueError(f"Artifact exceeds max size ({MAX_ARTIFACT_BYTES} bytes)")
    path.write_bytes(data)
    return path


def write_json(path: Path, obj: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(obj, indent=2, default=str).encode("utf-8")
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ValueError(f"Artifact exceeds max size ({MAX_ARTIFACT_BYTES} bytes)")
    path.write_bytes(data)
    return path


def read_text_list(path: Union[str, Path]) -> List[str]:
    p = Path(path)
    if not p.is_file():
        return []
    return [ln.strip() for ln in p.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]


def read_json(path: Union[str, Path]) -> Any:
    p = Path(path)
    if not p.is_file():
        return None
    return json.loads(p.read_text(encoding="utf-8"))


def register_artifact(
    db: Session,
    *,
    run_id: int,
    organization_id: int,
    node_id: str,
    port: str,
    path: Union[str, Path],
    content_type: Optional[str] = None,
) -> WorkflowArtifact:
    p = Path(path)
    size = p.stat().st_size if p.is_file() else 0
    media = content_type or mimetypes.guess_type(str(p))[0] or "application/octet-stream"
    art = WorkflowArtifact(
        run_id=run_id,
        organization_id=organization_id,
        node_id=node_id,
        port=port,
        path=str(p),
        filename=p.name,
        content_type=media,
        byte_size=size,
    )
    db.add(art)
    db.flush()
    return art


def materialize_value(
    ndir: Path,
    port: str,
    value: Any,
    port_type: str = "STRING",
) -> Optional[Path]:
    """Write a resolved input value into node in/ directory; return path if file-like."""
    if value is None:
        return None
    safe_port = port.replace("/", "_")
    if port_type in ("FILE", "FILE_LIST") or isinstance(value, list):
        lines = value if isinstance(value, list) else read_text_list(value) if isinstance(value, (str, Path)) and Path(str(value)).exists() else [str(value)]
        # If value is an existing path to a file list, copy contents
        if isinstance(value, str) and Path(value).is_file() and port_type in ("FILE", "FILE_LIST"):
            lines = read_text_list(value)
        out = ndir / "in" / f"{safe_port}.txt"
        write_text_list(out, [str(x) for x in lines])
        return out
    if port_type == "JSON" or isinstance(value, (dict, list)):
        out = ndir / "in" / f"{safe_port}.json"
        write_json(out, value)
        return out
    out = ndir / "in" / f"{safe_port}.txt"
    write_text_list(out, [str(value)])
    return out


def value_from_artifact_ref(ref: Any) -> Any:
    """Normalize an upstream output ref (path string, list, or dict with path)."""
    if ref is None:
        return None
    if isinstance(ref, dict):
        path = ref.get("path")
        if path and Path(path).is_file():
            if path.endswith(".json"):
                return read_json(path)
            return read_text_list(path)
        return ref.get("value", ref)
    if isinstance(ref, (list, dict)):
        return ref
    if isinstance(ref, str) and Path(ref).is_file():
        if ref.endswith(".json"):
            return read_json(ref)
        return read_text_list(ref)
    return ref
