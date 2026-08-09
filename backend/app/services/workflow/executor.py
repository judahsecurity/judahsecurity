"""Drive a WorkflowRun through an expanded DAG."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.models.workflow import (
    WorkflowRun,
    WorkflowRunStatus,
    WorkflowNodeRun,
    WorkflowNodeRunStatus,
    WorkflowVersion,
    WorkflowScript,
)
from app.services.workflow.dag import (
    DagError,
    expand_modules,
    predecessors,
    resolve_node_type,
    topological_levels,
)
from app.services.workflow.artifacts import (
    materialize_value,
    node_dir,
    register_artifact,
    value_from_artifact_ref,
    write_text_list,
)
from app.services.workflow.tool_adapters import run_tool_node
from app.services.workflow.script_runner import prepare_script_inputs, run_script

logger = logging.getLogger(__name__)

DEFAULT_NODE_CONCURRENCY = 2


class WorkflowExecutor:
    def __init__(self, db: Session, worker: Any, *, concurrency: int = DEFAULT_NODE_CONCURRENCY):
        self.db = db
        self.worker = worker
        self.concurrency = concurrency

    async def execute(self, run_id: int) -> None:
        run = self.db.query(WorkflowRun).filter(WorkflowRun.id == run_id).first()
        if not run:
            logger.error("WorkflowRun %s not found", run_id)
            return
        if run.status == WorkflowRunStatus.CANCELLED:
            return

        run.status = WorkflowRunStatus.RUNNING
        run.started_at = datetime.utcnow()
        run.current_step = "expanding graph"
        self.db.commit()

        try:
            version = self.db.query(WorkflowVersion).filter(WorkflowVersion.id == run.version_id).first()
            if not version:
                raise DagError("Workflow version not found")

            graph = expand_modules(
                self.db,
                version.graph or {},
                organization_id=run.organization_id,
            )
            levels = topological_levels(graph)
            nodes = {n["id"]: n for n in graph.get("nodes") or []}

            # Create node run rows
            for nid, node in nodes.items():
                existing = (
                    self.db.query(WorkflowNodeRun)
                    .filter(WorkflowNodeRun.run_id == run.id, WorkflowNodeRun.node_id == nid)
                    .first()
                )
                if existing:
                    continue
                data = node.get("data") or {}
                self.db.add(
                    WorkflowNodeRun(
                        run_id=run.id,
                        node_id=nid,
                        node_type=resolve_node_type(node),
                        node_label=data.get("label") or nid,
                        status=WorkflowNodeRunStatus.PENDING,
                    )
                )
            self.db.commit()

            outputs_by_node: Dict[str, Dict[str, Any]] = {}
            total_nodes = len(nodes)
            done = 0
            failed = False

            for level in levels:
                run = self.db.query(WorkflowRun).filter(WorkflowRun.id == run_id).first()
                if not run or run.status == WorkflowRunStatus.CANCELLED:
                    self._cancel_pending(run_id)
                    return

                # Skip sink/primitive lightweight handling can parallelize
                sem = asyncio.Semaphore(self.concurrency)

                async def _run_one(nid: str) -> None:
                    nonlocal done, failed
                    async with sem:
                        await self._execute_node(
                            run_id=run_id,
                            graph=graph,
                            node=nodes[nid],
                            run_inputs=(run.inputs or {}),
                            outputs_by_node=outputs_by_node,
                        )

                # Sequential within failure-sensitive path for shared db session safety:
                # run level nodes one-at-a-time on this session (worker handlers use same pattern).
                for nid in level:
                    run = self.db.query(WorkflowRun).filter(WorkflowRun.id == run_id).first()
                    if not run or run.status == WorkflowRunStatus.CANCELLED:
                        self._cancel_pending(run_id)
                        return
                    try:
                        run.current_step = f"running {nid}"
                        self.db.commit()
                        await self._execute_node(
                            run_id=run_id,
                            graph=graph,
                            node=nodes[nid],
                            run_inputs=(run.inputs or {}),
                            outputs_by_node=outputs_by_node,
                        )
                        done += 1
                        run.progress = int((done / max(total_nodes, 1)) * 100)
                        self.db.commit()
                    except Exception as e:
                        logger.exception("Node %s failed in run %s", nid, run_id)
                        nr = (
                            self.db.query(WorkflowNodeRun)
                            .filter(WorkflowNodeRun.run_id == run_id, WorkflowNodeRun.node_id == nid)
                            .first()
                        )
                        if nr:
                            nr.status = WorkflowNodeRunStatus.FAILED
                            nr.error_message = str(e)[:2000]
                            nr.completed_at = datetime.utcnow()
                        self.db.commit()
                        if not (run and run.continue_on_error):
                            failed = True
                            run.status = WorkflowRunStatus.FAILED
                            run.error_message = f"Node {nid} failed: {e}"
                            run.completed_at = datetime.utcnow()
                            self.db.commit()
                            return
                        failed = True

            run = self.db.query(WorkflowRun).filter(WorkflowRun.id == run_id).first()
            if run and run.status == WorkflowRunStatus.RUNNING:
                run.status = WorkflowRunStatus.FAILED if failed else WorkflowRunStatus.COMPLETED
                run.progress = 100
                run.current_step = "failed" if failed else "completed"
                run.completed_at = datetime.utcnow()
                self.db.commit()

        except Exception as e:
            logger.exception("Workflow run %s failed", run_id)
            run = self.db.query(WorkflowRun).filter(WorkflowRun.id == run_id).first()
            if run:
                run.status = WorkflowRunStatus.FAILED
                run.error_message = str(e)[:2000]
                run.completed_at = datetime.utcnow()
                run.current_step = "failed"
                self.db.commit()

    def _cancel_pending(self, run_id: int) -> None:
        pending = (
            self.db.query(WorkflowNodeRun)
            .filter(
                WorkflowNodeRun.run_id == run_id,
                WorkflowNodeRun.status.in_(
                    [WorkflowNodeRunStatus.PENDING, WorkflowNodeRunStatus.READY, WorkflowNodeRunStatus.RUNNING]
                ),
            )
            .all()
        )
        for nr in pending:
            nr.status = WorkflowNodeRunStatus.CANCELLED
            nr.completed_at = datetime.utcnow()
        run = self.db.query(WorkflowRun).filter(WorkflowRun.id == run_id).first()
        if run and run.status != WorkflowRunStatus.CANCELLED:
            run.status = WorkflowRunStatus.CANCELLED
            run.completed_at = datetime.utcnow()
        self.db.commit()

    def _resolve_inputs(
        self,
        graph: Dict[str, Any],
        node: Dict[str, Any],
        run_inputs: Dict[str, Any],
        outputs_by_node: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Any]:
        nid = node["id"]
        resolved: Dict[str, Any] = {}
        # literal params / defaults on node
        data = node.get("data") or {}
        if data.get("value_key") and data["value_key"] in run_inputs:
            port = (data.get("port") or {}).get("name") or data["value_key"]
            resolved[port] = run_inputs[data["value_key"]]

        for e in predecessors(graph, nid):
            src = e.get("source")
            src_handle = e.get("sourceHandle") or "out"
            tgt_handle = e.get("targetHandle") or src_handle
            src_outs = outputs_by_node.get(src) or {}
            val = None
            if src_handle in src_outs:
                val = src_outs[src_handle]
            elif len(src_outs) == 1:
                val = next(iter(src_outs.values()))
            if val is not None:
                resolved[tgt_handle] = value_from_artifact_ref(val) if not isinstance(val, dict) or "path" in val else value_from_artifact_ref(val)
                # Keep path refs for FILE ports
                if isinstance(val, dict) and val.get("path"):
                    resolved[tgt_handle] = val["path"]
        return resolved

    async def _execute_node(
        self,
        *,
        run_id: int,
        graph: Dict[str, Any],
        node: Dict[str, Any],
        run_inputs: Dict[str, Any],
        outputs_by_node: Dict[str, Dict[str, Any]],
    ) -> None:
        run = self.db.query(WorkflowRun).filter(WorkflowRun.id == run_id).first()
        if not run:
            return
        nid = node["id"]
        ntype = resolve_node_type(node)
        data = node.get("data") or {}
        nr = (
            self.db.query(WorkflowNodeRun)
            .filter(WorkflowNodeRun.run_id == run_id, WorkflowNodeRun.node_id == nid)
            .first()
        )
        if not nr:
            return

        nr.status = WorkflowNodeRunStatus.RUNNING
        nr.started_at = datetime.utcnow()
        resolved = self._resolve_inputs(graph, node, run_inputs, outputs_by_node)
        nr.inputs = {k: (v if not isinstance(v, list) else v[:100]) for k, v in resolved.items()}
        self.db.commit()

        ndir = node_dir(run.organization_id, run_id, nid)

        if ntype == "primitive":
            port = (data.get("port") or {}).get("name") or data.get("value_key") or "value"
            value = resolved.get(port)
            if value is None and data.get("value_key"):
                value = run_inputs.get(data["value_key"])
            if value is None and port in run_inputs:
                value = run_inputs[port]
            # Also accept top-level domain etc.
            if value is None and run_inputs:
                # single-key convenience
                if len(run_inputs) == 1:
                    value = next(iter(run_inputs.values()))
            path = materialize_value(ndir, port, value, (data.get("port") or {}).get("type", "STRING"))
            outs: Dict[str, Any] = {}
            if path:
                art = register_artifact(
                    self.db,
                    run_id=run_id,
                    organization_id=run.organization_id,
                    node_id=nid,
                    port=port,
                    path=path,
                )
                outs[port] = {"path": str(path), "artifact_id": art.id, "value": value}
            else:
                outs[port] = {"value": value}
            outputs_by_node[nid] = outs
            nr.outputs = outs
            nr.status = WorkflowNodeRunStatus.COMPLETED
            nr.completed_at = datetime.utcnow()
            self.db.commit()
            return

        if ntype == "sink":
            port = (data.get("port") or {}).get("name") or "in"
            value = resolved.get(port) or (next(iter(resolved.values())) if resolved else None)
            path = None
            if isinstance(value, str) and value:
                # copy into out
                from pathlib import Path
                import shutil

                if Path(value).is_file():
                    dest = ndir / "out" / Path(value).name
                    shutil.copy2(value, dest)
                    path = dest
                else:
                    path = write_text_list(ndir / "out" / f"{port}.txt", [value])
            elif isinstance(value, list):
                path = write_text_list(ndir / "out" / f"{port}.txt", [str(x) for x in value])
            outs = {}
            if path:
                art = register_artifact(
                    self.db,
                    run_id=run_id,
                    organization_id=run.organization_id,
                    node_id=nid,
                    port=port,
                    path=path,
                )
                outs[port] = {"path": str(path), "artifact_id": art.id}
            outputs_by_node[nid] = outs
            nr.outputs = outs
            nr.status = WorkflowNodeRunStatus.COMPLETED
            nr.completed_at = datetime.utcnow()
            self.db.commit()
            return

        if ntype == "tool":
            tool_id = data.get("tool_id")
            if not tool_id:
                raise ValueError(f"Tool node {nid} missing tool_id")
            outs, logs = await run_tool_node(
                self.db,
                self.worker,
                run_id=run_id,
                organization_id=run.organization_id,
                node_id=nid,
                tool_id=tool_id,
                params=data.get("params") or {},
                resolved_inputs=resolved,
            )
            outputs_by_node[nid] = outs
            nr.outputs = outs
            nr.logs = logs
            nr.status = WorkflowNodeRunStatus.COMPLETED
            nr.completed_at = datetime.utcnow()
            self.db.commit()
            return

        if ntype == "script":
            script_id = data.get("script_id")
            if not script_id:
                raise ValueError(f"Script node {nid} missing script_id")
            script = (
                self.db.query(WorkflowScript)
                .filter(
                    WorkflowScript.id == int(script_id),
                    WorkflowScript.organization_id == run.organization_id,
                )
                .first()
            )
            if not script:
                raise ValueError(f"Script {script_id} not found")
            prepare_script_inputs(ndir, resolved)
            env_extra = {f"INPUT_{k.upper()}": ",".join(v) if isinstance(v, list) else str(v) for k, v in resolved.items()}
            code, stdout, stderr, out_files = await run_script(
                language=script.language.value if hasattr(script.language, "value") else str(script.language),
                source=script.source or "",
                workdir=ndir,
                env_extra=env_extra,
            )
            nr.logs = f"exit={code}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
            if code != 0:
                raise RuntimeError(f"Script exited {code}: {stderr[-500:]}")
            outs = {}
            declared = {p.get("name"): p for p in (script.output_ports or []) if isinstance(p, dict)}
            for name, path in out_files.items():
                # Prefer declared port names (stem)
                port_name = name
                if name in declared:
                    port_name = name
                elif Path_stem(name) in declared:
                    port_name = Path_stem(name)
                art = register_artifact(
                    self.db,
                    run_id=run_id,
                    organization_id=run.organization_id,
                    node_id=nid,
                    port=port_name,
                    path=path,
                )
                outs[port_name] = {"path": str(path), "artifact_id": art.id}
            # Map declared ports to files when possible
            for pname in declared:
                if pname not in outs:
                    candidate = ndir / "out" / f"{pname}.txt"
                    if candidate.is_file():
                        art = register_artifact(
                            self.db,
                            run_id=run_id,
                            organization_id=run.organization_id,
                            node_id=nid,
                            port=pname,
                            path=candidate,
                        )
                        outs[pname] = {"path": str(candidate), "artifact_id": art.id}
            outputs_by_node[nid] = outs
            nr.outputs = outs
            nr.status = WorkflowNodeRunStatus.COMPLETED
            nr.completed_at = datetime.utcnow()
            self.db.commit()
            return

        if ntype == "module":
            # Should have been expanded; treat as no-op skip
            nr.status = WorkflowNodeRunStatus.SKIPPED
            nr.logs = "Module node should be expanded before execution"
            nr.completed_at = datetime.utcnow()
            self.db.commit()
            return

        raise ValueError(f"Unsupported node type: {ntype}")


def Path_stem(name: str) -> str:
    from pathlib import Path

    return Path(name).stem
