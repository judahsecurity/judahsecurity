"""
Custom Nuclei template on-disk store.

Custom (analyst-written / AI-generated) Nuclei templates live in the
`custom_nuclei_templates` Postgres table, which is the source of truth. Nuclei,
however, runs templates from the filesystem — so before those templates can
actually be used in a scan they must be written to disk.

This module materializes ACTIVE templates for an organization from the DB to a
directory on disk, laid out as:

    <NUCLEI_GENERATED_TEMPLATES_PATH>/org_<organization_id>/<template_id>.yaml

The scanner worker calls `materialize_org_templates()` right before running
Nuclei and passes the returned directory to the scanner via `-t`. The template
CRUD endpoints also call the single-file helpers so the on-disk copy stays in
sync as analysts activate/disable/delete templates.

Because the DB is the source of truth, `materialize_org_templates()` fully
rebuilds the org directory each run (writing active templates, removing stale
files). This keeps the approach robust even when the API and worker run in
separate processes/containers that do not share a filesystem.
"""

import logging
import os
import re
from pathlib import Path
from typing import Optional

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.custom_nuclei_template import CustomNucleiTemplate

logger = logging.getLogger(__name__)

# Only these characters are allowed in an on-disk template filename stem.
_SAFE_STEM = re.compile(r"[^A-Za-z0-9._-]")


def get_generated_templates_root() -> Optional[Path]:
    """Absolute path to the root directory for materialized custom templates.

    Resolved relative to the backend/ directory (three parents up from this
    file: app/services/ -> app/ -> backend/). Returns None if disabled.
    """
    configured = getattr(settings, "NUCLEI_GENERATED_TEMPLATES_PATH", "") or ""
    if not configured:
        return None
    p = Path(configured)
    if not p.is_absolute():
        p = Path(__file__).resolve().parent.parent.parent / configured
    return p


def _org_dir(root: Path, organization_id: int) -> Path:
    return root / f"org_{int(organization_id)}"


def _safe_stem(template_id: str) -> str:
    """Sanitize a template_id into a safe filename stem (no path traversal)."""
    stem = _SAFE_STEM.sub("-", (template_id or "").strip())
    stem = stem.strip(".-") or "template"
    return stem[:120]


def _template_path(root: Path, organization_id: int, template_id: str) -> Path:
    return _org_dir(root, organization_id) / f"{_safe_stem(template_id)}.yaml"


def write_template_file(template: CustomNucleiTemplate) -> Optional[str]:
    """Write a single template's YAML to disk. Best-effort; returns path or None."""
    root = get_generated_templates_root()
    if root is None or not template.template_yaml:
        return None
    try:
        path = _template_path(root, template.organization_id, template.template_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(template.template_yaml, encoding="utf-8")
        return str(path)
    except OSError as e:
        logger.warning(
            "Failed to write custom template %s (org=%s) to disk: %s",
            template.template_id, template.organization_id, e,
        )
        return None


def remove_template_file(organization_id: int, template_id: str) -> None:
    """Remove a single template's on-disk copy if present. Best-effort."""
    root = get_generated_templates_root()
    if root is None:
        return
    try:
        path = _template_path(root, organization_id, template_id)
        if path.exists():
            path.unlink()
    except OSError as e:
        logger.warning(
            "Failed to remove custom template %s (org=%s) from disk: %s",
            template_id, organization_id, e,
        )


def sync_template_file(template: CustomNucleiTemplate) -> None:
    """Ensure the on-disk copy reflects the template's current status.

    Active templates are written to disk; anything else (draft/disabled) is
    removed so it can't be picked up by a scan.
    """
    if template.status == "active":
        write_template_file(template)
    else:
        remove_template_file(template.organization_id, template.template_id)


def materialize_org_templates(db: Session, organization_id: int) -> Optional[str]:
    """Rebuild the on-disk directory of ACTIVE custom templates for an org.

    Writes every active template, removes any stale `.yaml` files no longer
    backed by an active template, and returns the org directory path — or None
    if the store is disabled or the org has no active templates.
    """
    root = get_generated_templates_root()
    if root is None:
        return None

    templates = (
        db.query(CustomNucleiTemplate)
        .filter(
            CustomNucleiTemplate.organization_id == organization_id,
            CustomNucleiTemplate.status == "active",
        )
        .all()
    )

    org_dir = _org_dir(root, organization_id)

    if not templates:
        # No active templates: clean out any stale directory contents.
        _remove_stale_files(org_dir, keep=set())
        return None

    try:
        org_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        logger.warning("Cannot create custom template dir %s: %s", org_dir, e)
        return None

    written: set[str] = set()
    for t in templates:
        if not t.template_yaml:
            continue
        path = _template_path(root, organization_id, t.template_id)
        try:
            path.write_text(t.template_yaml, encoding="utf-8")
            written.add(path.name)
        except OSError as e:
            logger.warning("Failed to write custom template %s: %s", t.template_id, e)

    _remove_stale_files(org_dir, keep=written)

    if not written:
        return None

    logger.info(
        "Materialized %d active custom Nuclei template(s) for org %s at %s",
        len(written), organization_id, org_dir,
    )
    return str(org_dir)


def _remove_stale_files(org_dir: Path, keep: set[str]) -> None:
    """Delete *.yaml files in org_dir that are not in `keep`. Best-effort."""
    if not org_dir.exists():
        return
    try:
        for entry in org_dir.iterdir():
            if entry.is_file() and entry.suffix in (".yaml", ".yml") and entry.name not in keep:
                try:
                    entry.unlink()
                except OSError:
                    pass
    except OSError as e:
        logger.warning("Failed to prune stale templates in %s: %s", org_dir, e)
