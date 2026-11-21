"""Asset inventory spreadsheets: CSV/XLSX export and import, bulk edits.

Import is additive and safe by default: new rows become assets, rows that
match an existing asset (organization + type + value) are skipped unless
``mode="update"``, which only touches the editable business fields (name,
description, tags, criticality, in_scope, is_monitored). Every row is
validated; a dry run reports what would happen without writing.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from app.models.asset import Asset, AssetType

EXPORT_COLUMNS = ("value", "asset_type", "name", "in_scope", "is_live", "is_monitored", "criticality",
                  "risk_score", "tags", "description", "discovery_source", "first_seen", "last_seen")
IMPORT_COLUMNS = ("value", "asset_type", "name", "description", "tags", "criticality", "in_scope",
                  "is_monitored")
EDITABLE_FIELDS = ("name", "description", "tags", "criticality", "in_scope", "is_monitored")
CRITICALITY = ("low", "medium", "high", "critical")
MAX_IMPORT_ROWS = 10_000
MAX_IMPORT_BYTES = 5 * 1024 * 1024
MAX_ERRORS = 200
_HOST = re.compile(r"^(?=.{1,253}$)(\*\.)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
_TRUE = {"true", "yes", "y", "1"}
_FALSE = {"false", "no", "n", "0"}


class ImportError_(ValueError):
    pass


def _spreadsheet_safe(value: Any) -> Any:
    """Neutralize formula injection in exported text cells."""
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + value
    return value


def asset_row(asset: Asset) -> Dict[str, Any]:
    kind = asset.asset_type.value if hasattr(asset.asset_type, "value") else str(asset.asset_type)
    return {
        "value": asset.value,
        "asset_type": kind,
        "name": asset.name,
        "in_scope": bool(asset.in_scope),
        "is_live": bool(asset.is_live),
        "is_monitored": bool(asset.is_monitored),
        "criticality": asset.criticality or "",
        "risk_score": asset.risk_score or 0,
        "tags": ";".join(str(t) for t in (asset.tags or [])),
        "description": asset.description or "",
        "discovery_source": asset.discovery_source or "",
        "first_seen": asset.first_seen.isoformat() if asset.first_seen else "",
        "last_seen": asset.last_seen.isoformat() if asset.last_seen else "",
    }


def export_csv(assets: Iterable[Asset]) -> bytes:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=EXPORT_COLUMNS)
    writer.writeheader()
    for asset in assets:
        writer.writerow({k: _spreadsheet_safe(v) for k, v in asset_row(asset).items()})
    return buffer.getvalue().encode("utf-8-sig")  # BOM so Excel reads UTF-8


def export_xlsx(assets: Iterable[Asset]) -> bytes:
    from openpyxl import Workbook

    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Assets"
    sheet.append(list(EXPORT_COLUMNS))
    for asset in assets:
        row = asset_row(asset)
        sheet.append([_spreadsheet_safe(row[c]) for c in EXPORT_COLUMNS])
    sheet.freeze_panes = "A2"
    out = io.BytesIO()
    workbook.save(out)
    return out.getvalue()


def detect_type(value: str) -> Optional[AssetType]:
    text = value.strip()
    if re.match(r"^https?://", text, re.I):
        return AssetType.URL
    try:
        ipaddress.ip_address(text)
        return AssetType.IP_ADDRESS
    except ValueError:
        pass
    try:
        if "/" in text:
            ipaddress.ip_network(text, strict=False)
            return AssetType.IP_RANGE
    except ValueError:
        pass
    if _HOST.match(text):
        return AssetType.SUBDOMAIN if text.lstrip("*.").count(".") >= 2 else AssetType.DOMAIN
    return None


def _bool(value: Any, default: Optional[bool]) -> Optional[bool]:
    if value is None or str(value).strip() == "":
        return default
    text = str(value).strip().lower()
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    raise ImportError_(f"expected true/false, got {value!r}")


def read_rows(filename: str, content: bytes) -> List[Dict[str, Any]]:
    if len(content) > MAX_IMPORT_BYTES:
        raise ImportError_(f"file is larger than {MAX_IMPORT_BYTES // (1024 * 1024)} MB")
    name = (filename or "").lower()
    if name.endswith(".xlsx"):
        from openpyxl import load_workbook

        sheet = load_workbook(io.BytesIO(content), read_only=True, data_only=True).active
        rows = sheet.iter_rows(values_only=True)
        header = [str(h or "").strip().lower() for h in next(rows, [])]
        records = [dict(zip(header, r)) for r in rows]
    elif name.endswith(".csv") or not name:
        text = content.decode("utf-8-sig", errors="replace")
        records = list(csv.DictReader(io.StringIO(text)))
        records = [{str(k or "").strip().lower(): v for k, v in r.items()} for r in records]
    else:
        raise ImportError_("upload a .csv or .xlsx file")
    records = [r for r in records if any(str(v or "").strip() for v in r.values())]
    if len(records) > MAX_IMPORT_ROWS:
        raise ImportError_(f"at most {MAX_IMPORT_ROWS} rows per import")
    if records and "value" not in records[0]:
        raise ImportError_("missing required column 'value'")
    return records


@dataclass
class ParsedRow:
    line: int
    value: str
    asset_type: AssetType
    fields: Dict[str, Any] = field(default_factory=dict)


def parse_row(line: int, record: Dict[str, Any]) -> ParsedRow:
    value = str(record.get("value") or "").strip()
    if not value or len(value) > 500:
        raise ImportError_("value is required (max 500 characters)")
    if value.startswith(("=", "+", "@")):
        raise ImportError_("value looks like a spreadsheet formula")
    raw_type = str(record.get("asset_type") or "").strip().upper()
    if raw_type:
        try:
            kind = AssetType(raw_type)
        except ValueError:
            raise ImportError_(f"unknown asset_type {raw_type!r}") from None
    else:
        kind = detect_type(value)
        if kind is None:
            raise ImportError_("could not detect asset_type; add an asset_type column")
    fields: Dict[str, Any] = {}
    if record.get("name"):
        fields["name"] = str(record["name"]).strip()[:255]
    if record.get("description"):
        fields["description"] = str(record["description"]).strip()[:5000]
    if record.get("tags"):
        tags = [t.strip() for t in re.split(r"[;,]", str(record["tags"])) if t.strip()]
        fields["tags"] = sorted(set(t[:64] for t in tags))[:50]
    if record.get("criticality"):
        crit = str(record["criticality"]).strip().lower()
        if crit not in CRITICALITY:
            raise ImportError_(f"criticality must be one of {', '.join(CRITICALITY)}")
        fields["criticality"] = crit
    for flag in ("in_scope", "is_monitored"):
        parsed = _bool(record.get(flag), None)
        if parsed is not None:
            fields[flag] = parsed
    return ParsedRow(line=line, value=value, asset_type=kind, fields=fields)


def import_assets(db, organization_id: int, records: List[Dict[str, Any]], *,
                  mode: str = "skip", dry_run: bool = False, source: str = "import") -> Dict[str, Any]:
    if mode not in ("skip", "update"):
        raise ImportError_("mode must be 'skip' or 'update'")
    result = {"created": 0, "updated": 0, "skipped": 0, "invalid": 0, "errors": [],
              "dry_run": dry_run}
    parsed: List[ParsedRow] = []
    seen = set()
    for index, record in enumerate(records, start=2):  # line 1 is the header
        try:
            row = parse_row(index, record)
        except ImportError_ as exc:
            result["invalid"] += 1
            if len(result["errors"]) < MAX_ERRORS:
                result["errors"].append({"line": index, "error": str(exc)})
            continue
        key = (row.asset_type, row.value.lower())
        if key in seen:
            result["skipped"] += 1
            continue
        seen.add(key)
        parsed.append(row)

    existing = {}
    values = list({r.value for r in parsed})
    for start in range(0, len(values), 500):
        for asset in db.query(Asset).filter(Asset.organization_id == organization_id,
                                            Asset.value.in_(values[start:start + 500])):
            existing[(asset.asset_type, asset.value.lower())] = asset

    for row in parsed:
        asset = existing.get((row.asset_type, row.value.lower()))
        if asset is None:
            result["created"] += 1
            if not dry_run:
                data = {"name": row.fields.get("name") or row.value, "description": None,
                        "tags": [], "criticality": "medium", **row.fields}
                new = Asset(organization_id=organization_id, asset_type=row.asset_type,
                            value=row.value, discovery_source=source, **data)
                if row.asset_type == AssetType.IP_ADDRESS:
                    new.ip_address = row.value
                    new.ip_addresses = [row.value]
                db.add(new)
        elif mode == "update" and row.fields:
            result["updated"] += 1
            if not dry_run:
                for key, value in row.fields.items():
                    setattr(asset, key, value)
        else:
            result["skipped"] += 1
    if not dry_run:
        db.commit()
    return result


def bulk_update(db, organization_id: int, asset_ids: List[int], changes: Dict[str, Any]) -> int:
    """Apply business-field edits to many assets of one organization."""
    assets = db.query(Asset).filter(Asset.organization_id == organization_id,
                                    Asset.id.in_(asset_ids)).all()
    add_tags = [t.strip()[:64] for t in changes.get("add_tags") or [] if t and t.strip()]
    remove_tags = {t.strip() for t in changes.get("remove_tags") or [] if t}
    for asset in assets:
        for key in ("criticality", "in_scope", "is_monitored", "description"):
            if changes.get(key) is not None:
                setattr(asset, key, changes[key])
        if add_tags or remove_tags:
            tags = [t for t in (asset.tags or []) if t not in remove_tags]
            asset.tags = sorted(set(tags) | set(add_tags))[:50]
    db.commit()
    return len(assets)
