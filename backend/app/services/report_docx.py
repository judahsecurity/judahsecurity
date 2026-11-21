"""Word (.docx) rendering of findings reports.

Uses the same context the HTML/PDF template gets (``ReportService``), so the
three formats carry the same findings, ordering and fields. Built with
python-docx so analysts can edit the report before sending it.
"""

from __future__ import annotations

from io import BytesIO
from typing import Any, Dict, Iterable, List, Optional

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
SEVERITY_RGB = {
    "critical": (0x9B, 0x1C, 0x1C),
    "high": (0xC2, 0x41, 0x0C),
    "medium": (0xA1, 0x62, 0x07),
    "low": (0x1D, 0x4E, 0xD8),
    "info": (0x4B, 0x55, 0x63),
}

# Text fields rendered as sections, in order, when present on a finding.
SECTIONS = (
    ("description", "Description"),
    ("impact", "Impact"),
    ("affected_component", "Affected component"),
    ("steps_to_reproduce", "Steps to reproduce"),
    ("evidence", "Evidence"),
    ("proof_of_concept", "Proof of concept"),
    ("remediation", "Remediation"),
)
MONOSPACE_FIELDS = {"evidence", "proof_of_concept"}
MAX_FIELD_CHARS = 20000


def _clean(text: Any) -> str:
    """Strip characters Word's XML cannot hold (control chars except tab/newline)."""
    value = "" if text is None else str(text)
    return "".join(ch for ch in value if ch in "\t\n" or ord(ch) >= 0x20)[:MAX_FIELD_CHARS]


def _shade(cell, hex_fill: str) -> None:
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn

    shading = OxmlElement("w:shd")
    shading.set(qn("w:val"), "clear")
    shading.set(qn("w:color"), "auto")
    shading.set(qn("w:fill"), hex_fill)
    cell._tc.get_or_add_tcPr().append(shading)


def _key_value_table(document, rows: Iterable[tuple]) -> None:
    rows = [(label, _clean(value)) for label, value in rows if value not in (None, "", [])]
    if not rows:
        return
    table = document.add_table(rows=0, cols=2)
    table.style = "Table Grid"
    for label, value in rows:
        cells = table.add_row().cells
        cells[0].text = label
        cells[0].paragraphs[0].runs[0].bold = True
        _shade(cells[0], "F3F4F6")
        cells[1].text = value
    document.add_paragraph()


def _add_text_block(document, text: str, monospace: bool) -> None:
    from docx.shared import Pt

    for line_block in _clean(text).split("\n\n"):
        paragraph = document.add_paragraph()
        run = paragraph.add_run(line_block)
        if monospace:
            run.font.name = "Consolas"
            run.font.size = Pt(9)


def build_findings_docx(
    *,
    findings: List[Dict[str, Any]],
    severity_counts: Dict[str, int],
    generated_at: str,
    report_title: Optional[str] = None,
    organization_name: Optional[str] = None,
    asset: Optional[Dict[str, Any]] = None,
) -> bytes:
    try:
        from docx import Document
        from docx.shared import Pt, RGBColor
    except ImportError as exc:  # pragma: no cover - dependency guard
        raise ImportError("python-docx is required for Word export. Install with: "
                          "pip install python-docx") from exc

    document = Document()
    style = document.styles["Normal"]
    style.font.name = "Calibri"
    style.font.size = Pt(10.5)

    document.add_heading(_clean(report_title or "Security Findings Report"), level=0)
    meta = document.add_paragraph()
    if organization_name:
        meta.add_run(_clean(organization_name)).bold = True
        meta.add_run("  ·  ")
    meta.add_run(f"Generated {_clean(generated_at)}")

    if asset and asset.get("value"):
        document.add_heading("Asset", level=1)
        _key_value_table(document, (
            ("Asset", asset.get("value")),
            ("Type", asset.get("asset_type")),
            ("IP address", asset.get("ip_address")),
            ("Risk score", asset.get("risk_score")),
            ("First seen", asset.get("first_seen")),
            ("Last seen", asset.get("last_seen")),
        ))

    document.add_heading("Summary", level=1)
    summary = document.add_table(rows=2, cols=len(SEVERITY_ORDER))
    summary.style = "Table Grid"
    for index, severity in enumerate(SEVERITY_ORDER):
        header = summary.rows[0].cells[index]
        header.text = severity.capitalize()
        header.paragraphs[0].runs[0].bold = True
        summary.rows[1].cells[index].text = str(severity_counts.get(severity, 0))
    document.add_paragraph(f"{len(findings)} finding(s) in this report.")

    if not findings:
        document.add_paragraph("No findings matched this report.")

    for number, finding in enumerate(findings, start=1):
        severity = str(finding.get("severity") or "info").lower()
        if number > 1:
            document.add_page_break()
        heading = document.add_heading(level=1)
        heading.add_run(f"{number}. {_clean(finding.get('title') or 'Untitled finding')}")
        badge = document.add_paragraph()
        run = badge.add_run(severity.upper())
        run.bold = True
        run.font.color.rgb = RGBColor(*SEVERITY_RGB.get(severity, SEVERITY_RGB["info"]))
        finding_asset = finding.get("asset") or {}
        _key_value_table(document, (
            ("Asset", finding_asset.get("value")),
            ("Status", finding.get("status")),
            ("CVSS", " ".join(str(x) for x in (finding.get("cvss_score"),
                                                finding.get("cvss_vector")) if x)),
            ("CVE", finding.get("cve_id")),
            ("CWE", finding.get("cwe_id")),
            ("Detected by", finding.get("detected_by")),
            ("First detected", finding.get("first_detected")),
            ("Last detected", finding.get("last_detected")),
        ))
        for field_name, label in SECTIONS:
            value = finding.get(field_name)
            if not value:
                continue
            document.add_heading(label, level=2)
            _add_text_block(document, value, monospace=field_name in MONOSPACE_FIELDS)
        references = [r for r in (finding.get("references") or []) if r]
        if references:
            document.add_heading("References", level=2)
            for ref in references[:50]:
                text = ref.get("url") or ref.get("title") if isinstance(ref, dict) else ref
                document.add_paragraph(_clean(text), style="List Bullet")

    buffer = BytesIO()
    document.save(buffer)
    return buffer.getvalue()
