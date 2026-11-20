"""Word export of findings reports, and asset labelling in selected-findings reports."""

from io import BytesIO
from types import SimpleNamespace

from docx import Document

from app.models.asset import Asset
from app.models.vulnerability import Severity
from app.services.report_docx import build_findings_docx
from app.services.report_service import ReportService


def _finding(fid, asset_id, severity, title):
    return SimpleNamespace(
        id=fid, asset_id=asset_id, title=title, description=f"desc {fid}",
        severity=severity, status=SimpleNamespace(value="open"), cvss_score=None,
        cvss_vector=None, cve_id=None, cwe_id=None, references=["https://owasp.org/x"],
        detected_by="agent", evidence="HTTP/1.1 200\x07 OK", proof_of_concept=None,
        remediation="Fix it", first_detected=None, last_detected=None, is_manual=False,
        impact="Data exposure", affected_component=None, steps_to_reproduce="1. GET /",
        tags=[], metadata_={},
    )


def _asset(aid, value):
    return SimpleNamespace(
        id=aid, value=value, name=value, asset_type=SimpleNamespace(value="domain"),
        ip_address=None, city=None, country=None, risk_score=3, first_seen=None, last_seen=None,
    )


class FakeQuery:
    def __init__(self, rows):
        self.rows = rows

    def filter(self, *_args):
        return self

    def all(self):
        return list(self.rows)


class FakeDb:
    def __init__(self, findings, assets):
        self.findings, self.assets = findings, assets

    def query(self, model):
        return FakeQuery(self.assets if model is Asset else self.findings)


def _service(db):
    service = ReportService.__new__(ReportService)
    service.db = db
    return service


def test_selected_findings_keep_their_own_asset_after_severity_sort():
    db = FakeDb(
        findings=[_finding(1, 10, Severity.LOW, "Low on a"),
                  _finding(2, 20, Severity.CRITICAL, "Critical on b")],
        assets=[_asset(10, "a.example.com"), _asset(20, "b.example.com")],
    )
    context = _service(db)._findings_report_context([1, 2])
    by_title = {f["title"]: f["asset"]["value"] for f in context["findings"]}
    assert [f["title"] for f in context["findings"]] == ["Critical on b", "Low on a"]
    assert by_title == {"Critical on b": "b.example.com", "Low on a": "a.example.com"}


def test_docx_contains_summary_findings_and_sanitized_text():
    db = FakeDb(findings=[_finding(1, 10, Severity.HIGH, "SQL injection in /search")],
                assets=[_asset(10, "app.example.com")])
    data = _service(db).generate_findings_report_docx([1], report_title="Q3 test",
                                                      organization_name="Acme")
    document = Document(BytesIO(data))
    text = "\n".join(p.text for p in document.paragraphs)
    cells = "\n".join(c.text for t in document.tables for row in t.rows for c in row.cells)
    assert "Q3 test" in text and "Acme" in text
    assert "1. SQL injection in /search" in text and "HIGH" in text
    assert "Data exposure" in text and "Fix it" in text and "https://owasp.org/x" in text
    assert "HTTP/1.1 200 OK" in text  # control character removed
    assert "app.example.com" in cells and "High" in cells


def test_empty_report_renders():
    data = build_findings_docx(findings=[], severity_counts={}, generated_at="now")
    text = "\n".join(p.text for p in Document(BytesIO(data)).paragraphs)
    assert "No findings matched this report." in text
