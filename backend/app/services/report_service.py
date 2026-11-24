"""
Report Service for generating PDF reports of security findings.

Provides functionality to generate professional PDF reports for:
- Individual assets with their findings
- Selected findings across multiple assets
- Executive summaries with severity distributions
"""

import logging
import os
from datetime import datetime
from typing import List, Optional, Dict, Any
from io import BytesIO
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy.orm import Session

from app.models.vulnerability import Vulnerability, Severity
from app.models.asset import Asset

logger = logging.getLogger(__name__)

TEMPLATE_DIR = Path(__file__).parent.parent / "templates" / "reports"

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class ReportService:
    """Service for generating PDF reports from security findings."""
    
    def __init__(self, db: Session):
        self.db = db
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=select_autoescape(['html', 'xml'])
        )
    
    def _format_datetime(self, dt: Optional[datetime]) -> str:
        """Format datetime for display in reports."""
        if dt is None:
            return "N/A"
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    
    def _prepare_finding_data(self, finding: Vulnerability) -> Dict[str, Any]:
        """Prepare finding data for template rendering."""
        severity_value = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
        status_value = finding.status.value if hasattr(finding.status, 'value') else str(finding.status)

        metadata = finding.metadata_ or {}
        oracle = metadata.get("oracle") if isinstance(metadata, dict) else None
        delphi = metadata.get("delphi") if isinstance(metadata, dict) else None

        return {
            "id": finding.id,
            "title": finding.title,
            "description": finding.description,
            "severity": severity_value,
            "cvss_score": finding.cvss_score,
            "cvss_vector": finding.cvss_vector,
            "cve_id": finding.cve_id,
            "cwe_id": finding.cwe_id,
            "references": finding.references or [],
            "status": status_value,
            "detected_by": finding.detected_by or "Unknown",
            "evidence": finding.evidence,
            "proof_of_concept": finding.proof_of_concept,
            "remediation": finding.remediation,
            "first_detected": self._format_datetime(finding.first_detected),
            "last_detected": self._format_datetime(finding.last_detected),
            "is_manual": getattr(finding, 'is_manual', False) or False,
            "impact": getattr(finding, 'impact', None),
            "affected_component": getattr(finding, 'affected_component', None),
            "steps_to_reproduce": getattr(finding, 'steps_to_reproduce', None),
            "tags": finding.tags or [],
            "oracle": oracle,
            "delphi": delphi,
        }
    
    def _prepare_asset_data(self, asset: Asset) -> Dict[str, Any]:
        """Prepare asset data for template rendering."""
        asset_type_value = asset.asset_type.value if hasattr(asset.asset_type, 'value') else str(asset.asset_type)
        
        return {
            "id": asset.id,
            "value": asset.value,
            "name": asset.name or asset.value,
            "asset_type": asset_type_value,
            "ip_address": asset.ip_address,
            "city": getattr(asset, 'city', None),
            "country": getattr(asset, 'country', None),
            "risk_score": getattr(asset, 'risk_score', 0) or 0,
            "first_seen": self._format_datetime(asset.first_seen),
            "last_seen": self._format_datetime(asset.last_seen),
        }
    
    def _count_severities(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count findings by severity level."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            sev = finding.get("severity", "info").lower()
            if sev in counts:
                counts[sev] += 1
        return counts
    
    def _sort_findings_by_severity(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sort findings by severity (critical first)."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return sorted(findings, key=lambda f: severity_order.get(f.get("severity", "info").lower(), 5))
    
    def generate_asset_report_html(
        self,
        asset_id: int,
        include_info_findings: bool = False,
        organization_name: Optional[str] = None
    ) -> str:
        """
        Generate HTML report for all findings on an asset.
        
        Args:
            asset_id: ID of the asset to report on
            include_info_findings: Whether to include informational findings
            organization_name: Optional organization name for the report header
            
        Returns:
            HTML string of the rendered report
        """
        context = self._asset_report_context(
            asset_id, include_info_findings, organization_name)
        template = self.jinja_env.get_template("asset_findings_report.html")
        return template.render(**context)

    def _asset_report_context(
        self,
        asset_id: int,
        include_info_findings: bool = False,
        organization_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        asset = self.db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            raise ValueError(f"Asset with ID {asset_id} not found")

        from app.services.agent.unverified_findings import exclude_hidden_levels

        # Unverified agent leads stay out of asset reports until an analyst promotes them.
        query = exclude_hidden_levels(
            self.db.query(Vulnerability).filter(Vulnerability.asset_id == asset_id), Vulnerability,
        )
        if not include_info_findings:
            query = query.filter(Vulnerability.severity != Severity.INFO)

        findings = [self._prepare_finding_data(f) for f in query.all()]
        findings = self._sort_findings_by_severity(findings)
        return {
            "asset": self._prepare_asset_data(asset),
            "findings": findings,
            "severity_counts": self._count_severities(findings),
            "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            "organization_name": organization_name,
        }

    def generate_asset_report_docx(
        self,
        asset_id: int,
        include_info_findings: bool = False,
        organization_name: Optional[str] = None,
    ) -> bytes:
        """Generate an editable Word report for all findings on an asset."""
        from app.services.report_docx import build_findings_docx

        context = self._asset_report_context(
            asset_id, include_info_findings, organization_name)
        return build_findings_docx(
            findings=context["findings"],
            severity_counts=context["severity_counts"],
            generated_at=context["generated_at"],
            organization_name=organization_name,
            asset=context["asset"],
            report_title=f"Security Findings Report: {context['asset']['value']}",
        )
    
    def generate_asset_report_pdf(
        self,
        asset_id: int,
        include_info_findings: bool = False,
        organization_name: Optional[str] = None
    ) -> bytes:
        """
        Generate PDF report for all findings on an asset.
        
        Args:
            asset_id: ID of the asset to report on
            include_info_findings: Whether to include informational findings
            organization_name: Optional organization name for the report header
            
        Returns:
            PDF bytes
        """
        try:
            from weasyprint import HTML, CSS
        except ImportError:
            logger.error("WeasyPrint not installed. Install with: pip install weasyprint")
            raise ImportError("WeasyPrint is required for PDF generation. Install with: pip install weasyprint")
        
        html_content = self.generate_asset_report_html(
            asset_id=asset_id,
            include_info_findings=include_info_findings,
            organization_name=organization_name
        )
        
        pdf_buffer = BytesIO()
        HTML(string=html_content, base_url=str(TEMPLATE_DIR)).write_pdf(pdf_buffer)
        pdf_buffer.seek(0)
        
        return pdf_buffer.read()
    
    def generate_findings_report_html(
        self,
        finding_ids: List[int],
        report_title: Optional[str] = None,
        organization_name: Optional[str] = None
    ) -> str:
        """
        Generate HTML report for selected findings.
        
        Args:
            finding_ids: List of finding IDs to include in the report
            report_title: Optional custom report title
            organization_name: Optional organization name for the report header
            
        Returns:
            HTML string of the rendered report
        """
        context = self._findings_report_context(finding_ids, report_title, organization_name)
        template = self.jinja_env.get_template("asset_findings_report.html")
        return template.render(**context)

    def _findings_report_context(
        self,
        finding_ids: List[int],
        report_title: Optional[str] = None,
        organization_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        findings_raw = self.db.query(Vulnerability).filter(
            Vulnerability.id.in_(finding_ids)
        ).all()
        if not findings_raw:
            raise ValueError("No findings found with the provided IDs")

        asset_ids = list(set(f.asset_id for f in findings_raw))
        assets = self.db.query(Asset).filter(Asset.id.in_(asset_ids)).all()
        asset_map = {a.id: self._prepare_asset_data(a) for a in assets}

        # Attach each finding's asset before sorting: zipping sorted findings
        # against the unsorted rows used to label findings with the wrong asset.
        findings = []
        for finding_raw in findings_raw:
            finding = self._prepare_finding_data(finding_raw)
            finding["asset"] = asset_map.get(finding_raw.asset_id, {})
            findings.append(finding)
        findings = self._sort_findings_by_severity(findings)

        first_asset = asset_map.get(findings_raw[0].asset_id, {"value": "Multiple Assets"})
        return {
            "asset": first_asset,
            "findings": findings,
            "severity_counts": self._count_severities(findings),
            "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            "organization_name": organization_name,
            "report_title": report_title or "Security Findings Report",
        }

    def generate_findings_report_docx(
        self,
        finding_ids: List[int],
        report_title: Optional[str] = None,
        organization_name: Optional[str] = None,
    ) -> bytes:
        """Generate an editable Word report for selected findings."""
        from app.services.report_docx import build_findings_docx

        context = self._findings_report_context(finding_ids, report_title, organization_name)
        multi_asset = len({(f.get("asset") or {}).get("id") for f in context["findings"]}) > 1
        return build_findings_docx(
            findings=context["findings"],
            severity_counts=context["severity_counts"],
            generated_at=context["generated_at"],
            organization_name=organization_name,
            asset=None if multi_asset else context["asset"],
            report_title=context["report_title"],
        )
    
    def generate_findings_report_pdf(
        self,
        finding_ids: List[int],
        report_title: Optional[str] = None,
        organization_name: Optional[str] = None
    ) -> bytes:
        """
        Generate PDF report for selected findings.
        
        Args:
            finding_ids: List of finding IDs to include in the report
            report_title: Optional custom report title
            organization_name: Optional organization name for the report header
            
        Returns:
            PDF bytes
        """
        try:
            from weasyprint import HTML
        except ImportError:
            logger.error("WeasyPrint not installed. Install with: pip install weasyprint")
            raise ImportError("WeasyPrint is required for PDF generation. Install with: pip install weasyprint")
        
        html_content = self.generate_findings_report_html(
            finding_ids=finding_ids,
            report_title=report_title,
            organization_name=organization_name
        )
        
        pdf_buffer = BytesIO()
        HTML(string=html_content, base_url=str(TEMPLATE_DIR)).write_pdf(pdf_buffer)
        pdf_buffer.seek(0)
        
        return pdf_buffer.read()


def get_report_service(db: Session) -> ReportService:
    """Factory function to create ReportService instance."""
    return ReportService(db)
