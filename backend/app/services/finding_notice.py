"""Owner-facing finding notice, rendered from one template in several formats.

Layout (every label and paragraph is configurable in the ``finding_response``
settings, ``notice`` block):

    External Exposure                              header ({exposure_title} Exposure)
    <Title>                                        colored like the severity
    Severity: <Urgent|Critical|High|Medium|Low|Info>
    Type: <e.g. Service or Interface Exposure>
    Affected Asset: <asset, linked when it is a hostname>
    To: <owning team>
    <intro paragraph: detected date, SLA days, GRC>
    Reporter / Ticket Number / Severity / Expected Remediation Date
    Description / Impact / Steps to Reproduce / Remediation/Recommendation / Key Evidence
    <closing paragraphs, with {contact} linked to the VM team>

Every executor (Judah's own sender, Blink, a ticket) uses this output, so
owners get the same notice whoever sends it.

Formats: ``json`` (fields + subject + html + text, for workflows), ``html``
(email body, inline styles only), ``text``, ``docx`` (Word attachment, no
third-party dependency) and ``pdf`` (via WeasyPrint when installed).
"""

from __future__ import annotations

import io
import re
import zipfile
from datetime import datetime
from typing import Any, Dict, List, Optional
from xml.sax.saxutils import escape as xml_escape

from jinja2 import Environment, select_autoescape

from app.models.finding_response import FindingResponse
from app.models.vulnerability import Vulnerability

TIER_LABELS = {
    "urgent": "Urgent", "critical": "Critical", "high": "High",
    "medium": "Medium", "low": "Low", "info": "Info",
}
REQUIRED_FIELDS = ("description", "impact", "steps_to_reproduce", "remediation")
_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.IGNORECASE)
_EMAIL_RE = re.compile(r"^[^@\s<>\"]+@[^@\s<>\"]+\.[^@\s<>\"]+$")
DEFAULT_LABELS = {
    "severity": "Severity", "type": "Type", "asset": "Affected Asset", "recipient": "To",
    "remediation_date": "Expected Remediation Date", "remediation": "Remediation/Recommendation",
}


class NoticeUnavailable(RuntimeError):
    """The requested format cannot be produced on this deployment."""


class _Default(dict):
    def __missing__(self, key):  # unknown placeholders stay visible instead of raising
        return "{" + key + "}"


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _fmt(template: str, values: Dict[str, Any]) -> str:
    try:
        return str(template or "").format_map(_Default(values))
    except (ValueError, IndexError):
        return str(template or "")


def asset_link(asset: str) -> Optional[str]:
    """https link for a hostname asset; None for IPs, CIDRs and cloud IDs."""
    value = _clean(asset)
    if value.startswith(("http://", "https://")):
        return value
    return f"https://{value}" if _HOST_RE.match(value) else None


def infer_type(vuln: Vulnerability) -> str:
    """Notice "Type" when the analyst did not set one at triage."""
    title = _clean(vuln.title).lower()
    if getattr(vuln, "port_service_id", None) or re.search(r"^\[?port \d+|port exposure|exposed (service|port)", title):
        return "Service or Interface Exposure"
    if re.search(r"certificate|\btls\b|\bssl\b", title):
        return "Certificate"
    if re.search(r"takeover|dangling", title):
        return "Subdomain Takeover"
    if re.search(r"secret|credential|api key|password", title):
        return "Exposed Credential"
    if re.search(r"misconfig|header|directory listing|default page", title):
        return "Misconfiguration"
    return "Vulnerability"


def _paragraph(template: str, values: Dict[str, Any], contact_name: str, contact_email: str) -> List[Dict[str, str]]:
    """Split a paragraph template into text/link segments around {contact}."""
    segments: List[Dict[str, str]] = []
    parts = str(template or "").split("{contact}")
    for i, part in enumerate(parts):
        text = _fmt(part, values)
        if text:
            segments.append({"text": text})
        if i < len(parts) - 1:
            if contact_email:
                segments.append({"text": contact_name, "href": f"mailto:{contact_email}"})
            else:
                segments.append({"text": contact_name})
    return segments


def build_fields(vuln: Vulnerability, response: Optional[FindingResponse], settings: Dict[str, Any]) -> Dict[str, Any]:
    notice = settings.get("notice") or {}
    labels = {**DEFAULT_LABELS, **(notice.get("labels") or {})}
    date_format = notice.get("date_format") or "%m/%d/%Y"

    def fmt_date(value: Optional[datetime]) -> str:
        if not value:
            return ""
        try:
            return value.strftime(date_format)
        except (ValueError, TypeError):
            return value.strftime("%m/%d/%Y")

    severity = _clean(getattr(vuln.severity, "value", vuln.severity)).lower() or "info"
    tier = (response.sla_tier if response and response.sla_tier else severity).lower()
    colors = notice.get("severity_colors") or {}
    color = str(colors.get(tier) or colors.get(severity) or "000000").lstrip("#")
    if not re.fullmatch(r"[0-9A-Fa-f]{6}", color):
        color = "000000"
    due = response.sla_due_at if response and response.sla_due_at else vuln.remediation_deadline
    internet = True if response is None or response.internet_accessible is None else bool(response.internet_accessible)
    asset = vuln.asset.value if vuln.asset else ""
    source_names = notice.get("source_names") or {}
    sources = sorted({o.source for o in (getattr(vuln, "observations", None) or [])}) or [vuln.detected_by or "manual"]
    reporter = ", ".join(dict.fromkeys(source_names.get(s, str(s).replace("_", " ").title()) for s in sources if s))
    contact_name = _clean(notice.get("contact_name")) or "Vulnerability Management"
    contact_email = _clean(notice.get("contact_email"))
    if contact_email and not _EMAIL_RE.match(contact_email):
        contact_email = ""

    fields: Dict[str, Any] = {
        "finding_id": vuln.id,
        "title": _clean(vuln.title),
        "severity": TIER_LABELS.get(tier, tier.title()),
        "severity_key": tier,
        "scanner_severity": TIER_LABELS.get(severity, severity.title()),
        "color": color,
        "finding_type": (response.finding_type if response and response.finding_type else infer_type(vuln)),
        "exposure": "external" if internet else "internal",
        "exposure_title": "External" if internet else "Internal",
        "remediation_date": fmt_date(due),
        "remediation_date_iso": due.date().isoformat() if due else "",
        "detected_date": fmt_date(vuln.first_detected),
        "sla_days": response.sla_days if response else None,
        "affected_asset": asset,
        "affected_asset_url": asset_link(asset),
        "affected_component": _clean(vuln.affected_component),
        "recipient": (response.owner_team or response.owner_email) if response else None,
        "owner_email": response.owner_email if response else None,
        "reporter": reporter,
        "ticket_number": (response.ticket_key if response else None) or "",
        "description": _clean(vuln.description),
        "impact": _clean(vuln.impact),
        "steps_to_reproduce": _clean(vuln.steps_to_reproduce),
        "remediation": _clean(vuln.remediation),
        "evidence": _clean(vuln.evidence),
        "cve_ids": list(vuln.cves or ([vuln.cve_id] if vuln.cve_id else [])),
        "references": [str(r) for r in (vuln.references or [])][:10],
        "labels": labels,
        "footer": _clean(notice.get("footer")),
    }
    values = {k: v for k, v in fields.items() if isinstance(v, (str, int)) and v is not None}
    values["sla_days"] = fields["sla_days"] if fields["sla_days"] is not None else ""
    values["asset"] = asset
    fields["header"] = _fmt(notice.get("header_template") or "", values).strip()
    intro_template = notice.get("intro_template") if fields["sla_days"] else notice.get("intro_no_sla_template")
    fields["intro"] = _paragraph(intro_template, values, contact_name, contact_email) if intro_template else []
    fields["closing"] = [
        _paragraph(t, values, contact_name, contact_email) for t in (notice.get("closing_templates") or []) if t
    ]
    fields["missing_fields"] = [k for k in REQUIRED_FIELDS if not fields[k]]
    subject_values = {k: (v if v not in (None, "") else "TBD") for k, v in values.items()}
    subject_values.setdefault("deadline", fields["remediation_date"] or "TBD")
    subject_values["deadline"] = fields["remediation_date"] or "TBD"
    subject = _fmt(notice.get("subject_template") or "[{severity}] {title}", subject_values)
    fields["subject"] = re.sub(r"[\r\n]+", " ", subject)[:250]
    return fields


def _sections(fields: Dict[str, Any]) -> List[tuple]:
    sections = [
        ("Description", "description"),
        ("Impact", "impact"),
        ("Steps to Reproduce", "steps_to_reproduce"),
        (fields["labels"]["remediation"], "remediation"),
    ]
    if fields.get("evidence"):
        sections.append(("Key Evidence", "evidence"))
    return sections


def _summary(fields: Dict[str, Any]) -> List[tuple]:
    rows = [("Reporter", fields["reporter"])]
    if fields["ticket_number"]:
        rows.append(("Ticket Number", fields["ticket_number"]))
    rows.append((fields["labels"]["severity"], fields["severity"]))
    rows.append((fields["labels"]["remediation_date"], fields["remediation_date"] or "To be set at triage"))
    return rows


def plain(segments: List[Dict[str, str]]) -> str:
    return "".join(s["text"] for s in segments)


# ── HTML / text ───────────────────────────────────────────────────────────────

_env = Environment(autoescape=select_autoescape(default=True, default_for_string=True))

_HTML = _env.from_string("""<!doctype html>
<html><head><meta charset="utf-8"><title>{{ f.subject }}</title></head>
<body style="margin:0;padding:24px;background:#ffffff;font-family:Calibri,Arial,Helvetica,sans-serif;color:#1E2F3D;font-size:14px;line-height:1.45">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:720px">
{% if f.header %}<tr><td style="font-size:22px;font-weight:bold;text-decoration:underline;padding-bottom:4px">{{ f.header }}</td></tr>{% endif %}
<tr><td style="padding-bottom:8px;font-size:22px;font-weight:bold;color:#{{ f.color }}">{{ f.title }}</td></tr>
<tr><td style="font-size:18px;font-weight:bold">{{ f.labels.severity }}: <span style="color:#{{ f.color }}">{{ f.severity }}</span></td></tr>
<tr><td style="font-size:18px"><b>{{ f.labels.type }}:</b> {{ f.finding_type }}</td></tr>
<tr><td style="font-size:18px;padding-bottom:12px"><b>{{ f.labels.asset }}:</b>
{% if f.affected_asset_url %}<a href="{{ f.affected_asset_url }}" style="color:#0563C1">{{ f.affected_asset }}</a>{% else %}{{ f.affected_asset }}{% endif %}{% if f.affected_component %} &middot; {{ f.affected_component }}{% endif %}</td></tr>
{% if f.recipient %}<tr><td style="padding-bottom:8px"><b>{{ f.labels.recipient }}:</b> {{ f.recipient }}</td></tr>{% endif %}
{% if f.intro %}<tr><td style="padding-bottom:12px">{% for s in f.intro %}{% if s.href %}<a href="{{ s.href }}" style="color:#0563C1">{{ s.text }}</a>{% else %}{{ s.text }}{% endif %}{% endfor %}</td></tr>{% endif %}
<tr><td style="padding-bottom:8px">{% for label, value in summary %}<b>{{ label }}:</b> {{ value }}<br>{% endfor %}</td></tr>
{% for label, key in sections %}
<tr><td style="padding-top:8px"><b>{{ label }}:</b>
{%- if key == "evidence" %}<pre style="margin:4px 0 0;white-space:pre-wrap;font-family:Consolas,Menlo,monospace;font-size:12px;background:#f4f6f8;padding:8px">{{ f.evidence }}</pre>
{%- else %} {{ (f[key] or "Not provided")|e|replace("\\n", "<br>"|safe) }}{% endif %}</td></tr>
{% endfor %}
{% if f.cve_ids %}<tr><td style="padding-top:8px"><b>CVE:</b> {{ f.cve_ids|join(", ") }}</td></tr>{% endif %}
{% for p in f.closing %}<tr><td style="padding-top:12px">{% for s in p %}{% if s.href %}<a href="{{ s.href }}" style="color:#0563C1">{{ s.text }}</a>{% else %}{{ s.text }}{% endif %}{% endfor %}</td></tr>{% endfor %}
{% if f.footer %}<tr><td style="padding-top:20px;color:#5b6b78;font-size:12px">{{ f.footer }}</td></tr>{% endif %}
<tr><td style="padding-top:20px;color:#8a97a3;font-size:11px">Finding #{{ f.finding_id }}</td></tr>
</table></body></html>
""")


def render_html(fields: Dict[str, Any]) -> str:
    return _HTML.render(f=fields, sections=_sections(fields), summary=_summary(fields))


def render_text(fields: Dict[str, Any]) -> str:
    labels = fields["labels"]
    asset = fields["affected_asset"] + (f" ({fields['affected_component']})" if fields["affected_component"] else "")
    lines = ([fields["header"]] if fields["header"] else []) + [
        fields["title"],
        f"{labels['severity']}: {fields['severity']}",
        f"{labels['type']}: {fields['finding_type']}",
        f"{labels['asset']}: {asset}",
    ]
    if fields["recipient"]:
        lines.append(f"{labels['recipient']}: {fields['recipient']}")
    lines.append("")
    if fields["intro"]:
        lines += [plain(fields["intro"]), ""]
    lines += [f"{label}: {value}" for label, value in _summary(fields)] + [""]
    for label, key in _sections(fields):
        lines += [f"{label}:", fields[key] or "Not provided", ""]
    if fields["cve_ids"]:
        lines += ["CVE: " + ", ".join(fields["cve_ids"]), ""]
    for p in fields["closing"]:
        text = plain(p)
        emails = [s["href"][7:] for s in p if s.get("href")]
        lines += [text + (f" ({emails[0]})" if emails else ""), ""]
    if fields.get("footer"):
        lines += [fields["footer"], ""]
    lines.append(f"Finding #{fields['finding_id']}")
    return "\n".join(lines).rstrip() + "\n"


# ── DOCX (hand-built OOXML, no python-docx dependency) ────────────────────────

_W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" ' \
     'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"'


def _run(text: str, *, bold: bool = False, color: Optional[str] = None, size: Optional[int] = None,
         mono: bool = False, link_style: bool = False, underline: bool = False) -> str:
    props = []
    if mono:
        props.append('<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/>')
    if bold:
        props.append("<w:b/>")
    if link_style:
        props.append('<w:color w:val="0563C1"/><w:u w:val="single"/>')
    else:
        if color:
            props.append(f'<w:color w:val="{color}"/>')
        if underline:
            props.append('<w:u w:val="single"/>')
    if size:
        props.append(f'<w:sz w:val="{size}"/>')
    rpr = f"<w:rPr>{''.join(props)}</w:rPr>" if props else ""
    parts = str(text).split("\n")
    body = '<w:br/>'.join(f'<w:t xml:space="preserve">{xml_escape(p)}</w:t>' for p in parts)
    return f"<w:r>{rpr}{body}</w:r>"


def _para(*runs: str, spacing_after: int = 120) -> str:
    return f'<w:p><w:pPr><w:spacing w:after="{spacing_after}"/></w:pPr>{"".join(runs)}</w:p>'


class _Links:
    def __init__(self) -> None:
        self.urls: List[str] = []

    def run(self, url: str, text: str, size: Optional[int] = None) -> str:
        self.urls.append(url)
        return f'<w:hyperlink r:id="rIdLink{len(self.urls)}">{_run(text, link_style=True, size=size)}</w:hyperlink>'

    def segments(self, segments: List[Dict[str, str]], size: Optional[int] = None) -> str:
        return "".join(
            self.run(s["href"], s["text"], size) if s.get("href") else _run(s["text"], size=size)
            for s in segments
        )


def render_docx(fields: Dict[str, Any]) -> bytes:
    body_color = "1E2F3D"
    labels = fields["labels"]
    links = _Links()
    paras = []
    if fields["header"]:
        paras.append(_para(_run(fields["header"], bold=True, size=32, underline=True), spacing_after=40))
    paras += [
        _para(_run(fields["title"], bold=True, color=fields["color"], size=32)),
        _para(_run(f"{labels['severity']}: ", bold=True, size=28),
              _run(fields["severity"], bold=True, color=fields["color"], size=28), spacing_after=40),
        _para(_run(f"{labels['type']}: ", bold=True, size=28), _run(fields["finding_type"], size=28), spacing_after=40),
    ]
    asset_text = fields["affected_asset"] + (f" ({fields['affected_component']})" if fields["affected_component"] else "")
    asset_run = (links.run(fields["affected_asset_url"], asset_text, 28) if fields.get("affected_asset_url")
                 else _run(asset_text, size=28))
    paras.append(_para(_run(f"{labels['asset']}: ", bold=True, size=28), asset_run))
    if fields["recipient"]:
        paras.append(_para(_run(f"{labels['recipient']}: ", bold=True), _run(fields["recipient"])))
    if fields["intro"]:
        paras.append(_para(links.segments(fields["intro"])))
    for label, value in _summary(fields):
        paras.append(_para(_run(f"{label}: ", bold=True), _run(value), spacing_after=20))
    paras.append(_para("", spacing_after=60))
    for label, key in _sections(fields):
        if key == "evidence":
            paras.append(_para(_run(f"{label}:", bold=True), spacing_after=40))
            paras.append(_para(_run(fields[key], color=body_color, size=20, mono=True)))
        else:
            paras.append(_para(_run(f"{label}: ", bold=True), _run(fields[key] or "Not provided", color=body_color)))
    if fields["cve_ids"]:
        paras.append(_para(_run("CVE: ", bold=True), _run(", ".join(fields["cve_ids"]))))
    for p in fields["closing"]:
        paras.append(_para(links.segments(p)))
    if fields.get("footer"):
        paras.append(_para(_run(fields["footer"], color="5B6B78", size=18)))
    paras.append(_para(_run(f"Finding #{fields['finding_id']}", color="8A97A3", size=16)))

    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f"<w:document {_W}><w:body>{''.join(paras)}"
        '<w:sectPr><w:pgSz w:w="12240" w:h="15840"/>'
        '<w:pgMar w:top="1080" w:right="1080" w:bottom="1080" w:left="1080" w:header="720" w:footer="720" w:gutter="0"/>'
        "</w:sectPr></w:body></w:document>"
    )
    doc_rels = "".join(
        f'<Relationship Id="rIdLink{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" '
        f'Target="{xml_escape(url, {chr(34): "&quot;"})}" TargetMode="External"/>'
        for i, url in enumerate(links.urls, start=1)
    )
    styles = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:cs="Calibri"/>'
        '<w:sz w:val="22"/></w:rPr></w:rPrDefault></w:docDefaults></w:styles>'
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/word/document.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            '<Override PartName="/word/styles.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
            "</Types>"
        ))
        z.writestr("_rels/.rels", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
            'Target="word/document.xml"/></Relationships>'
        ))
        z.writestr("word/_rels/document.xml.rels", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rIdStyles" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
            f'Target="styles.xml"/>{doc_rels}</Relationships>'
        ))
        z.writestr("word/document.xml", document)
        z.writestr("word/styles.xml", styles)
    return buf.getvalue()


def render_pdf(fields: Dict[str, Any]) -> bytes:
    try:
        from weasyprint import HTML  # heavy optional dependency
    except Exception as exc:  # ImportError, or missing system libraries
        raise NoticeUnavailable("PDF rendering needs WeasyPrint on this deployment; use format=docx or html") from exc
    return HTML(string=render_html(fields)).write_pdf()


def filename(fields: Dict[str, Any], ext: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "-", fields["title"]).strip("-")[:60] or "finding"
    return f"finding-{fields['finding_id']}-{slug}.{ext}"
