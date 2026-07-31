"""
Detection feedback helpers.

Shared logic for recording that a detection template's LOGIC is wrong (keyed on
template_id) and for generating a copy-pasteable upstream bug report suitable
for filing against the detection template's source project
(e.g. projectdiscovery/nuclei-templates).

Used by both the scanner worker (automatic recording when the validator agent
returns a false-positive verdict caused by template logic) and the API
(analyst-driven feedback).
"""

from typing import Optional

from sqlalchemy.orm import Session

from app.models.detection_feedback import DetectionFeedback


def generate_upstream_nuclei_report(
    *,
    template_id: str,
    target: Optional[str] = None,
    detected_by: Optional[str] = "nuclei",
    severity: Optional[str] = None,
    logic_issue: str = "",
    evidence: Optional[str] = None,
    reasoning: Optional[str] = None,
) -> str:
    """Render a Markdown bug report describing a false-positive detection.

    The report is intentionally generic (no org-identifying data beyond the
    template id and a redactable target) so it can be filed upstream.
    """
    tool = (detected_by or "nuclei").strip() or "nuclei"
    sev = (severity or "unknown").strip()
    target_line = target or "<redacted target>"

    lines = [
        f"## False positive: `{template_id}`",
        "",
        f"- **Tool:** {tool}",
        f"- **Template ID:** `{template_id}`",
        f"- **Reported severity:** {sev}",
        f"- **Target:** {target_line}",
        "",
        "### Summary",
        "",
        "This template produced a finding that did not hold up under active "
        "re-testing. The match appears to be caused by the template's own "
        "detection logic rather than a real, exploitable condition on the target.",
        "",
        "### Detection logic issue",
        "",
        (logic_issue.strip() or "The matcher fired without confirming the "
         "vulnerable behavior (e.g. it matched a banner/version/response string "
         "rather than proving the issue is actually exploitable)."),
        "",
    ]

    if reasoning:
        lines += ["### Validator reasoning", "", reasoning.strip(), ""]

    if evidence:
        lines += [
            "### Re-test evidence",
            "",
            "```",
            evidence.strip()[:4000],
            "```",
            "",
        ]

    lines += [
        "### Suggested fix",
        "",
        "Tighten the matcher so it only fires when the vulnerable behavior is "
        "actually demonstrated (e.g. require a response that proves the action "
        "succeeded, add a negative matcher for the benign case, or downgrade the "
        "template to `info` if it is detection-only).",
    ]

    return "\n".join(lines)


def record_detection_feedback(
    db: Session,
    *,
    organization_id: int,
    template_id: str,
    logic_issue: str,
    detected_by: Optional[str] = "nuclei",
    verdict: Optional[str] = "false_positive",
    severity: Optional[str] = None,
    target: Optional[str] = None,
    evidence: Optional[str] = None,
    reasoning: Optional[str] = None,
    example_vulnerability_id: Optional[int] = None,
    finding_validation_id: Optional[int] = None,
    source: str = "validator_agent",
    reported_by_user_id: Optional[int] = None,
    upstream_report: Optional[str] = None,
) -> DetectionFeedback:
    """Create and persist a DetectionFeedback row (generating the report if needed)."""
    if upstream_report is None:
        upstream_report = generate_upstream_nuclei_report(
            template_id=template_id,
            target=target,
            detected_by=detected_by,
            severity=severity,
            logic_issue=logic_issue,
            evidence=evidence,
            reasoning=reasoning,
        )

    feedback = DetectionFeedback(
        organization_id=organization_id,
        template_id=template_id,
        detected_by=detected_by,
        verdict=verdict,
        logic_issue=logic_issue,
        upstream_report=upstream_report,
        example_vulnerability_id=example_vulnerability_id,
        finding_validation_id=finding_validation_id,
        source=source,
        reported_by_user_id=reported_by_user_id,
    )
    db.add(feedback)
    db.commit()
    db.refresh(feedback)
    return feedback
