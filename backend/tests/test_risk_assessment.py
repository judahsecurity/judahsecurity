"""Marcus RA quality gate — demonstrated-only, no inflation to Critical."""

from __future__ import annotations

from app.services.agent.risk_assessment import (
    format_gaps,
    pending_payload,
    queue_pending_ra,
    validate_risk_assessment,
)
from app.services.agent.engagement_brain import (
    EngagementBrain,
    methodology_progress,
)
from app.services.agent.skill_md import load_skill_md


APPSMITH_RA = {
    "verdict": "confirm",
    "confirmed_severity": "high",
    "cvss_score": 8.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
    "sla": "now",
    "why_this_severity": (
        "Internet self-registration plus REST action execution is working "
        "non-blind SSRF from the Azure Kubernetes pod. appsmith-0 hostname "
        "bypassed the IP allowlist and returned health plus tenant config."
    ),
    "why_not_higher": (
        "Azure IMDS and localhost literals were blocked. No writes, no cloud "
        "token, no customer PII dump. Kubernetes API died on TLS."
    ),
    "why_not_lower": (
        "Any internet user can mint an App Developer session and fetch arbitrary "
        "URLs from inside the cluster with the full upstream body returned."
    ),
    "demonstrated": [
        {"asset": "attacker OOB host", "result": "200 plus interact.sh body in execute response"},
        {"asset": "appsmith-0:8080/api/v1/health", "result": "All systems are up"},
        {"asset": "appsmith-0:8080/api/v1/tenants/current", "result": "tenant id and org config"},
        {"asset": "pod IP leak", "result": "10.244.10.131 in WebClient errors"},
    ],
    "not_demonstrated": [
        {"target": "Azure IMDS", "outcome": "blocked by allowlist"},
        {"target": "internal writes", "outcome": "not attempted"},
    ],
    "control_failures": [
        {"control": "identity", "failure": "open FORM signup with no email verification"},
        {"control": "SSRF filter", "failure": "pod DNS and empty-base REST URLs not blocked"},
    ],
    "business_risk": (
        "Production Appsmith control plane on Azure AKS. Outsider can map the "
        "namespace and read unauthenticated Appsmith JSON from the pod network."
    ),
    "remediation_sequence": [
        {
            "when": "now",
            "action": "Disable self-registration and delete test accounts",
            "done_when": "POST /api/v1/users without invite returns 4xx",
        },
        {
            "when": "same window",
            "action": "Block pod DNS, cluster names, and RFC1918 in action execute",
            "done_when": "appsmith-0 and OOB hosts fail with host not allowed",
        },
    ],
    "retest_criteria": [
        "Signup disabled or domain-gated",
        "Unprivileged user cannot execute REST actions to unapproved hosts",
        "appsmith-0 and RFC1918 rejected",
        "Datasource test is admin-only",
    ],
    "ticket_title": "High — Appsmith SSRF via REST action execution",
    "ra_note": (
        "Confirmed High. Open signup plus action execute yields non-blind SSRF "
        "from AKS. IMDS blocked. Disable signup immediately."
    ),
    "cwes": ["CWE-918", "CWE-284"],
}


def test_appsmith_packet_confirms_high():
    parsed, gaps = validate_risk_assessment(APPSMITH_RA, proposed_severity="high")
    assert gaps == [], gaps
    assert parsed["verdict"] == "confirm"
    assert parsed["confirmed_severity"] == "high"


def test_hmac_signing_key_is_critical_for_marcus():
    from app.services.js_client_signing_secrets import allows_critical_ra

    assert allows_critical_ra(
        "CWE-321 client HMAC-SHA256 signing key reconstructed via Object.keys "
        "join in a public JavaScript bundle; HmacSHA256 alg HS256"
    )
    assert not allows_critical_ra(
        "CouchDB AuthSession cookie hmac with couch_httpd_auth.secret"
    )
    packet = dict(APPSMITH_RA)
    packet["confirmed_severity"] = "critical"
    packet["verdict"] = "confirm"
    packet["ticket_title"] = "Critical — CWE-321 HMAC signing key in public JS"
    packet["why_this_severity"] = (
        "Unauthenticated GET of main-es2015.js reconstructs an HMAC-SHA256 "
        "signing key via Object.keys(this.waste).join('') and signs HS256 JWTs "
        "for every API request. MQTT and RFID credentials are in the same bundle."
    )
    packet["why_not_lower"] = (
        "The signing secret is in a public bundle with no auth. Backend timeout "
        "does not reduce exposure. Gitleaks never sees a string literal."
    )
    packet["ra_note"] = (
        "Confirm Critical CWE-321. Reconstruction is enough. Do not drop on "
        "ilens_api timeout. Rotate HMAC, MQTT, and RFID. Move signing server-side."
    )
    packet["business_risk"] = (
        "ICS/MES iLens digital twin: forged API signatures and SCADA MQTT access "
        "from an internet-reachable Angular bundle."
    )
    packet["demonstrated"] = [
        {"asset": "main-es2015.js", "result": "HTTP 200 no auth, Object.keys waste HMAC key"},
        {"asset": "HmacSHA256 HS256", "result": "signs all API requests from reconstructed key"},
        {"asset": "MQTT/RFID", "result": "broker and badge creds in the same chunk"},
    ]
    packet["cwes"] = ["CWE-321", "CWE-798"]
    parsed, gaps = validate_risk_assessment(packet, proposed_severity="critical")
    assert gaps == [], gaps
    assert parsed["confirmed_severity"] == "critical"


def test_critical_without_write_is_rejected():
    inflated = dict(APPSMITH_RA)
    inflated["confirmed_severity"] = "critical"
    inflated["verdict"] = "upgrade"
    parsed, gaps = validate_risk_assessment(inflated)
    assert parsed is None
    assert any("Critical requires" in g for g in gaps)


def test_weak_ra_fails_gate():
    parsed, gaps = validate_risk_assessment({
        "verdict": "confirm",
        "confirmed_severity": "high",
        "why_this_severity": "SSRF is bad",
    })
    assert parsed is None
    assert len(gaps) >= 4
    assert "RA IMPROVE" in format_gaps(gaps)


def test_info_skips_depth_requirements():
    parsed, gaps = validate_risk_assessment({
        "verdict": "confirm",
        "confirmed_severity": "info",
        "why_this_severity": "Banner disclosure only — no privileged data retrieved from this host during the test window.",
        "why_not_higher": "unused",
        "why_not_lower": "unused",
    })
    assert gaps == [], gaps
    assert parsed["confirmed_severity"] == "info"


def test_pending_ra_blocks_complete():
    brain = EngagementBrain()
    queue_pending_ra(brain, finding_id=42, title="SSRF", severity="high")
    progress = methodology_progress(brain)
    # Unseeded brains are not ready anyway; seed a killed high-pri card so
    # the only blocker is the pending RA.
    from app.services.agent.engagement_brain import Hypothesis
    brain.hypotheses = [
        Hypothesis(
            id="m1",
            title="seeded",
            assumption="x",
            test="x",
            pass_criteria="x",
            kill_criteria="x",
            specialist="ssrf",
            status="killed",
            priority="high",
            source="methodology",
            methodology_id="ssrf_url_fetch",
        )
    ]
    brain.pending_risk_assessments = [{"finding_id": 42, "title": "SSRF", "status": "pending"}]
    progress = methodology_progress(brain)
    assert progress["pending_risk_assessments"] == 1
    assert progress["ready_to_complete"] is False
    assert any(b.get("specialist") == "risk_assessor" for b in progress["blockers"])


def test_skill_pack_loads():
    pack = load_skill_md("risk_assessment")
    assert pack
    assert "Marcus" in pack["body"]
    assert "assess_finding_risk" in pack["body"]
    assert "why_not_higher" in pack["body"]


def test_pending_payload_shape():
    p = pending_payload(title="SSRF", severity="high", finding_id=3)
    assert p["status"] == "pending"
    assert p["assessor"] == "marcus"
