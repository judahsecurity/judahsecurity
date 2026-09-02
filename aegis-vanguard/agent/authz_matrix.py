"""
Authorization matrix — automated broken-access-control detection.

Broken access control is OWASP A01 and the most prevalent, most missed class in
real applications — and flags don't test it. This is the Autorize-style
technique pros use, automated and wired to the proof gate: take requests that
were made *with credentials*, replay each one under a different identity (user
B) and with no credentials at all, and diff the responses.

  authorized request (as A)  →  replay as B      →  same private 2xx body? → horizontal BAC / IDOR
                             →  replay unauthenticated → same 2xx body?     → missing authorization

A hit registers a verified `response_diff` proof token, so the finding passes
the gate automatically. The critical false-positive guard: only requests whose
baseline actually carried an auth header are tested, so public pages (200 to
everyone) are never flagged.
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from agent.http_session import (
    _AUTH_HEADERS,
    HttpRequest,
    HttpResponse,
    ProxyBackend,
    apply_mutations,
    response_diff,
)
from agent.finding_oracle import register_proof

logger = logging.getLogger("agent.authz_matrix")

# Classifications
BROKEN_ACCESS = "BROKEN_ACCESS"   # another user's identity reached the resource
AUTH_BYPASS = "AUTH_BYPASS"       # no identity at all reached the resource
ENFORCED = "ENFORCED"             # rejected or diverged — access control held
INCONCLUSIVE = "INCONCLUSIVE"

_SIMILARITY_BAC = 0.95            # body this similar under a changed identity == same resource


def _has_auth(request: HttpRequest) -> bool:
    return any(k.lower() in _AUTH_HEADERS for k in request.headers)


def _is_2xx(resp: HttpResponse) -> bool:
    return 200 <= (resp.status or 0) < 300


def classify(identity: str, base: HttpResponse, resp: HttpResponse) -> str:
    """Classify one identity's replay against the authorized baseline."""
    if resp.error or not _is_2xx(base):
        return INCONCLUSIVE
    if resp.status in (401, 403):
        return ENFORCED
    if _is_2xx(resp):
        d = response_diff(base, resp)
        if d["identical_body"] or d["body_similarity"] >= _SIMILARITY_BAC:
            return AUTH_BYPASS if identity == "unauth" else BROKEN_ACCESS
    return ENFORCED


@dataclass
class MatrixFinding:
    url: str
    method: str
    identity: str
    classification: str
    proof_token_id: Optional[str] = None
    body_similarity: Optional[float] = None

    def to_dict(self) -> dict:
        return {
            "title": f"Broken access control: {self.method} {self.url}",
            "vuln_type": "broken_access_control",
            "url": self.url,
            "endpoint": self.url,
            "method": self.method,
            "identity": self.identity,
            "classification": self.classification,
            "severity": "high",
            "confidence": "confirmed",
            "proof_token_id": self.proof_token_id,
            "body_similarity": self.body_similarity,
        }


@dataclass
class MatrixReport:
    tested: int = 0
    skipped_no_auth: int = 0
    findings: List[MatrixFinding] = field(default_factory=list)
    results: List[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "tested": self.tested,
            "skipped_no_auth": self.skipped_no_auth,
            "broken_access_findings": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "results": self.results,
        }


def run_authorization_matrix(
    requests: List[HttpRequest],
    backend: ProxyBackend,
    *,
    identity_b: Optional[Dict[str, str]] = None,
    include_unauth: bool = True,
    register: bool = True,
) -> MatrixReport:
    """Replay each credentialed request under other identities and diff.

    identity_b: headers for a second user (e.g. {"Cookie": "session=bob"}); the
    baseline identity is stripped first so B fully replaces A. include_unauth
    adds the no-credentials column (missing-authorization detection).
    """
    identities: Dict[str, dict] = {}
    if include_unauth:
        identities["unauth"] = {"strip_auth": True}
    if identity_b:
        identities["user_b"] = {"strip_auth": True, "set_headers": identity_b}

    report = MatrixReport()
    if not identities:
        return report

    for request in requests:
        if not _has_auth(request):
            report.skipped_no_auth += 1
            continue
        base = backend.send(request)
        if not _is_2xx(base):
            # Baseline was not a successful authorized resource — nothing to bypass.
            report.results.append({"url": request.url, "identity": "baseline",
                                   "classification": INCONCLUSIVE, "status": base.status})
            continue
        report.tested += 1
        for name, mut in identities.items():
            resp = backend.send(apply_mutations(request, mut))
            cls = classify(name, base, resp)
            sim = response_diff(base, resp)["body_similarity"]
            token_id = None
            if cls in (BROKEN_ACCESS, AUTH_BYPASS) and register:
                token = register_proof(
                    "response_diff", verified=True, subject=request.url,
                    detail=f"{cls} as {name}: same 2xx body (similarity {sim:.2f})")
                token_id = token.token_id
                report.findings.append(MatrixFinding(
                    url=request.url, method=request.method, identity=name,
                    classification=cls, proof_token_id=token_id, body_similarity=sim))
                logger.info("AUTHZ MATRIX: %s on %s %s (as %s)",
                            cls, request.method, request.url, name)
            report.results.append({
                "url": request.url, "method": request.method, "identity": name,
                "classification": cls, "status": resp.status,
                "body_similarity": round(sim, 3), "proof_token_id": token_id,
            })
    return report
