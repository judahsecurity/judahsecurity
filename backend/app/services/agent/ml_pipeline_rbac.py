"""Self-registered user can train/delete ML models (CWE-285 / CWE-863).

Gold bar: low-priv / self-reg JWT gets 200/202/204 on POST /api/v1/train/ (or
celery queue) while a documented admin sibling is 401/403 for anonymous.
Do not DELETE production models. One tiny canary train or OPTIONS/authz probe.
Open signup is the internet exposure, not a second finding.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

ML_WRITE_RE = re.compile(
    r"(?i)(/api/v1/train/?|/api/v1/celery-task/?|logixtwin-train|"
    r"/api/drf-celery|/api/v1/optimize/?)"
)
DELETE_CELERY_RE = re.compile(r"(?i)celery-task")

_FINDING_HINTS = (
    "celery-task",
    "celery_task",
    "/api/v1/train",
    "logixtwin",
    "ml pipeline",
    "ml model training",
    "ml_pipeline_rbac",
    "missing rbac",
    "missing role-based",
)

WRITEUP_RULES = (
    "ML pipeline missing RBAC (CWE-285 / CWE-863): self-registered or low-priv JWT "
    "can POST /api/v1/train/ or queue celery. Do not DELETE production models; one "
    "canary train or OPTIONS/authz probe. Open signup is the internet exposure, not "
    "a second finding. SUBMIT High. Remediation: admin/ML-engineer roles on train/"
    "delete/celery; email verification on signup."
)

REVIEW_RULES = (
    "ML train/delete missing RBAC (Ask Marcus): keep Demonstrated High. Do not ask "
    "hunters to DELETE production models. Retest bar: non-admin POST /api/v1/train/ "
    "returns 403. Do not dump datasets."
)

VERIFIER_ADDENDUM = (
    "This is an ML-pipeline RBAC candidate. Re-derive ONLY:\n"
    "1) If a throwaway self-reg session exists, POST /api/v1/train/ with a tiny "
    "canary body (or OPTIONS). Expect 200/202/204 for missing RBAC.\n"
    "2) Do NOT DELETE /api/v1/celery-task/. Do not dump training datasets. Do not "
    "inject pickle/code.\n"
    "confirmed if low-priv/self-reg is 200/202/204 on train/celery. refuted if "
    "403 for non-admin. Closed signup is not a refute if a mapped low-priv token "
    "still trains."
)

HUNTER_RULES = (
    "ML train/delete missing RBAC: throwaway self-reg if open; POST /api/v1/train/ "
    "or celery queue as that user. Do not DELETE production models. "
    "queue_finding_followups(vuln_type='ml_pipeline_rbac')."
)


def is_ml_write_path(url: str) -> bool:
    if not url:
        return False
    return bool(ML_WRITE_RE.search(urlparse(url).path or url))


def destructive_violation(method: str, url: str) -> Optional[str]:
    if (method or "GET").upper() != "DELETE":
        return None
    if not is_ml_write_path(url) and not DELETE_CELERY_RE.search(url or ""):
        return None
    return (
        "Blocked: do not DELETE production celery-task / ML models. Prove missing "
        "RBAC with POST /api/v1/train/ (tiny canary) or OPTIONS. "
        "queue_finding_followups(vuln_type='ml_pipeline_rbac')."
    )


def destructive_violation_in_text(text: str) -> Optional[str]:
    blob = text or ""
    if not re.search(r"(?i)\bdelete\b", blob):
        return None
    if not (ML_WRITE_RE.search(blob) or DELETE_CELERY_RE.search(blob)):
        return None
    if "-X DELETE" in blob or "-XDELETE" in blob.replace(" ", "") or "method\":\"DELETE" in blob or "method\": \"DELETE" in blob:
        return (
            "Blocked: do not DELETE production celery-task / ML models. Prove with "
            "POST /api/v1/train/ canary or OPTIONS."
        )
    return None


def canary_train_body() -> Dict[str, Any]:
    return {"aegis_canary": True, "rows": 1}


def sanitize_ml_body(
    url: str,
    method: str,
    body: Optional[str],
) -> Tuple[Optional[str], Optional[str]]:
    if not is_ml_write_path(url):
        return body, None
    if (method or "GET").upper() not in ("POST", "PUT", "PATCH"):
        return body, None
    raw = (body or "").strip()
    if not raw:
        return json.dumps(canary_train_body(), separators=(",", ":")), (
            "injected tiny ML canary train body (do not dump datasets)"
        )
    return body, None


def is_ml_rbac_finding(text: str) -> bool:
    blob = (text or "").lower()
    return any(h in blob for h in _FINDING_HINTS)


def has_ml_rbac_proof(text: str) -> bool:
    blob = (text or "").lower()
    accepted = any(s in blob for s in ("200", "202", "204", "ml_rbac_bypass"))
    identity = any(
        t in blob
        for t in (
            "self-reg",
            "self-registered",
            "throwaway",
            "low-priv",
            "non-admin",
            "any user",
            "any registrant",
        )
    )
    return accepted and identity


def caps_critical_as_high(text: str) -> bool:
    return is_ml_rbac_finding(text)


def annotate_compare_proof(
    *,
    baseline_url: str,
    mutant_url: str,
    baseline_status: int,
    mutant_status: int,
) -> Tuple[List[str], Optional[Dict[str, Any]], Optional[str]]:
    ml = is_ml_write_path(mutant_url) or is_ml_write_path(baseline_url)
    if not ml:
        return [], None, None
    if baseline_status in (401, 403) and mutant_status in (200, 202, 204):
        proof = {
            "lane": "ml_pipeline_rbac",
            "demonstrated": True,
            "baseline_status": baseline_status,
            "mutant_status": mutant_status,
            "submit": (
                "High — low-priv/self-reg can train or queue ML jobs. "
                "Do not DELETE production models."
            ),
        }
        return ["ml_rbac_bypass"], proof, "MUTANT_BYPASS_CANDIDATE"
    return [], None, None
