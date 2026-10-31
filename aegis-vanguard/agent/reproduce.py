"""Independent, deterministic reproduction of baseline-class findings.

A published finding should not rest on a hunter's or exploit agent's own
transcript. For the two baseline classes — SQL injection and reflected XSS —
this module re-runs the deterministic differential probe from scratch against
the finding's own endpoint/parameter (using the captured baseline request when
available) and only reports the signal as reproduced when the probe sees it
again. Classes without a deterministic reproducer return ``applicable=False``
so the LLM validator's verdict stands unchanged for them.

The probe callables are injected so the verdict logic is unit-tested without a
network; in production they default to the real scanners.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from agent.coverage import _normalize_class

_SQLI_CLASSES = frozenset({"sqli"})
_XSS_CLASSES = frozenset({"xss", "reflected_xss", "stored_xss"})

ProbeFn = Callable[..., Dict[str, Any]]
DomFn = Callable[..., Dict[str, Any]]


def _default_sqli_probe(url, bridge, **kw):
    import scanners
    return scanners.run_probe_sqli_params(url, bridge, **kw)


def _default_xss_probe(url, bridge, **kw):
    import scanners
    return scanners.run_probe_xss_reflection(url, bridge, **kw)


def _finding_request(finding: Dict[str, Any], baseline: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    baseline = baseline or {}
    method = str(baseline.get("method") or finding.get("method") or "GET").upper()
    url = str(
        baseline.get("url")
        or finding.get("endpoint") or finding.get("url") or finding.get("matched_at") or ""
    )
    body = str(baseline.get("body") or finding.get("body") or "")
    headers_json = str(baseline.get("headers_json") or "{}")
    params = str(
        finding.get("parameter_spec") or finding.get("param")
        or finding.get("parameter") or ""
    )
    return {
        "method": method, "url": url, "body": body,
        "headers_json": headers_json, "params": params,
    }


def _verdict(
    vuln_class: str,
    reproduced: bool,
    probe_name: str,
    result: Dict[str, Any],
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    candidates = result.get("candidates") or result.get("findings") or []
    signals = sorted({
        str(sig)
        for item in candidates if isinstance(item, dict)
        for sig in (item.get("signals") or [item.get("vuln_type") or item.get("type") or ""])
        if sig
    })
    verdict = {
        "applicable": True,
        "class": vuln_class,
        "reproduced": bool(reproduced),
        "probe": probe_name,
        "signals": signals,
        "candidate_count": len(candidates),
        "evidence": "; ".join(
            str(item.get("evidence") or item.get("why") or "")
            for item in candidates if isinstance(item, dict) and (item.get("evidence") or item.get("why"))
        )[:1000],
    }
    if extra:
        verdict.update(extra)
    return verdict


def reproduce_finding(
    finding: Dict[str, Any],
    *,
    baseline: Optional[Dict[str, Any]] = None,
    bridge: Any = None,
    probe_sqli: Optional[ProbeFn] = None,
    probe_xss: Optional[ProbeFn] = None,
    dom_xss: Optional[DomFn] = None,
    timeout: int = 20,
) -> Dict[str, Any]:
    """Re-run the deterministic probe for a finding and report reproduction.

    Returns a verdict dict. ``applicable`` is False for classes without a
    deterministic reproducer. ``reproduced`` is None when the probe could not
    run (e.g. a network error) so callers can distinguish "did not reproduce"
    from "could not test".
    """
    cls = _normalize_class(
        finding.get("vuln_type") or finding.get("type")
        or finding.get("vulnerability_class")
    )
    req = _finding_request(finding, baseline)
    if not req["url"]:
        return {"applicable": False, "class": cls, "reproduced": None,
                "reason": "finding has no testable URL"}

    if cls in _SQLI_CLASSES:
        probe = probe_sqli or _default_sqli_probe
        try:
            result = probe(
                req["url"], bridge, method=req["method"], body=req["body"],
                params=req["params"], headers_json=req["headers_json"], timeout=timeout,
            )
        except Exception as exc:  # noqa: BLE001
            return {"applicable": True, "class": "sqli", "reproduced": None,
                    "probe": "probe_sqli_params", "reason": f"probe error: {exc}"}
        return _verdict("sqli", bool(result.get("candidates")), "probe_sqli_params", result)

    if cls in _XSS_CLASSES:
        probe = probe_xss or _default_xss_probe
        try:
            result = probe(
                req["url"], bridge, method=req["method"], body=req["body"],
                params=req["params"], headers_json=req["headers_json"], timeout=timeout,
            )
        except Exception as exc:  # noqa: BLE001
            return {"applicable": True, "class": "xss", "reproduced": None,
                    "probe": "probe_xss_reflection", "reason": f"probe error: {exc}"}
        reproduced = bool(result.get("candidates"))
        extra: Dict[str, Any] = {}
        # Stronger proof: confirm the payload actually executes in a browser.
        if reproduced and dom_xss is not None:
            try:
                dom = dom_xss(req["url"], params=req["params"])
                extra["dom_execution"] = dom
                if isinstance(dom, dict) and dom.get("executed") is False:
                    reproduced = False
            except Exception as exc:  # noqa: BLE001
                extra["dom_execution"] = {"error": str(exc)}
        return _verdict("xss", reproduced, "probe_xss_reflection", result, extra)

    return {"applicable": False, "class": cls, "reproduced": None,
            "reason": "no deterministic reproducer for this class"}


__all__ = ["reproduce_finding"]
