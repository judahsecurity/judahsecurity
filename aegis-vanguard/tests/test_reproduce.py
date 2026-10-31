from agent.reproduce import reproduce_finding


def _probe_with(candidates):
    captured = {}

    def probe(url, bridge, **kw):
        captured["url"] = url
        captured.update(kw)
        return {"candidates": candidates, "findings": candidates,
                "vulnerable": bool(candidates)}

    return probe, captured


def test_sqli_reproduced_when_probe_sees_candidate():
    probe, captured = _probe_with([
        {"parameter": "query:category", "signals": ["boolean_diff", "timing"],
         "evidence": "true/false responses differ"},
    ])
    verdict = reproduce_finding(
        {"vuln_type": "sqli", "endpoint": "https://t.test/catalog",
         "parameter": "category", "method": "GET"},
        baseline={"method": "GET", "url": "https://t.test/catalog?category=1",
                  "headers_json": "{}", "body": ""},
        probe_sqli=probe,
    )
    assert verdict["applicable"] and verdict["reproduced"] is True
    assert verdict["probe"] == "probe_sqli_params"
    assert "boolean_diff" in verdict["signals"]
    # The probe was driven with the captured baseline, not reconstructed values.
    assert captured["url"] == "https://t.test/catalog?category=1"
    assert captured["params"] == "category"


def test_sqli_not_reproduced_when_probe_empty():
    probe, _ = _probe_with([])
    verdict = reproduce_finding(
        {"vuln_type": "sqli", "endpoint": "https://t.test/x", "parameter": "id"},
        probe_sqli=probe,
    )
    assert verdict["reproduced"] is False


def test_probe_error_yields_inconclusive_not_false():
    def boom(url, bridge, **kw):
        raise RuntimeError("network down")

    verdict = reproduce_finding(
        {"vuln_type": "sqli", "endpoint": "https://t.test/x", "parameter": "id"},
        probe_sqli=boom,
    )
    assert verdict["reproduced"] is None  # could not test != did not reproduce


def test_xss_requires_browser_execution_when_dom_checker_present():
    probe, _ = _probe_with([{"vuln_type": "xss", "evidence": "unescaped reflection"}])

    # Reflection reproduces, but the browser says it did not execute -> not reproduced.
    verdict = reproduce_finding(
        {"vuln_type": "xss", "endpoint": "https://t.test/s", "parameter": "q"},
        probe_xss=probe,
        dom_xss=lambda url, params="": {"executed": False},
    )
    assert verdict["reproduced"] is False
    assert verdict["dom_execution"] == {"executed": False}

    verdict2 = reproduce_finding(
        {"vuln_type": "xss", "endpoint": "https://t.test/s", "parameter": "q"},
        probe_xss=probe,
        dom_xss=lambda url, params="": {"executed": True},
    )
    assert verdict2["reproduced"] is True


def test_non_baseline_class_is_not_applicable():
    verdict = reproduce_finding(
        {"vuln_type": "ssrf", "endpoint": "https://t.test/f", "parameter": "url"},
    )
    assert verdict["applicable"] is False
    assert verdict["reproduced"] is None


def test_missing_url_is_not_applicable():
    verdict = reproduce_finding({"vuln_type": "sqli", "parameter": "id"})
    assert verdict["applicable"] is False
