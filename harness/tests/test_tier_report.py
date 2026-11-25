import json
from pathlib import Path

from local_harness.benchmark.tier_report import finding_tier, main, tier_report
from local_harness.findings import normalize

EXPECTED = [
    {"id": "E-SQLI", "category": "sqli", "endpoint": "/rest/user/login"},
    {"id": "E-XSS", "category": "xss", "endpoint": "/search"},
    {"id": "E-SSRF", "category": "ssrf", "endpoint": "/profile/image/url"},
    {"id": "E-IDOR", "category": "idor", "endpoint": "/rest/basket/{id}"},
]


def _f(title, url, level, confirmed=True):
    return {"type": "vulnerability", "title": title, "severity": "high", "url": url,
            "confidence": "confirmed" if confirmed else "low",
            "tags": (["confirmed"] if confirmed else []) + [level], "verification_level": level}


def _findings():
    return [normalize(row) for row in (
        _f("SQL injection in login", "http://x/rest/user/login", "exploit_verified"),
        _f("Reflected XSS", "http://x/search?q=1", "reproduced"),
        _f("SSRF via profile image", "http://x/profile/image/url", "unverified", confirmed=False),
        _f("SQL injection in feedback", "http://x/api/Feedbacks", "unverified", confirmed=False),
    )]


def test_tier_detection_falls_back_to_confirmed_flag():
    legacy = normalize({"type": "vulnerability", "title": "SQLi", "confidence": "confirmed"})
    assert finding_tier(legacy) == "exploit_verified"
    assert finding_tier(normalize({"type": "vulnerability", "title": "x"})) == "other"


def test_cumulative_recall_and_noise_per_tier():
    report = tier_report(_findings(), EXPECTED)
    steps = {s["through_tier"]: s for s in report["cumulative"]}
    assert steps["exploit_verified"]["recall"] == 0.25
    assert steps["reproduced"]["added_defects"] == ["E-XSS"]
    assert steps["unverified"]["added_defects"] == ["E-SSRF"]
    assert steps["unverified"]["added_false_positives"] == ["SQL injection in feedback"]
    assert report["recovered_by_looser_tiers"] == ["E-SSRF", "E-XSS"]
    assert report["missed"] == ["E-IDOR"]
    assert report["final_recall"] == 0.75
    assert report["findings_by_tier"]["unverified"] == 2


def test_cli_gate(tmp_path: Path):
    gt = tmp_path / "gt.json"
    gt.write_text(json.dumps({"app": {"expected_findings": EXPECTED}}))
    sink = tmp_path / "findings.jsonl"
    sink.write_text("\n".join(json.dumps(_f("SQL injection in login", "http://x/rest/user/login",
                                            "exploit_verified")) for _ in range(1)) + "\n")
    out = tmp_path / "report.json"
    args = ["--ground-truth", str(gt), "--target", "app", "--findings", str(sink), "--out", str(out)]
    assert main(args + ["--min-recall", "0.2"]) == 0
    assert main(args + ["--min-recall", "0.5"]) == 2
    assert json.loads(out.read_text())["final_recall"] == 0.25


def test_real_world_corpus_is_valid():
    corpus = json.loads((Path(__file__).parents[1] / "local_harness/benchmark/ground_truth/REAL_WORLD.json").read_text())
    for name, entry in corpus.items():
        if name.startswith("_"):
            continue
        ids = [e["id"] for e in entry["expected_findings"]]
        assert len(ids) == len(set(ids)) and entry["setup"]["up"] and entry["setup"]["down"]
        assert all("method" not in e for e in entry["expected_findings"])  # sink records carry no method
