"""Pure core of the XBEN suite runner: flag computation, discovery, port
parsing, suite summary, and regression detection. The live driver (make /
docker compose / run_pentest) is not exercised here — it needs docker."""

import json
import os
import tempfile
import unittest
from pathlib import Path

import importlib.util

_spec = importlib.util.spec_from_file_location(
    "bench_xben", Path(__file__).resolve().parents[1] / "bench_xben.py")
bench = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bench)


class ExpectedFlagTest(unittest.TestCase):
    def test_matches_real_xben_020(self):
        # ground truth: the flag captured in a real XBEN-020-24 run
        self.assertEqual(
            bench.expected_flag("XBEN-020-24"),
            "FLAG{6e5d772fb6e28ca52985079acf7bfa46d729870e6bae73166208f1fdcd831667}")

    def test_uppercases_name(self):
        self.assertEqual(bench.expected_flag("xben-020-24"),
                         bench.expected_flag("XBEN-020-24"))

    def test_format(self):
        f = bench.expected_flag("XBEN-001-24")
        self.assertTrue(f.startswith("FLAG{") and f.endswith("}"))
        self.assertEqual(len(f), len("FLAG{}") + 64)


class DiscoverTest(unittest.TestCase):
    def _make_bench(self, root, name, meta=None):
        d = Path(root) / name
        d.mkdir(parents=True)
        (d / "docker-compose.yml").write_text("services: {}\n")
        if meta is not None:
            (d / "benchmark.json").write_text(json.dumps(meta))
        return d

    def test_discovers_and_filters(self):
        with tempfile.TemporaryDirectory() as root:
            self._make_bench(root, "XBEN-001-24", {"level": 1, "win_condition": "flag"})
            self._make_bench(root, "XBEN-002-24", {"level": 2, "win_condition": "question"})
            self._make_bench(root, "XBEN-003-24", {"level": 1, "win_condition": "flag"})
            # a dir with no compose file must be ignored
            (Path(root) / "notabench").mkdir()

            all_flag = bench.discover_benchmarks(root)
            self.assertEqual([b["name"] for b in all_flag],
                             ["XBEN-001-24", "XBEN-003-24"])  # question one excluded
            self.assertEqual(all_flag[0]["expected"], bench.expected_flag("XBEN-001-24"))

    def test_only_and_level_filters(self):
        with tempfile.TemporaryDirectory() as root:
            self._make_bench(root, "XBEN-001-24", {"level": 1, "win_condition": "flag"})
            self._make_bench(root, "XBEN-003-24", {"level": 3, "win_condition": "flag"})
            self.assertEqual(
                [b["name"] for b in bench.discover_benchmarks(root, only=["XBEN-003-24"])],
                ["XBEN-003-24"])
            self.assertEqual(
                [b["name"] for b in bench.discover_benchmarks(root, levels=[1])],
                ["XBEN-001-24"])

    def test_missing_meta_defaults_to_flag(self):
        with tempfile.TemporaryDirectory() as root:
            self._make_bench(root, "XBEN-009-24", meta=None)
            got = bench.discover_benchmarks(root)
            self.assertEqual(len(got), 1)
            self.assertEqual(got[0]["win_condition"], "flag")


class PublishedPortTest(unittest.TestCase):
    def test_json_lines_prefers_port_80(self):
        out = "\n".join([
            json.dumps({"Service": "internal-service", "Publishers": None}),
            json.dumps({"Service": "web", "Publishers": [
                {"URL": "0.0.0.0", "TargetPort": 80, "PublishedPort": 56348, "Protocol": "tcp"}]}),
        ])
        self.assertEqual(bench.parse_published_port(out), 56348)

    def test_json_array_form(self):
        out = json.dumps([
            {"Service": "web", "Publishers": [
                {"TargetPort": 80, "PublishedPort": 49155}]}])
        self.assertEqual(bench.parse_published_port(out), 49155)

    def test_falls_back_to_first_when_no_80(self):
        out = json.dumps({"Service": "web", "Publishers": [
            {"TargetPort": 8080, "PublishedPort": 33000}]})
        self.assertEqual(bench.parse_published_port(out), 33000)

    def test_raises_when_nothing_published(self):
        out = json.dumps({"Service": "internal", "Publishers": None})
        with self.assertRaises(RuntimeError):
            bench.parse_published_port(out)

    def test_empty_output(self):
        with self.assertRaises(RuntimeError):
            bench.parse_published_port("")


class SummaryAndRegressionTest(unittest.TestCase):
    def test_summarize(self):
        results = [
            {"name": "A", "status": "PASS"},
            {"name": "B", "status": "FAIL"},
            {"name": "C", "status": "NO_CAPTURES"},
        ]
        s = bench.summarize(results)
        self.assertEqual((s["passed"], s["failed"], s["ungraded"], s["graded"]), (1, 1, 1, 2))
        self.assertAlmostEqual(s["pass_rate"], 50.0)

    def test_regression_detected(self):
        baseline = {"pass_rate": 100.0, "results": {"A": "PASS", "B": "PASS"}}
        summary = {"pass_rate": 50.0, "results": {"A": "PASS", "B": "FAIL"}}
        cmp = bench.compare_baseline(summary, baseline)
        self.assertEqual(cmp["regressed"], ["B"])
        self.assertEqual(cmp["regressed_count"], 1)
        self.assertAlmostEqual(cmp["rate_drop"], 50.0)

    def test_no_regression_when_improved(self):
        baseline = {"pass_rate": 50.0, "results": {"A": "PASS", "B": "FAIL"}}
        summary = {"pass_rate": 100.0, "results": {"A": "PASS", "B": "PASS"}}
        cmp = bench.compare_baseline(summary, baseline)
        self.assertEqual(cmp["regressed"], [])
        self.assertLess(cmp["rate_drop"], 0)


if __name__ == "__main__":
    os.chdir(Path(__file__).resolve().parents[1])
    unittest.main()
