"""WPScan / scanner exit-code semantics: findings-found is success, not failure."""

import importlib.util
from pathlib import Path


def _load_cli_results():
    """Load cli_results without importing app.services.mcp package (pulls MCPServer)."""
    path = Path(__file__).resolve().parents[1] / "app" / "services" / "mcp" / "cli_results.py"
    spec = importlib.util.spec_from_file_location("cli_results_mod", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


_cli = _load_cli_results()
normalize_cli_result = _cli.normalize_cli_result
wpscan_output_looks_complete = _cli.wpscan_output_looks_complete


WPSCAN_FINDINGS = """
[+] URL: https://www.emulate3d.com/
[i] WordPress version 5.8.1 identified
 | [!] Title: Yoast SEO < 22.6 - Reflected Cross-Site Scripting
[i] 3 plugin(s) Identified.
[i] 1 user(s) Identified.
[+] admin
 | Found By: Wp Json Api
[+] WPScan DB API OK
"""


def test_wpscan_exit_5_is_success():
    out = normalize_cli_result("execute_wpscan", {
        "success": False,
        "output": WPSCAN_FINDINGS,
        "error": "progress bar noise on stderr",
        "exit_code": 5,
    })
    assert out["success"] is True
    assert out["error"] is None
    assert "[!] Title:" in out["output"]


def test_wpscan_incomplete_stays_failure():
    out = normalize_cli_result("execute_wpscan", {
        "success": False,
        "output": "Scraped data",
        "error": "aborted",
        "exit_code": 1,
    })
    assert out["success"] is False
