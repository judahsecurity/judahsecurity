"""URL-discovery and CMS wrappers must pass targets as data, never through a shell."""
import subprocess

import pytest

import scanners

HOSTILE = "example.com; touch /tmp/pwned #"


class Bridge:
    def __init__(self):
        self.urls, self.findings = [], []

    def submit_url(self, url, **_meta):
        self.urls.append(url)

    def submit_finding(self, finding):
        self.findings.append(finding)

    def flush(self):
        pass


@pytest.fixture
def calls(monkeypatch):
    seen = []

    def fake_run(cmd, **kwargs):
        seen.append((cmd, kwargs))
        out = "https://example.com/a\n" if cmd[0] in {"waybackurls", "gau"} else "[+] CMS: WordPress\n"
        return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")

    monkeypatch.setattr(scanners, "_tool_available", lambda _name: True)
    monkeypatch.setattr(scanners.subprocess, "run", fake_run)
    return seen


@pytest.mark.parametrize("fn, argv", [
    (scanners.run_waybackurls, ["waybackurls"]),
    (scanners.run_gau, ["gau", "--subs"]),
])
def test_url_discovery_feeds_domain_on_stdin(calls, fn, argv):
    bridge = Bridge()
    assert fn(HOSTILE, bridge) == ["https://example.com/a"]
    cmd, kwargs = calls[0]
    assert cmd == argv
    assert kwargs["input"] == HOSTILE + "\n"
    assert not kwargs.get("shell")


def test_cmseek_passes_target_as_single_argument(calls):
    assert scanners.run_cmseek(HOSTILE, Bridge()) == "WordPress"
    cmd, kwargs = calls[0]
    assert cmd == ["cmseek", "-u", HOSTILE, "--batch"]
    assert "bash" not in cmd and not kwargs.get("shell")
