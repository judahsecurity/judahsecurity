"""One Chromium launch configuration for the assessment worker and smoke check."""

from __future__ import annotations

import os

from app.services.agent.assessment_proxy import assessment_browser_proxy


def launch_options() -> dict:
    options = {
        "headless": True,
        "chromium_sandbox": (
            os.getenv("AEGIS_BROWSER_ENABLE_SANDBOX", "0").lower() in ("1", "true", "yes")
            and os.getenv("AEGIS_BROWSER_DISABLE_SANDBOX", "0").lower() not in ("1", "true", "yes")
        ),
    }
    executable = os.getenv("AEGIS_CHROMIUM_PATH") or os.getenv("PROWL_CHROMIUM_PATH") or os.getenv("CHROME_BIN")
    if executable:
        options["executable_path"] = executable
    proxy = assessment_browser_proxy()
    if proxy:
        options["proxy"] = proxy
        if proxy.get("username"):
            # Judah Gate: trust only the Gate's leaf key, not every bad certificate.
            from app.services.agent.judah_gate_ca import leaf_spki_sha256

            options["args"] = [f"--ignore-certificate-errors-spki-list={leaf_spki_sha256()}"]
    return options
