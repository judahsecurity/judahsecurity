"""One Chromium launch configuration for the assessment worker and smoke check."""

from __future__ import annotations

import os


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
    return options
