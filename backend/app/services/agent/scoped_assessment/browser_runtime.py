"""One Chromium launch configuration for the assessment worker and smoke check."""

from __future__ import annotations

import os

from app.services.agent.assessment_proxy import assessment_browser_proxy


# Chromium's own background services (component updates, Google account
# checks, safe-browsing and metrics pings) would otherwise leave through the
# assessment proxy alongside target traffic. Assessment browsers need none.
QUIET_CHROMIUM_ARGS = (
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-sync",
    "--disable-default-apps",
    "--disable-domain-reliability",
    "--disable-client-side-phishing-detection",
    "--disable-features=OptimizationHints,MediaRouter,Translate,AutofillServerCommunication",
    "--no-first-run",
    "--no-default-browser-check",
    "--metrics-recording-only",
)


def launch_options() -> dict:
    options = {
        "headless": True,
        "args": list(QUIET_CHROMIUM_ARGS),
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
    return options
