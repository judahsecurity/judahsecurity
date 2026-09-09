#!/usr/bin/env python3
"""Check standalone Interactsh availability and optionally verify a live callback."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

_SERVICE_PATH = Path(__file__).resolve().parents[1] / "app" / "services" / "interactsh_service.py"
_SPEC = importlib.util.spec_from_file_location("aegis_interactsh_check", _SERVICE_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError(f"Could not load Interactsh service from {_SERVICE_PATH}")
interactsh_service = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = interactsh_service
_SPEC.loader.exec_module(interactsh_service)


def live_check(timeout_seconds: int = 30) -> dict:
    registration = interactsh_service.register()
    if not registration.get("success"):
        return registration
    session_id = registration["session_id"]
    callback_url = (
        registration["payload_url"].rstrip("/")
        + "/aegis-health-"
        + uuid.uuid4().hex[:12]
    )
    try:
        try:
            with urllib.request.urlopen(callback_url, timeout=15) as response:
                response.read(256)
        except urllib.error.HTTPError:
            # The collector may reject the path after recording the interaction.
            pass
        deadline = time.time() + max(5, min(int(timeout_seconds), 45))
        polls = 0
        while time.time() < deadline:
            polls += 1
            result = interactsh_service.poll(session_id)
            if result.get("interactions"):
                return {
                    "success": True,
                    "callback_observed": True,
                    "payload_domain": registration.get("payload_domain"),
                    "polls": polls,
                    "protocols": sorted(
                        {
                            str(item.get("protocol") or "unknown")
                            for item in result["interactions"]
                        }
                    ),
                }
            time.sleep(2)
        return {
            "success": False,
            "callback_observed": False,
            "payload_domain": registration.get("payload_domain"),
            "polls": polls,
            "error": "No callback observed before the readiness timeout",
        }
    finally:
        interactsh_service.stop(session_id)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--live",
        action="store_true",
        help="Register with the public service, trigger the generated URL, and poll it.",
    )
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args(argv)

    result = interactsh_service.health()
    if args.live and result.get("success"):
        result = {"health": result, "live": live_check(args.timeout)}
    print(json.dumps(result, indent=2, default=str))
    success = result.get("success") if not args.live else result["live"].get("success")
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
