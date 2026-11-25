"""CMSeeK parser (console output or its ``cms.json`` result).

Ported from Vanguard ``run_cmseek``. Fix: Vanguard took ``line.split(":")[-1]``
of any line with "CMS:" or "Detected CMS", so "CMS Detected, CMS ID: wp,
Detection method: generator" became the CMS name "generator". The name, id,
version and detection method are now read from their own fields.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from asm_scanner_core.parsers.base import Observation, ParsedResult, extract_json, run_status, strip_ansi

TOOL = "cmseek"

_NAME = re.compile(r"\bCMS:\s*(?P<name>[^\n\r]+)")
_ID = re.compile(r"CMS ID:\s*(?P<id>[\w.-]+)", re.I)
_METHOD = re.compile(r"Detection method:\s*(?P<method>[\w .-]+)", re.I)
_VERSION = re.compile(r"(?:CMS|WordPress|Joomla|Drupal) Version:\s*(?P<version>[\w.+-]+)", re.I)
_URL = re.compile(r"(?:CMS )?URL:\s*(?P<url>https?://\S+)", re.I)
_TARGET = re.compile(r"Target:\s*(?P<target>\S+)", re.I)
_FAILED = re.compile(r"CMS Detection failed|Failed to detect CMS|could not detect", re.I)

_ID_NAMES = {"wp": "WordPress", "joom": "Joomla", "dru": "Drupal", "mg": "Magento",
             "shopify": "Shopify", "ghost": "Ghost", "ty 3": "TYPO3", "tp3": "TYPO3"}


def _from_json(data: Dict[str, Any]) -> Optional[Dict[str, str]]:
    name = str(data.get("cms_name") or "")
    cms_id = str(data.get("cms_id") or "")
    if not (name or cms_id):
        return None
    version = next((str(v) for k, v in data.items()
                    if k.endswith("_version") and v and not isinstance(v, (dict, list))), "")
    return {"name": name or _ID_NAMES.get(cms_id, cms_id), "id": cms_id, "version": version,
            "url": str(data.get("cms_url") or ""), "target": str(data.get("url") or ""), "method": ""}


def parse_cmseek(output: str, exit_code: Optional[int] = None, *, timed_out: bool = False,
                 **_context: Any) -> ParsedResult:
    text = strip_ansi(output or "")
    found: Optional[Dict[str, str]] = None
    data = extract_json(text)
    if isinstance(data, dict):
        found = _from_json(data)
    if found is None:
        name_match = _NAME.search(text)
        id_match = _ID.search(text)
        if name_match or id_match:
            cms_id = id_match.group("id") if id_match else ""
            name = name_match.group("name").strip() if name_match else _ID_NAMES.get(cms_id, cms_id)
            version = _VERSION.search(text)
            url = _URL.search(text)
            target = _TARGET.search(text)
            method = _METHOD.search(text)
            found = {"name": name, "id": cms_id, "version": version.group("version") if version else "",
                     "url": url.group("url") if url else "", "target": target.group("target") if target else "",
                     "method": method.group("method").strip() if method else ""}
    observations = []
    if found and found["name"]:
        title = f"CMS detected: {found['name']}" + (f" {found['version']}" if found["version"] else "")
        observations.append(Observation(
            kind="cms", title=title, target=found["target"],
            attributes={"cms": found["name"], "cms_id": found["id"], "version": found["version"],
                        "detection_method": found["method"], "vendor_url": found["url"]},
        ))
    status, reason = run_status(exit_code=exit_code, timed_out=timed_out, have_data=bool(observations))
    if status == "ok" and not observations and not _FAILED.search(text):
        status, reason = "inconclusive", "no CMS verdict in output"
    return ParsedResult(tool=TOOL, status=status, observations=observations,
                        counts={"cms": len(observations)}, reason=reason)
