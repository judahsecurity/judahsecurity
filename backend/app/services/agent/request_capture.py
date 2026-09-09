"""Bounded execution-owned REST request templates, never credential storage.

Only transport/browser callbacks populate this store. Imported inventories are
discovery hints and cannot acquire replay authority. Values stay session-local.
"""

import json
import re
import secrets
from collections import OrderedDict
from copy import deepcopy
from urllib.parse import urlsplit, urlunsplit

from app.services.agent.evidence_store import origin, redact_artifact
from app.services.agent.runtime_mapper import normalize_request


class RequestCaptureStore:
    def __init__(self, limit=200):
        self._records = OrderedDict()
        self.limit = limit

    def record(self, request, *, identity, source, evidence_id=""):
        """Return safe metadata, or None when faithful replay is unsupported."""
        try:
            origin(request["url"])
            parts = urlsplit(request["url"])
            # Query credentials, multipart, binary and templated values require
            # dedicated adapters. Do not silently replay a modified approximation.
            if parts.query or parts.fragment or "{{" in request["url"]:
                return None
            method = request.get("method", "GET").upper()
            if method not in ("GET", "PATCH", "PUT", "DELETE"):
                return None
            body = request.get("body")
            if body in (None, "", b""):
                body = None
            elif isinstance(body, (str, bytes)):
                body = json.loads(body)
            if body is not None and not isinstance(body, dict):
                return None
            encoded = json.dumps(body, allow_nan=False)
            if len(encoded.encode()) > 65536 or "{{" in encoded:
                return None
            if redact_artifact(body) != body or re.search(
                r'"[^"\n]*(?:password|secret|token|credential|api.?key|authorization|cookie)[^"\n]*"\s*:',
                encoded,
                re.IGNORECASE,
            ):
                return None
            # Carry only representation headers. Authentication and routing
            # headers come exclusively from the identity registry at execution.
            headers = {
                k.lower(): v
                for k, v in request.get("headers", {}).items()
                if k.lower() in ("accept", "content-type")
            }
            spec = {
                "url": urlunsplit(parts),
                "method": method,
                "headers": headers,
                "body": body,
            }
            ops = normalize_request(spec, identity=identity, source=source)
            if len(ops) != 1 or ops[0]["protocol"] != "rest":
                return None
            capture_id = secrets.token_hex(16)
            row = {
                "id": capture_id,
                "operation_id": ops[0]["id"],
                "identity": identity,
                "source": source,
                "evidence_id": evidence_id,
                "request": deepcopy(spec),
            }
            self._records[capture_id] = row
            while len(self._records) > self.limit:
                self._records.popitem(last=False)
            return self.describe(row)
        except (ValueError, TypeError, KeyError, AttributeError):
            return None

    @staticmethod
    def describe(row):
        spec = row["request"]
        return {
            **{k: v for k, v in row.items() if k != "request"},
            "method": spec["method"],
            "url": spec["url"],
            "body_fields": sorted((spec["body"] or {}).keys()),
        }

    def list(self, operation_id=None):
        return [
            self.describe(row)
            for row in self._records.values()
            if operation_id is None or row["operation_id"] == operation_id
        ]

    def get(self, capture_id):
        if capture_id not in self._records:
            raise ValueError("Unknown or expired execution-owned capture")
        return deepcopy(self._records[capture_id])
