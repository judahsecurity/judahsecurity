"""Bounded execution-owned request templates, never credential storage.

Only transport/browser callbacks populate this store. Imported inventories are
discovery hints and cannot acquire replay authority. Values stay session-local.
"""

import json
import re
import secrets
from collections import Counter, OrderedDict
from copy import deepcopy
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from app.services.agent.evidence_store import origin, redact_artifact
from app.services.agent.runtime_mapper import normalize_request


class RequestCaptureStore:
    def __init__(self, limit=200):
        self._records = OrderedDict()
        self.limit = limit
        self.evicted = 0
        self.rejected = Counter()

    def _reject(self, reason):
        self.rejected[reason] += 1
        return None

    def record(
        self,
        request,
        *,
        identity,
        source,
        evidence_id="",
        hypothesis_id="",
        coverage_cell_id="",
        tenant="",
        parameter="",
        test_type="",
        candidate_id="",
        proof_run_id="",
        proof_escalation_id="",
        verifier_run_id="",
        finding_id="",
    ):
        """Return safe metadata, or None when faithful replay is unsupported."""
        try:
            origin(request["url"])
            parts = urlsplit(request["url"])
            # Keep the original query privately for faithful replay. Credential
            # parameters, fragments and templated URLs are not proof captures.
            if parts.fragment or "{{" in request["url"]:
                return self._reject("unsupported_url")
            query = parse_qsl(parts.query, keep_blank_values=True)
            if len(parts.query) > 8192 or len(query) > 32 or any(
                not key for key, _ in query
            ):
                return self._reject("unsupported_query")
            if any(
                re.search(
                    r"password|passwd|secret|token|credential|api.?key|authorization|cookie|session|csrf",
                    key,
                    re.IGNORECASE,
                )
                for key, _ in query
            ):
                return self._reject("sensitive_query")
            method = request.get("method", "GET").upper()
            if method not in ("GET", "POST", "PATCH", "PUT", "DELETE"):
                return self._reject("unsupported_method")
            content_type = next(
                (str(value).lower() for key, value in (request.get("headers") or {}).items()
                 if str(key).lower() == "content-type"),
                "",
            )
            body = request.get("body")
            if body in (None, "", b""):
                body = None
            elif isinstance(body, bytes):
                body = body.decode("utf-8")
            if body is None:
                body_format = "none"
            elif "application/x-www-form-urlencoded" in content_type:
                if not isinstance(body, str) or len(body.encode()) > 65536:
                    return self._reject("unsupported_body")
                fields = parse_qsl(body, keep_blank_values=True)
                if len(fields) > 64 or "{{" in body or any(
                    not key or re.search(
                        r"password|passwd|secret|token|credential|api.?key|authorization|cookie|session|csrf",
                        key, re.IGNORECASE,
                    ) for key, _ in fields
                ):
                    return self._reject("unsupported_body")
                body_format = "form"
            else:
                if isinstance(body, str):
                    body = json.loads(body)
                if not isinstance(body, dict):
                    return self._reject("unsupported_body")
                encoded = json.dumps(body, allow_nan=False)
                if len(encoded.encode()) > 65536 or "{{" in encoded:
                    return self._reject("unsupported_body")
                if redact_artifact(body) != body or re.search(
                    r'"[^"\n]*(?:password|secret|token|credential|api.?key|authorization|cookie)[^"\n]*"\s*:',
                    encoded,
                    re.IGNORECASE,
                ):
                    return self._reject("sensitive_body")
                body_format = "json"
            if method in ("GET", "DELETE") and body is not None:
                return self._reject("unsupported_body")
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
            if len(ops) != 1 or ops[0]["protocol"] not in ("rest", "graphql"):
                return self._reject("not_rest_or_static")
            protocol = ops[0]["protocol"]
            if protocol == "graphql":
                query_text = body.get("query") if isinstance(body, dict) else None
                operation = re.match(r"\s*(query|mutation)\b", query_text or "")
                shorthand = isinstance(query_text, str) and query_text.lstrip().startswith("{")
                definitions = re.findall(
                    r"(?:^|})\s*(?:query|mutation|subscription)\b",
                    query_text or "",
                )
                if body_format != "json" or not (operation or shorthand) or len(definitions) > 1:
                    return self._reject("unsupported_graphql")
                graphql_kind = operation.group(1) if operation else "query"
            else:
                graphql_kind = ""
            capture_id = secrets.token_hex(16)
            row = {
                "id": capture_id,
                "operation_id": ops[0]["id"],
                "identity": identity,
                "source": source,
                "evidence_id": evidence_id,
                "hypothesis_id": str(hypothesis_id or ""),
                "coverage_cell_id": str(coverage_cell_id or ""),
                "tenant": str(tenant or ""),
                "parameter": str(parameter or ""),
                "test_type": str(test_type or ""),
                "candidate_id": str(candidate_id or ""),
                "proof_run_id": str(proof_run_id or ""),
                "proof_escalation_id": str(proof_escalation_id or ""),
                "verifier_run_id": str(verifier_run_id or ""),
                "finding_id": str(finding_id or ""),
                "request": deepcopy(spec),
                "body_format": body_format,
                "protocol": protocol,
                "graphql_kind": graphql_kind,
            }
            self._records[capture_id] = row
            while len(self._records) > self.limit:
                self._records.popitem(last=False)
                self.evicted += 1
            return self.describe(row)
        except (ValueError, TypeError, KeyError, AttributeError):
            return self._reject("invalid_request")

    @staticmethod
    def describe(row):
        from app.services.agent.authorization_leads import leads_for_capture

        spec = row["request"]
        parts = urlsplit(spec["url"])
        return {
            **{k: v for k, v in row.items() if k != "request"},
            "method": spec["method"],
            "url": urlunsplit(parts._replace(query="", fragment="")),
            "query_fields": sorted(
                {key for key, _ in parse_qsl(parts.query, keep_blank_values=True)}
            ),
            "body_fields": sorted(
                {key for key, _ in parse_qsl(spec["body"], keep_blank_values=True)}
                if row.get("body_format") == "form"
                else (spec["body"] or {}).keys()
            ),
            "authorization_references": [
                {key: lead[key] for key in (
                    "reference", "path_index", "value_shape", "priority_score", "replayable"
                )}
                for lead in leads_for_capture(row)
            ],
        }

    def authorization_leads(self, operation_id=None):
        from app.services.agent.authorization_leads import rank_leads

        return rank_leads([
            row for row in self._records.values()
            if operation_id is None or row["operation_id"] == operation_id
        ])

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
