"""
HTTP session store & interception layer — stateful, evidence-bearing HTTP.

Why this exists
---------------
Proving broken access control / IDOR / CSRF / business-logic flaws requires
carrying identity across requests and *replaying* a captured request under a
changed identity, then showing the response changed (or didn't) in a way that
proves the flaw. A one-shot `send_http_request` can't: it has no memory and no
notion of "the same request as a different user". A session store + replay +
response-diff can — and the diff is the auditable artifact. This is the same
principle as the flag oracle: machine-checkable proof, not report prose.

Pluggable backend
------------------
`ProxyBackend` abstracts *how a request is sent*. The bundled default
(`ScannersBackend`) delegates to the existing send path
(`scanners.run_send_http_request`), inheriting its scope / private-range
safety. `CaidoBackend` is a first-class adapter that drives a running Caido
instance for Strix-style interception when the operator provides one. Tests
inject a `ProxyBackend` returning canned responses, so the whole layer is
exercised with no network.
"""

import difflib
import json
import logging
import os
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from agent.tracing import redact_value

logger = logging.getLogger("agent.http_session")

# Headers stripped by the strip_auth mutation — the classic "does it still work
# without my credentials / as nobody?" access-control probe.
_AUTH_HEADERS = {"cookie", "authorization", "x-api-key", "x-auth-token",
                 "x-csrf-token", "x-xsrf-token"}


# ── Value types ────────────────────────────────────────────────────────────
@dataclass
class HttpRequest:
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""

    def clone(self) -> "HttpRequest":
        return HttpRequest(self.method, self.url, dict(self.headers), self.body)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class HttpResponse:
    status: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    elapsed_ms: Optional[int] = None
    error: str = ""
    redirect_history: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.error and self.status != 0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class HttpTransaction:
    id: str
    request: HttpRequest
    response: HttpResponse
    label: str = ""
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "label": self.label,
            "created_at": self.created_at,
            "request": self.request.to_dict(),
            "response": self.response.to_dict(),
        }


def response_from_scanner_dict(d: dict) -> HttpResponse:
    """Map the dict returned by scanners.run_send_http_request → HttpResponse."""
    if not isinstance(d, dict):
        return HttpResponse(error=f"non-dict result: {type(d).__name__}")
    if d.get("error"):
        return HttpResponse(error=str(d["error"]),
                            elapsed_ms=d.get("elapsed_ms"))
    return HttpResponse(
        status=int(d.get("status") or 0),
        headers={str(k): str(v) for k, v in (d.get("headers") or {}).items()},
        body=str(d.get("body") or ""),
        elapsed_ms=d.get("elapsed_ms"),
        redirect_history=list(d.get("redirect_history") or []),
    )


# ── Mutations ──────────────────────────────────────────────────────────────
def apply_mutations(req: HttpRequest, mutations: dict) -> HttpRequest:
    """Return a mutated clone of a request. Supported mutation keys:

      method / url / body : replace outright
      set_headers  {name: value}  add or overwrite; value null → delete header
      set_query    {param: value} add or overwrite query param; null → delete
      strip_auth   true           drop Cookie/Authorization/API-key/CSRF headers

    strip_auth is the "as nobody" test; set_headers with another user's session
    cookie is the "as a different user" test — the two core authz probes.
    """
    out = req.clone()
    mutations = mutations or {}

    if isinstance(mutations.get("method"), str):
        out.method = mutations["method"]
    if isinstance(mutations.get("url"), str):
        out.url = mutations["url"]
    if "body" in mutations and isinstance(mutations["body"], str):
        out.body = mutations["body"]

    if mutations.get("strip_auth"):
        out.headers = {k: v for k, v in out.headers.items()
                       if k.lower() not in _AUTH_HEADERS}

    set_headers = mutations.get("set_headers")
    if isinstance(set_headers, dict):
        for name, value in set_headers.items():
            # case-insensitive overwrite/delete
            existing = [k for k in out.headers if k.lower() == str(name).lower()]
            for k in existing:
                del out.headers[k]
            if value is not None:
                out.headers[name] = str(value)

    set_query = mutations.get("set_query")
    if isinstance(set_query, dict):
        parts = urlsplit(out.url)
        params = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
                  if k not in set_query]
        for k, v in set_query.items():
            if v is not None:
                params.append((k, str(v)))
        out.url = urlunsplit(parts._replace(query=urlencode(params)))

    return out


# ── Response diff (the evidence primitive) ─────────────────────────────────
def response_diff(a: HttpResponse, b: HttpResponse) -> dict:
    """Structured diff of two responses, with an access-control–oriented read.

    Returns a hint, not a verdict: the agent/validator still decides, but the
    diff itself is the artifact a human can audit.
    """
    ratio = difflib.SequenceMatcher(None, a.body or "", b.body or "").ratio()
    diff = {
        "status_a": a.status,
        "status_b": b.status,
        "status_changed": a.status != b.status,
        "len_a": len(a.body or ""),
        "len_b": len(b.body or ""),
        "body_similarity": round(ratio, 4),
        "identical_body": (a.body or "") == (b.body or ""),
        "error_b": b.error or None,
    }
    diff["summary"] = _diff_summary(a, b, ratio)
    return diff


def _diff_summary(a: HttpResponse, b: HttpResponse, ratio: float) -> str:
    if b.error:
        return f"replay errored ({b.error}); no conclusion"
    if b.status in (401, 403) and a.status not in (401, 403):
        return (f"replay was rejected ({a.status}→{b.status}) — access control "
                "appears ENFORCED")
    if a.status == b.status and ratio >= 0.95:
        return (f"near-identical response ({b.status}, similarity {ratio:.2f}) "
                "under the changed/absent identity — POSSIBLE broken access "
                "control; confirm the body contains the other identity's data")
    if a.status == b.status and ratio < 0.6:
        return (f"same status ({b.status}) but body diverged (similarity "
                f"{ratio:.2f}) — likely identity-scoped; access control plausible")
    return (f"status {a.status}→{b.status}, body similarity {ratio:.2f} — "
            "inconclusive, inspect both responses")


# ── Backends ───────────────────────────────────────────────────────────────
class ProxyBackend(ABC):
    """Abstracts how an HttpRequest is actually sent."""

    name = "abstract"

    @abstractmethod
    def send(self, request: HttpRequest) -> HttpResponse:  # pragma: no cover
        ...


class ScannersBackend(ProxyBackend):
    """Bundled default: reuse the existing send path (curl/httpx under the hood,
    plus its private-range block), so replay obeys the same safety as a normal
    send_http_request."""

    name = "scanners"

    def __init__(self, bridge=None, follow_redirects: bool = True):
        self.bridge = bridge
        self.follow_redirects = follow_redirects

    def send(self, request: HttpRequest) -> HttpResponse:
        import scanners
        result = scanners.run_send_http_request(
            method=request.method,
            url=request.url,
            headers_json=json.dumps(request.headers),
            body=request.body,
            follow_redirects=self.follow_redirects,
            bridge=self.bridge,
        )
        return response_from_scanner_dict(result)


class CaidoBackend(ProxyBackend):
    """Adapter for a running Caido instance (Strix-style interception/replay).

    Requires the operator to run Caido and expose its API; configure with
    AEGIS_CAIDO_API (base URL) and AEGIS_CAIDO_TOKEN. Unconfigured, `send`
    raises an actionable error rather than silently falling back — you should
    know which engine produced your evidence. The request shape below is
    validated against a live Caido instance, not in this repo's tests.
    """

    name = "caido"

    def __init__(self, api_url: Optional[str] = None, token: Optional[str] = None):
        self.api_url = (api_url or os.environ.get("AEGIS_CAIDO_API") or "").rstrip("/")
        self.token = token or os.environ.get("AEGIS_CAIDO_TOKEN")

    def send(self, request: HttpRequest) -> HttpResponse:
        if not self.api_url:
            raise RuntimeError(
                "CaidoBackend requires a running Caido instance: set "
                "AEGIS_CAIDO_API (and AEGIS_CAIDO_TOKEN). Falling back silently "
                "would hide which engine produced the evidence."
            )
        import urllib.request

        payload = json.dumps({
            "method": request.method,
            "url": request.url,
            "headers": request.headers,
            "body": request.body,
        }).encode()
        req = urllib.request.Request(
            f"{self.api_url}/replay",
            data=payload,
            headers={"Content-Type": "application/json",
                     **({"Authorization": f"Bearer {self.token}"} if self.token else {})},
            method="POST",
        )
        t0 = time.time()
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8", "ignore") or "{}")
        except Exception as e:  # noqa: BLE001 — surface as a response error
            return HttpResponse(error=f"caido: {e}",
                                elapsed_ms=round((time.time() - t0) * 1000))
        return HttpResponse(
            status=int(data.get("status") or 0),
            headers={str(k): str(v) for k, v in (data.get("headers") or {}).items()},
            body=str(data.get("body") or ""),
            elapsed_ms=round((time.time() - t0) * 1000),
        )


def make_backend(name: Optional[str] = None) -> ProxyBackend:
    name = (name or os.environ.get("AEGIS_PROXY_BACKEND") or "scanners").lower()
    if name == "caido":
        return CaidoBackend()
    return ScannersBackend()


# ── Session store ──────────────────────────────────────────────────────────
class SessionStore:
    """Thread-safe ledger of HTTP transactions, replayable during the run.

    Persisted to disk redacted (cookies/bearer stripped) for the audit trail;
    the in-memory copy keeps full headers so replay can carry real identity.
    """

    def __init__(self, persist_path: Optional[str] = None, redact: bool = True):
        self._txns: List[HttpTransaction] = []
        self._by_id: Dict[str, HttpTransaction] = {}
        self._counter = 0
        self._lock = threading.Lock()
        self.persist_path = Path(persist_path) if persist_path else None
        self.redact = redact

    def record(self, request: HttpRequest, response: HttpResponse,
               label: str = "") -> HttpTransaction:
        with self._lock:
            self._counter += 1
            txn = HttpTransaction(
                id=f"txn-{self._counter:04d}",
                request=request.clone(),
                response=response,
                label=label,
            )
            self._txns.append(txn)
            self._by_id[txn.id] = txn
        self._persist(txn)
        return txn

    def exchange(self, backend: ProxyBackend, request: HttpRequest,
                 label: str = "") -> HttpTransaction:
        """Send a request via a backend and record the transaction."""
        response = backend.send(request)
        return self.record(request, response, label=label)

    def get(self, txn_id: str) -> Optional[HttpTransaction]:
        with self._lock:
            return self._by_id.get(txn_id)

    def all(self) -> List[HttpTransaction]:
        with self._lock:
            return list(self._txns)

    def summary(self, limit: int = 20) -> List[dict]:
        with self._lock:
            rows = self._txns[-limit:] if limit else list(self._txns)
        return [
            {"id": t.id, "method": t.request.method, "url": t.request.url,
             "status": t.response.status, "label": t.label}
            for t in rows
        ]

    def _persist(self, txn: HttpTransaction) -> None:
        if not self.persist_path:
            return
        try:
            data = txn.to_dict()
            if self.redact:
                data = redact_value(data)
            self.persist_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.persist_path, "a") as fh:
                fh.write(json.dumps(data, default=str) + "\n")
        except Exception as e:  # persistence is best-effort
            logger.debug("session persist failed: %s", e)


# ── Process-wide singletons ────────────────────────────────────────────────
_STORE: Optional[SessionStore] = None
_BACKEND: Optional[ProxyBackend] = None
_LOCK = threading.Lock()


def get_session_store() -> SessionStore:
    global _STORE
    if _STORE is None:
        with _LOCK:
            if _STORE is None:
                _STORE = SessionStore(
                    persist_path=os.environ.get("AEGIS_SESSION_LOG"),
                )
    return _STORE


def set_session_store(store: SessionStore) -> SessionStore:
    global _STORE
    with _LOCK:
        _STORE = store
    return store


def get_backend() -> ProxyBackend:
    global _BACKEND
    if _BACKEND is None:
        with _LOCK:
            if _BACKEND is None:
                _BACKEND = make_backend()
    return _BACKEND


def set_backend(backend: ProxyBackend) -> ProxyBackend:
    global _BACKEND
    with _LOCK:
        _BACKEND = backend
    return backend


def reset_session() -> None:
    """Drop store + backend singletons — used by tests to isolate runs."""
    global _STORE, _BACKEND
    with _LOCK:
        _STORE = None
        _BACKEND = None
