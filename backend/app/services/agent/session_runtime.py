"""Isolate mutable tool state by organization and assessment session.

ContextVars flow into specialist tasks, so concurrent verifiers share only their
own assessment state, even when the product uses a singleton orchestrator.
"""

from __future__ import annotations

import time


MAX_MANAGER_SESSIONS = 256


def _dispose(bucket):
    store = bucket.get("_evidence_store") if isinstance(bucket, dict) else None
    if store is not None and hasattr(store, "clear"):
        store.clear()


def clear_session_runtime(obj, organization_id, session_id) -> bool:
    """Drop transient identities, evidence, workflows, and receipts for one session."""
    runtime = obj.__dict__.get("_session_runtime", {})
    bucket = runtime.pop((organization_id, session_id), None)
    if bucket is not None:
        _dispose(bucket)
        return True
    return False


class SessionValue:
    def __init__(self, factory):
        self.factory = factory

    def __set_name__(self, owner, name):
        self.name = name

    def _bucket(self, obj):
        from app.services.agent.tools import current_organization_id, current_session_id

        key = (current_organization_id.get(), current_session_id.get())
        runtime = obj.__dict__.setdefault("_session_runtime", {})
        bucket = runtime.setdefault(key, {})
        bucket["__last_access__"] = time.monotonic()
        if len(runtime) > MAX_MANAGER_SESSIONS:
            stale = sorted(
                (item for item in runtime.items() if item[0] != key),
                key=lambda item: item[1].get("__last_access__", 0),
            )
            while len(runtime) > MAX_MANAGER_SESSIONS and stale:
                old_key, old_bucket = stale.pop(0)
                runtime.pop(old_key, None)
                _dispose(old_bucket)
        return bucket

    def __get__(self, obj, owner=None):
        if obj is None:
            return self
        bucket = self._bucket(obj)
        if self.name not in bucket:
            bucket[self.name] = self.factory()
        return bucket[self.name]

    def __set__(self, obj, value):
        self._bucket(obj)[self.name] = value
