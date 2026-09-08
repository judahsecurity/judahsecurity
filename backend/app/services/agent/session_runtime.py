"""Isolate mutable tool state by organization and assessment session.

ContextVars flow into specialist tasks, so concurrent verifiers share only their
own assessment state, even when the product uses a singleton orchestrator.
"""

from __future__ import annotations


class SessionValue:
    def __init__(self, factory):
        self.factory = factory

    def __set_name__(self, owner, name):
        self.name = name

    def _bucket(self, obj):
        from app.services.agent.tools import current_organization_id, current_session_id

        key = (current_organization_id.get(), current_session_id.get())
        if "_session_runtime" not in obj.__dict__:
            obj.__dict__["_session_runtime"] = {}
        return obj.__dict__["_session_runtime"].setdefault(key, {})

    def __get__(self, obj, owner=None):
        if obj is None:
            return self
        bucket = self._bucket(obj)
        if self.name not in bucket:
            bucket[self.name] = self.factory()
        return bucket[self.name]

    def __set__(self, obj, value):
        self._bucket(obj)[self.name] = value
