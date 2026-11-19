"""Shared test fixtures/config for the backend test suite.

Sets the minimum environment required to import `app.*` modules. `SECRET_KEY`
has no default in `app.core.config.Settings`, so it must be present before any
module that imports `settings` is loaded.
"""

import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production")
# Tests drive many requests through mock transports; real pacing would only
# slow them down. test_target_pacing exercises the profiles explicitly.
os.environ.setdefault("AGENT_PACING_PROFILE", "off")
