"""Shared test fixtures/config for the backend test suite.

Sets the minimum environment required to import `app.*` modules. `SECRET_KEY`
has no default in `app.core.config.Settings`, so it must be present before any
module that imports `settings` is loaded.
"""

import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production")


import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_provider_cooldowns():
    """Provider cooldowns are process-wide; keep tests independent."""
    from app.services.agent.provider_cooldown import provider_cooldowns

    provider_cooldowns.reset()
    yield
    provider_cooldowns.reset()
