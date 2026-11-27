"""Shared test fixtures/config for the backend test suite.

Sets the minimum environment required to import `app.*` modules. `SECRET_KEY`
has no default in `app.core.config.Settings`, so it must be present before any
module that imports `settings` is loaded.
"""

import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production")
# Most pipeline tests pin the crawl/first-pass/enrichment/fireteam order. The
# once-per-target exposure check (on by default in production) sits between
# first pass and enrichment; test_exposure_check.py turns it on where tested.
os.environ.setdefault("AGENT_EXPOSURE_CHECK", "false")
