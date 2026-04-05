"""Root test configuration.

Disables telemetry for all tests to prevent real PostHog events from leaking
during test runs. Individual telemetry tests re-enable it via their own
fixtures (mock_posthog deletes the env var and injects a mock client).
"""

from __future__ import annotations

import os


def pytest_configure(config):  # noqa: ARG001
    """Disable telemetry before any test collection or import."""
    os.environ["LUCIDSHARK_TELEMETRY"] = "0"
