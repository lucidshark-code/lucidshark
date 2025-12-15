"""Plugin infrastructure for lucidscan.

This package provides the plugin discovery and management infrastructure
for all plugin types:
- Scanner plugins (lucidscan.scanners)
- Enricher plugins (lucidscan.enrichers) - future
- Reporter plugins (lucidscan.reporters)

Plugins are discovered via Python entry points.
"""

from lucidscan.plugins.discovery import (
    discover_plugins,
    get_plugin,
    list_available_plugins,
    SCANNER_ENTRY_POINT_GROUP,
    REPORTER_ENTRY_POINT_GROUP,
)

__all__ = [
    "discover_plugins",
    "get_plugin",
    "list_available_plugins",
    "SCANNER_ENTRY_POINT_GROUP",
    "REPORTER_ENTRY_POINT_GROUP",
]
