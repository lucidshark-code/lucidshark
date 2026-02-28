"""Reporter plugins for lucidshark output formatting.

Plugins are discovered via Python entry points (lucidshark.reporters group).
"""

from typing import Dict, Type

from lucidshark.plugins.reporters.base import ReporterPlugin
from lucidshark.plugins.reporters.json_reporter import JSONReporter
from lucidshark.plugins.reporters.table_reporter import TableReporter
from lucidshark.plugins.reporters.summary_reporter import SummaryReporter
from lucidshark.plugins.reporters.sarif_reporter import SARIFReporter
from lucidshark.plugins.reporters.ai_reporter import AIReporter
from lucidshark.plugins import REPORTER_ENTRY_POINT_GROUP
from lucidshark.plugins.discovery import (
    discover_plugins,
    get_plugin,
    list_available_plugins as _list_plugins,
)


def discover_reporter_plugins() -> Dict[str, Type[ReporterPlugin]]:
    """Discover all installed reporter plugins via entry points."""
    return discover_plugins(REPORTER_ENTRY_POINT_GROUP, ReporterPlugin)


def get_reporter_plugin(name: str) -> ReporterPlugin | None:
    """Get an instantiated reporter plugin by name."""
    return get_plugin(REPORTER_ENTRY_POINT_GROUP, name, ReporterPlugin)


def list_available_reporters() -> list[str]:
    """List names of all available reporter plugins."""
    return _list_plugins(REPORTER_ENTRY_POINT_GROUP)


__all__ = [
    "ReporterPlugin",
    "AIReporter",
    "JSONReporter",
    "TableReporter",
    "SummaryReporter",
    "SARIFReporter",
    "discover_reporter_plugins",
    "get_reporter_plugin",
    "list_available_reporters",
]
