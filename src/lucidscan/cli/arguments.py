"""Argument parser construction for lucidscan CLI."""

from __future__ import annotations

import argparse
from pathlib import Path


def _add_global_options(parser: argparse.ArgumentParser) -> None:
    """Add global options: version, debug, verbose, quiet, format."""
    parser.add_argument(
        "--version",
        action="store_true",
        help="Show lucidscan version and exit.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose (info-level) logging.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Reduce logging output to errors only.",
    )
    parser.add_argument(
        "--format",
        choices=["json", "table", "sarif", "summary"],
        default=None,
        help="Output format (default: json, or as specified in config file).",
    )


def _add_diagnostic_options(parser: argparse.ArgumentParser) -> None:
    """Add diagnostic options: status, list-scanners."""
    parser.add_argument(
        "--status",
        action="store_true",
        help="Show scanner plugin status and installed versions.",
    )
    parser.add_argument(
        "--list-scanners",
        action="store_true",
        help="List all available scanner plugins and exit.",
    )


def _add_domain_options(parser: argparse.ArgumentParser) -> None:
    """Add scanner domain options: sca, container, iac, sast, all."""
    parser.add_argument(
        "--sca",
        action="store_true",
        help="Enable Software Composition Analysis (Trivy plugin).",
    )
    parser.add_argument(
        "--container",
        action="store_true",
        help="Enable container image scanning (Trivy plugin).",
    )
    parser.add_argument(
        "--iac",
        action="store_true",
        help="Enable Infrastructure-as-Code scanning (Checkov plugin).",
    )
    parser.add_argument(
        "--sast",
        action="store_true",
        help="Enable static application security testing (OpenGrep plugin).",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Enable all scanner plugins.",
    )


def _add_target_options(parser: argparse.ArgumentParser) -> None:
    """Add target options: path, image."""
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to scan (default: current directory).",
    )
    parser.add_argument(
        "--image",
        action="append",
        dest="images",
        metavar="IMAGE",
        help="Container image to scan (can be specified multiple times).",
    )


def _add_config_options(parser: argparse.ArgumentParser) -> None:
    """Add configuration options: config, fail-on."""
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        default=None,
        help="Exit with code 1 if issues at or above this severity are found.",
    )
    parser.add_argument(
        "--config",
        metavar="PATH",
        type=Path,
        help="Path to config file (default: .lucidscan.yml in project root).",
    )


def _add_execution_options(parser: argparse.ArgumentParser) -> None:
    """Add execution options: sequential."""
    parser.add_argument(
        "--sequential",
        action="store_true",
        help="Disable parallel scanner execution (for debugging).",
    )


def build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser for lucidscan CLI.

    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog="lucidscan",
        description="lucidscan - Plugin-based security scanning framework.",
    )

    _add_global_options(parser)
    _add_diagnostic_options(parser)
    _add_domain_options(parser)
    _add_target_options(parser)
    _add_config_options(parser)
    _add_execution_options(parser)

    return parser
