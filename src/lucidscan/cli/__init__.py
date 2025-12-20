"""LucidScan CLI package.

This package provides the command-line interface for lucidscan.
"""

from __future__ import annotations

from typing import Iterable, Optional

from lucidscan.cli.runner import CLIRunner, get_version
from lucidscan.cli.arguments import build_parser
from lucidscan.cli.exit_codes import (
    EXIT_SUCCESS,
    EXIT_ISSUES_FOUND,
    EXIT_SCANNER_ERROR,
    EXIT_INVALID_USAGE,
    EXIT_BOOTSTRAP_FAILURE,
)


def main(argv: Optional[Iterable[str]] = None) -> int:
    """CLI entrypoint.

    Returns an exit code suitable for use as a console script.

    Args:
        argv: Command-line arguments (defaults to sys.argv).

    Returns:
        Exit code.
    """
    runner = CLIRunner()
    return runner.run(argv)


__all__ = [
    "main",
    "build_parser",
    "get_version",
    "CLIRunner",
    "EXIT_SUCCESS",
    "EXIT_ISSUES_FOUND",
    "EXIT_SCANNER_ERROR",
    "EXIT_INVALID_USAGE",
    "EXIT_BOOTSTRAP_FAILURE",
]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
