"""CLI runner orchestration."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Optional

from importlib.metadata import version, PackageNotFoundError

from lucidscan.cli.arguments import build_parser
from lucidscan.cli.config_bridge import ConfigBridge
from lucidscan.cli.exit_codes import (
    EXIT_INVALID_USAGE,
    EXIT_SCANNER_ERROR,
    EXIT_SUCCESS,
)
from lucidscan.cli.commands.status import StatusCommand
from lucidscan.cli.commands.list_scanners import ListScannersCommand
from lucidscan.cli.commands.scan import ScanCommand
from lucidscan.config import load_config
from lucidscan.config.loader import ConfigError
from lucidscan.core.logging import configure_logging, get_logger

LOGGER = get_logger(__name__)


def get_version() -> str:
    """Get lucidscan version.

    Returns:
        Version string from package metadata or fallback.
    """
    try:
        return version("lucidscan")
    except PackageNotFoundError:
        # Fallback for editable installs that have not yet built metadata.
        from lucidscan import __version__
        return __version__


class CLIRunner:
    """Orchestrates CLI execution."""

    def __init__(self) -> None:
        """Initialize CLIRunner with parser and commands."""
        self.parser = build_parser()
        self._version = get_version()
        self.status_cmd = StatusCommand(version=self._version)
        self.list_cmd = ListScannersCommand()
        self.scan_cmd = ScanCommand(version=self._version)

    def run(self, argv: Optional[Iterable[str]] = None) -> int:
        """Run the CLI.

        Args:
            argv: Command-line arguments (defaults to sys.argv).

        Returns:
            Exit code.
        """
        # Handle --help specially to return 0
        if argv is not None:
            argv_list = list(argv)
            if "--help" in argv_list or "-h" in argv_list:
                self.parser.print_help()
                return EXIT_SUCCESS
        else:
            argv_list = None

        args = self.parser.parse_args(argv_list)

        # Configure logging as early as possible
        configure_logging(
            debug=args.debug,
            verbose=args.verbose,
            quiet=args.quiet,
        )

        # Handle --version
        if args.version:
            print(self._version)
            return EXIT_SUCCESS

        # Handle --status
        if args.status:
            return self.status_cmd.execute(args)

        # Handle --list-scanners
        if args.list_scanners:
            return self.list_cmd.execute(args)

        # Check if we should run a scan
        cli_scan_requested = any([
            args.sca,
            args.container,
            args.iac,
            args.sast,
            args.all,
        ])

        # Load configuration
        project_root = Path(args.path).resolve()
        cli_overrides = ConfigBridge.args_to_overrides(args)

        try:
            config = load_config(
                project_root=project_root,
                cli_config_path=args.config,
                cli_overrides=cli_overrides,
            )
        except ConfigError as e:
            LOGGER.error(str(e))
            return EXIT_INVALID_USAGE

        config_has_enabled_domains = bool(config.get_enabled_domains())

        if cli_scan_requested or config_has_enabled_domains:
            try:
                return self.scan_cmd.execute(args, config)
            except FileNotFoundError:
                return EXIT_INVALID_USAGE
            except Exception as e:
                if args.debug:
                    import traceback
                    traceback.print_exc()
                return EXIT_SCANNER_ERROR

        # If no scanners are selected, show help to guide users
        self.parser.print_help()
        return EXIT_SUCCESS
