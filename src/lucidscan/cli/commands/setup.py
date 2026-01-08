"""Setup command implementation.

Configure AI tools (Claude Code, Cursor) to use LucidScan via MCP.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from argparse import Namespace
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from lucidscan.cli.commands import Command
from lucidscan.cli.exit_codes import EXIT_SUCCESS, EXIT_INVALID_USAGE
from lucidscan.core.logging import get_logger

LOGGER = get_logger(__name__)

# MCP server configuration for LucidScan
LUCIDSCAN_MCP_CONFIG = {
    "command": "lucidscan",
    "args": ["serve", "--mcp"],
}


class SetupCommand(Command):
    """Configure AI tools to use LucidScan via MCP."""

    def __init__(self, version: str):
        """Initialize SetupCommand.

        Args:
            version: Current lucidscan version string.
        """
        self._version = version

    @property
    def name(self) -> str:
        """Command identifier."""
        return "setup"

    def execute(self, args: Namespace) -> int:
        """Execute the setup command.

        Args:
            args: Parsed command-line arguments.

        Returns:
            Exit code.
        """
        # Determine which tools to configure
        configure_claude = getattr(args, "claude_code", False)
        configure_cursor = getattr(args, "cursor", False)
        configure_all = getattr(args, "setup_all", False)

        if configure_all:
            configure_claude = True
            configure_cursor = True

        if not configure_claude and not configure_cursor:
            print("No AI tool specified. Use --claude-code, --cursor, or --all.")
            print("\nRun 'lucidscan setup --help' for more options.")
            return EXIT_INVALID_USAGE

        dry_run = getattr(args, "dry_run", False)
        force = getattr(args, "force", False)
        remove = getattr(args, "remove", False)

        success = True

        if configure_claude:
            if not self._setup_claude_code(dry_run, force, remove):
                success = False

        if configure_cursor:
            if not self._setup_cursor(dry_run, force, remove):
                success = False

        if success and not dry_run:
            print("\nRestart your AI tool to apply changes.")

        return EXIT_SUCCESS if success else EXIT_INVALID_USAGE

    def _setup_claude_code(
        self,
        dry_run: bool = False,
        force: bool = False,
        remove: bool = False,
    ) -> bool:
        """Configure Claude Code MCP settings.

        Args:
            dry_run: If True, only show what would be done.
            force: If True, overwrite existing config.
            remove: If True, remove LucidScan from config.

        Returns:
            True if successful.
        """
        print("Configuring Claude Code...")

        config_path = self._get_claude_code_config_path()
        if config_path is None:
            print("  Could not determine Claude Code config location.")
            return False

        return self._configure_mcp_tool(
            tool_name="Claude Code",
            config_path=config_path,
            config_key="mcpServers",
            dry_run=dry_run,
            force=force,
            remove=remove,
        )

    def _setup_cursor(
        self,
        dry_run: bool = False,
        force: bool = False,
        remove: bool = False,
    ) -> bool:
        """Configure Cursor MCP settings.

        Args:
            dry_run: If True, only show what would be done.
            force: If True, overwrite existing config.
            remove: If True, remove LucidScan from config.

        Returns:
            True if successful.
        """
        print("Configuring Cursor...")

        config_path = self._get_cursor_config_path()
        if config_path is None:
            print("  Could not determine Cursor config location.")
            return False

        return self._configure_mcp_tool(
            tool_name="Cursor",
            config_path=config_path,
            config_key="mcpServers",
            dry_run=dry_run,
            force=force,
            remove=remove,
        )

    def _configure_mcp_tool(
        self,
        tool_name: str,
        config_path: Path,
        config_key: str,
        dry_run: bool = False,
        force: bool = False,
        remove: bool = False,
    ) -> bool:
        """Configure an MCP-compatible tool.

        Args:
            tool_name: Name of the tool for display.
            config_path: Path to the config file.
            config_key: Key in the config for MCP servers.
            dry_run: If True, only show what would be done.
            force: If True, overwrite existing config.
            remove: If True, remove LucidScan from config.

        Returns:
            True if successful.
        """
        # Check if lucidscan command is available
        lucidscan_path = shutil.which("lucidscan")
        if not lucidscan_path and not dry_run:
            print(f"  Warning: 'lucidscan' command not found in PATH.")
            print(f"  Make sure LucidScan is installed and accessible.")

        # Read existing config
        config, error = self._read_json_config(config_path)
        if error and not remove:
            # For new config, start fresh
            config = {}

        # Get or create the MCP servers section
        mcp_servers = config.get(config_key, {})

        if remove:
            # Remove LucidScan from config
            if "lucidscan" in mcp_servers:
                if dry_run:
                    print(f"  Would remove lucidscan from {config_path}")
                else:
                    del mcp_servers["lucidscan"]
                    config[config_key] = mcp_servers
                    if not mcp_servers:
                        del config[config_key]
                    self._write_json_config(config_path, config)
                    print(f"  Removed lucidscan from {config_path}")
            else:
                print(f"  lucidscan not found in {config_path}")
            return True

        # Check if LucidScan is already configured
        if "lucidscan" in mcp_servers and not force:
            print(f"  LucidScan already configured in {config_path}")
            print(f"  Use --force to overwrite.")
            return True

        # Add LucidScan config
        mcp_servers["lucidscan"] = LUCIDSCAN_MCP_CONFIG.copy()
        config[config_key] = mcp_servers

        if dry_run:
            print(f"  Would write to {config_path}:")
            print(f"    {json.dumps(config, indent=2)}")
            return True

        # Ensure parent directory exists
        config_path.parent.mkdir(parents=True, exist_ok=True)

        # Write config
        success = self._write_json_config(config_path, config)
        if success:
            print(f"  Added lucidscan to {config_path}")
            self._print_available_tools()
        return success

    def _get_claude_code_config_path(self) -> Optional[Path]:
        """Get the Claude Code MCP config file path.

        Returns:
            Path to config file or None if not determinable.
        """
        # Claude Code stores MCP config in ~/.claude/mcp_servers.json
        home = Path.home()

        if sys.platform == "win32":
            # Windows: %USERPROFILE%\.claude\mcp_servers.json
            return home / ".claude" / "mcp_servers.json"
        else:
            # macOS/Linux: ~/.claude/mcp_servers.json
            return home / ".claude" / "mcp_servers.json"

    def _get_cursor_config_path(self) -> Optional[Path]:
        """Get the Cursor MCP config file path.

        Returns:
            Path to config file or None if not determinable.
        """
        home = Path.home()

        if sys.platform == "win32":
            # Windows: %USERPROFILE%\.cursor\mcp.json
            return home / ".cursor" / "mcp.json"
        elif sys.platform == "darwin":
            # macOS: ~/.cursor/mcp.json
            return home / ".cursor" / "mcp.json"
        else:
            # Linux: ~/.cursor/mcp.json
            return home / ".cursor" / "mcp.json"

    def _read_json_config(self, path: Path) -> Tuple[Dict[str, Any], Optional[str]]:
        """Read a JSON config file.

        Args:
            path: Path to the config file.

        Returns:
            Tuple of (config dict, error message or None).
        """
        if not path.exists():
            return {}, f"Config file does not exist: {path}"

        try:
            with open(path, "r") as f:
                content = f.read().strip()
                if not content:
                    return {}, None
                return json.loads(content), None
        except json.JSONDecodeError as e:
            return {}, f"Invalid JSON in {path}: {e}"
        except Exception as e:
            return {}, f"Error reading {path}: {e}"

    def _write_json_config(self, path: Path, config: Dict[str, Any]) -> bool:
        """Write a JSON config file.

        Args:
            path: Path to the config file.
            config: Configuration dictionary.

        Returns:
            True if successful.
        """
        try:
            with open(path, "w") as f:
                json.dump(config, f, indent=2)
                f.write("\n")
            return True
        except Exception as e:
            print(f"  Error writing {path}: {e}")
            return False

    def _print_available_tools(self) -> None:
        """Print available MCP tools."""
        print("\n  Available MCP tools:")
        print("    - scan: Run quality checks on the codebase")
        print("    - check_file: Check a specific file")
        print("    - get_fix_instructions: Get detailed fix guidance")
        print("    - apply_fix: Auto-fix linting issues")
        print("    - get_status: Show LucidScan configuration")
