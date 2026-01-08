"""Tests for setup command."""

from __future__ import annotations

import json
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

import pytest

from lucidscan.cli.commands.setup import SetupCommand, LUCIDSCAN_MCP_CONFIG
from lucidscan.cli.exit_codes import EXIT_SUCCESS, EXIT_INVALID_USAGE


class TestSetupCommand:
    """Tests for SetupCommand."""

    def test_name(self) -> None:
        """Test command name property."""
        cmd = SetupCommand(version="1.0.0")
        assert cmd.name == "setup"

    def test_no_tool_specified_returns_invalid_usage(self, capsys) -> None:
        """Test that no tool specified returns EXIT_INVALID_USAGE."""
        cmd = SetupCommand(version="1.0.0")
        args = Namespace(
            claude_code=False,
            cursor=False,
            setup_all=False,
            dry_run=False,
            force=False,
            remove=False,
        )
        exit_code = cmd.execute(args)
        assert exit_code == EXIT_INVALID_USAGE

        captured = capsys.readouterr()
        assert "No AI tool specified" in captured.out

    def test_setup_all_configures_both_tools(self, tmp_path: Path, capsys) -> None:
        """Test that --all configures both Claude Code and Cursor."""
        cmd = SetupCommand(version="1.0.0")
        args = Namespace(
            claude_code=False,
            cursor=False,
            setup_all=True,
            dry_run=True,
            force=False,
            remove=False,
        )

        claude_config = tmp_path / ".claude" / "mcp_servers.json"
        cursor_config = tmp_path / ".cursor" / "mcp.json"

        with patch.object(cmd, "_get_claude_code_config_path", return_value=claude_config):
            with patch.object(cmd, "_get_cursor_config_path", return_value=cursor_config):
                exit_code = cmd.execute(args)

        assert exit_code == EXIT_SUCCESS
        captured = capsys.readouterr()
        assert "Claude Code" in captured.out
        assert "Cursor" in captured.out


class TestSetupClaudeCode:
    """Tests for Claude Code setup."""

    def test_creates_new_config_file(self, tmp_path: Path, capsys) -> None:
        """Test creating a new Claude Code config file."""
        cmd = SetupCommand(version="1.0.0")
        config_path = tmp_path / ".claude" / "mcp_servers.json"

        args = Namespace(
            claude_code=True,
            cursor=False,
            setup_all=False,
            dry_run=False,
            force=False,
            remove=False,
        )

        with patch.object(cmd, "_get_claude_code_config_path", return_value=config_path):
            with patch("shutil.which", return_value="/usr/local/bin/lucidscan"):
                exit_code = cmd.execute(args)

        assert exit_code == EXIT_SUCCESS
        assert config_path.exists()

        config = json.loads(config_path.read_text())
        assert "mcpServers" in config
        assert "lucidscan" in config["mcpServers"]
        assert config["mcpServers"]["lucidscan"] == LUCIDSCAN_MCP_CONFIG

    def test_preserves_existing_mcp_servers(self, tmp_path: Path) -> None:
        """Test that existing MCP servers are preserved."""
        cmd = SetupCommand(version="1.0.0")
        config_path = tmp_path / ".claude" / "mcp_servers.json"
        config_path.parent.mkdir(parents=True)

        # Create existing config with another MCP server
        existing_config = {
            "mcpServers": {
                "other-tool": {
                    "command": "other-command",
                    "args": ["--some-flag"],
                }
            }
        }
        config_path.write_text(json.dumps(existing_config))

        args = Namespace(
            claude_code=True,
            cursor=False,
            setup_all=False,
            dry_run=False,
            force=False,
            remove=False,
        )

        with patch.object(cmd, "_get_claude_code_config_path", return_value=config_path):
            with patch("shutil.which", return_value="/usr/local/bin/lucidscan"):
                exit_code = cmd.execute(args)

        assert exit_code == EXIT_SUCCESS

        config = json.loads(config_path.read_text())
        assert "other-tool" in config["mcpServers"]
        assert "lucidscan" in config["mcpServers"]

    def test_skips_if_already_configured(self, tmp_path: Path, capsys) -> None:
        """Test that setup skips if LucidScan already configured."""
        cmd = SetupCommand(version="1.0.0")
        config_path = tmp_path / ".claude" / "mcp_servers.json"
        config_path.parent.mkdir(parents=True)

        # Create existing config with lucidscan
        existing_config = {
            "mcpServers": {
                "lucidscan": LUCIDSCAN_MCP_CONFIG,
            }
        }
        config_path.write_text(json.dumps(existing_config))

        args = Namespace(
            claude_code=True,
            cursor=False,
            setup_all=False,
            dry_run=False,
            force=False,
            remove=False,
        )

        with patch.object(cmd, "_get_claude_code_config_path", return_value=config_path):
            with patch("shutil.which", return_value="/usr/local/bin/lucidscan"):
                exit_code = cmd.execute(args)

        assert exit_code == EXIT_SUCCESS
        captured = capsys.readouterr()
        assert "already configured" in captured.out

    def test_force_overwrites_existing(self, tmp_path: Path) -> None:
        """Test that --force overwrites existing config."""
        cmd = SetupCommand(version="1.0.0")
        config_path = tmp_path / ".claude" / "mcp_servers.json"
        config_path.parent.mkdir(parents=True)

        # Create existing config with different lucidscan config
        existing_config = {
            "mcpServers": {
                "lucidscan": {
                    "command": "old-command",
                    "args": ["--old-flag"],
                },
            }
        }
        config_path.write_text(json.dumps(existing_config))

        args = Namespace(
            claude_code=True,
            cursor=False,
            setup_all=False,
            dry_run=False,
            force=True,
            remove=False,
        )

        with patch.object(cmd, "_get_claude_code_config_path", return_value=config_path):
            with patch("shutil.which", return_value="/usr/local/bin/lucidscan"):
                exit_code = cmd.execute(args)

        assert exit_code == EXIT_SUCCESS

        config = json.loads(config_path.read_text())
        assert config["mcpServers"]["lucidscan"] == LUCIDSCAN_MCP_CONFIG

    def test_dry_run_does_not_write(self, tmp_path: Path, capsys) -> None:
        """Test that --dry-run does not write config file."""
        cmd = SetupCommand(version="1.0.0")
        config_path = tmp_path / ".claude" / "mcp_servers.json"

        args = Namespace(
            claude_code=True,
            cursor=False,
            setup_all=False,
            dry_run=True,
            force=False,
            remove=False,
        )

        with patch.object(cmd, "_get_claude_code_config_path", return_value=config_path):
            with patch("shutil.which", return_value="/usr/local/bin/lucidscan"):
                exit_code = cmd.execute(args)

        assert exit_code == EXIT_SUCCESS
        assert not config_path.exists()

        captured = capsys.readouterr()
        assert "Would write" in captured.out

    def test_remove_deletes_lucidscan(self, tmp_path: Path, capsys) -> None:
        """Test that --remove removes LucidScan from config."""
        cmd = SetupCommand(version="1.0.0")
        config_path = tmp_path / ".claude" / "mcp_servers.json"
        config_path.parent.mkdir(parents=True)

        # Create existing config with lucidscan and another tool
        existing_config = {
            "mcpServers": {
                "lucidscan": LUCIDSCAN_MCP_CONFIG,
                "other-tool": {"command": "other"},
            }
        }
        config_path.write_text(json.dumps(existing_config))

        args = Namespace(
            claude_code=True,
            cursor=False,
            setup_all=False,
            dry_run=False,
            force=False,
            remove=True,
        )

        with patch.object(cmd, "_get_claude_code_config_path", return_value=config_path):
            exit_code = cmd.execute(args)

        assert exit_code == EXIT_SUCCESS

        config = json.loads(config_path.read_text())
        assert "lucidscan" not in config["mcpServers"]
        assert "other-tool" in config["mcpServers"]

        captured = capsys.readouterr()
        assert "Removed lucidscan" in captured.out

    def test_remove_not_found(self, tmp_path: Path, capsys) -> None:
        """Test removing when LucidScan not in config."""
        cmd = SetupCommand(version="1.0.0")
        config_path = tmp_path / ".claude" / "mcp_servers.json"
        config_path.parent.mkdir(parents=True)

        # Create existing config without lucidscan
        existing_config = {
            "mcpServers": {
                "other-tool": {"command": "other"},
            }
        }
        config_path.write_text(json.dumps(existing_config))

        args = Namespace(
            claude_code=True,
            cursor=False,
            setup_all=False,
            dry_run=False,
            force=False,
            remove=True,
        )

        with patch.object(cmd, "_get_claude_code_config_path", return_value=config_path):
            exit_code = cmd.execute(args)

        assert exit_code == EXIT_SUCCESS
        captured = capsys.readouterr()
        assert "not found" in captured.out


class TestSetupCursor:
    """Tests for Cursor setup."""

    def test_creates_cursor_config(self, tmp_path: Path) -> None:
        """Test creating Cursor config file."""
        cmd = SetupCommand(version="1.0.0")
        config_path = tmp_path / ".cursor" / "mcp.json"

        args = Namespace(
            claude_code=False,
            cursor=True,
            setup_all=False,
            dry_run=False,
            force=False,
            remove=False,
        )

        with patch.object(cmd, "_get_cursor_config_path", return_value=config_path):
            with patch("shutil.which", return_value="/usr/local/bin/lucidscan"):
                exit_code = cmd.execute(args)

        assert exit_code == EXIT_SUCCESS
        assert config_path.exists()

        config = json.loads(config_path.read_text())
        assert "mcpServers" in config
        assert "lucidscan" in config["mcpServers"]


class TestConfigPaths:
    """Tests for config path determination."""

    def test_claude_code_config_path_unix(self) -> None:
        """Test Claude Code config path on Unix systems."""
        cmd = SetupCommand(version="1.0.0")
        with patch("sys.platform", "darwin"):
            path = cmd._get_claude_code_config_path()
            assert path is not None
            assert ".claude" in str(path)
            assert "mcp_servers.json" in str(path)

    def test_cursor_config_path_unix(self) -> None:
        """Test Cursor config path on Unix systems."""
        cmd = SetupCommand(version="1.0.0")
        with patch("sys.platform", "darwin"):
            path = cmd._get_cursor_config_path()
            assert path is not None
            assert ".cursor" in str(path)
            assert "mcp.json" in str(path)


class TestJsonConfigOperations:
    """Tests for JSON config read/write operations."""

    def test_read_nonexistent_file(self, tmp_path: Path) -> None:
        """Test reading nonexistent config file."""
        cmd = SetupCommand(version="1.0.0")
        config_path = tmp_path / "nonexistent.json"

        config, error = cmd._read_json_config(config_path)
        assert config == {}
        assert error is not None
        assert "does not exist" in error

    def test_read_empty_file(self, tmp_path: Path) -> None:
        """Test reading empty config file."""
        cmd = SetupCommand(version="1.0.0")
        config_path = tmp_path / "empty.json"
        config_path.write_text("")

        config, error = cmd._read_json_config(config_path)
        assert config == {}
        assert error is None

    def test_read_invalid_json(self, tmp_path: Path) -> None:
        """Test reading invalid JSON file."""
        cmd = SetupCommand(version="1.0.0")
        config_path = tmp_path / "invalid.json"
        config_path.write_text("{ not valid json }")

        config, error = cmd._read_json_config(config_path)
        assert config == {}
        assert error is not None
        assert "Invalid JSON" in error

    def test_write_config(self, tmp_path: Path) -> None:
        """Test writing config file."""
        cmd = SetupCommand(version="1.0.0")
        config_path = tmp_path / "test.json"

        config = {"key": "value"}
        success = cmd._write_json_config(config_path, config)

        assert success
        assert config_path.exists()

        written = json.loads(config_path.read_text())
        assert written == config
