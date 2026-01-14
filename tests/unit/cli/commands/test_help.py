"""Tests for help command."""

from __future__ import annotations

from argparse import Namespace

from lucidscan.cli.commands.help import HelpCommand, get_help_content
from lucidscan.cli.exit_codes import EXIT_SUCCESS


class TestHelpCommand:
    """Tests for HelpCommand."""

    def test_command_name(self) -> None:
        """Test command name property."""
        cmd = HelpCommand(version="1.0.0")
        assert cmd.name == "help"

    def test_execute_returns_success(self, capsys) -> None:
        """Test execute returns success exit code."""
        cmd = HelpCommand(version="1.0.0")
        result = cmd.execute(Namespace())

        assert result == EXIT_SUCCESS

    def test_execute_outputs_documentation(self, capsys) -> None:
        """Test execute outputs documentation content."""
        cmd = HelpCommand(version="1.0.0")
        cmd.execute(Namespace())

        captured = capsys.readouterr()
        # Verify key sections are present
        assert "LucidScan Reference Documentation" in captured.out
        assert "Quick Start" in captured.out
        assert "CLI Commands" in captured.out
        assert "MCP Tools Reference" in captured.out
        assert "Configuration Reference" in captured.out


class TestGetHelpContent:
    """Tests for get_help_content function."""

    def test_returns_string(self) -> None:
        """Test that get_help_content returns a string."""
        content = get_help_content()
        assert isinstance(content, str)

    def test_contains_expected_sections(self) -> None:
        """Test that content contains expected documentation sections."""
        content = get_help_content()

        # Check for main sections
        assert "# LucidScan Reference Documentation" in content
        assert "## Quick Start" in content
        assert "## CLI Commands" in content
        assert "## MCP Tools Reference" in content
        assert "## Configuration Reference" in content
        assert "## Best Practices for AI Agents" in content

    def test_contains_cli_commands(self) -> None:
        """Test that content documents CLI commands."""
        content = get_help_content()

        assert "lucidscan init" in content
        assert "lucidscan scan" in content
        assert "lucidscan status" in content
        assert "lucidscan serve" in content
        assert "lucidscan autoconfigure" in content
        assert "lucidscan help" in content

    def test_contains_mcp_tools(self) -> None:
        """Test that content documents MCP tools."""
        content = get_help_content()

        assert "`scan`" in content
        assert "`check_file`" in content
        assert "`get_fix_instructions`" in content
        assert "`apply_fix`" in content
        assert "`get_status`" in content
        assert "`get_help`" in content

    def test_contains_configuration_options(self) -> None:
        """Test that content documents configuration options."""
        content = get_help_content()

        assert "lucidscan.yml" in content
        assert "fail_on" in content
        assert "pipeline" in content
        assert "linting" in content
        assert "type_checking" in content
        assert "security" in content
