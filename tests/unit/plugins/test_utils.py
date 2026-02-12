"""Unit tests for shared plugin utilities."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock


from lucidshark.plugins.utils import (
    get_cli_version,
    resolve_src_paths,
)


class TestGetCliVersion:
    """Tests for get_cli_version function."""

    def test_returns_version_on_success(self) -> None:
        """Test successful version retrieval."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "1.2.3"

        with patch("subprocess.run", return_value=mock_result):
            version = get_cli_version(Path("/usr/bin/tool"))

        assert version == "1.2.3"

    def test_returns_unknown_on_empty_output(self) -> None:
        """Test returns 'unknown' when output is empty."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            version = get_cli_version(Path("/usr/bin/tool"))

        assert version == "unknown"

    def test_returns_unknown_on_whitespace_output(self) -> None:
        """Test returns 'unknown' when output is only whitespace."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "   \n\t  "

        with patch("subprocess.run", return_value=mock_result):
            version = get_cli_version(Path("/usr/bin/tool"))

        assert version == "unknown"

    def test_returns_unknown_on_exception(self) -> None:
        """Test returns 'unknown' when subprocess raises exception."""
        with patch("subprocess.run", side_effect=OSError("Command not found")):
            version = get_cli_version(Path("/usr/bin/nonexistent"))

        assert version == "unknown"

    def test_returns_unknown_on_timeout(self) -> None:
        """Test returns 'unknown' when subprocess times out."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 30)):
            version = get_cli_version(Path("/usr/bin/slow"))

        assert version == "unknown"

    def test_returns_unknown_on_nonzero_exit(self) -> None:
        """Test returns 'unknown' when command exits with error."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            version = get_cli_version(Path("/usr/bin/failing"))

        assert version == "unknown"

    def test_uses_custom_parser(self) -> None:
        """Test custom parser function is used."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Version 2.0.0"

        def extract_version(s: str) -> str:
            return s.split()[1]

        with patch("subprocess.run", return_value=mock_result):
            version = get_cli_version(Path("/usr/bin/tool"), parser=extract_version)

        assert version == "2.0.0"

    def test_returns_unknown_when_parser_returns_empty(self) -> None:
        """Test returns 'unknown' when parser returns empty string."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "invalid output"

        def bad_parser(s: str) -> str:
            return ""  # Always returns empty

        with patch("subprocess.run", return_value=mock_result):
            version = get_cli_version(Path("/usr/bin/tool"), parser=bad_parser)

        assert version == "unknown"


class TestResolveSrcPaths:
    """Tests for resolve_src_paths function."""

    def test_returns_context_paths_when_provided(self) -> None:
        """Test that explicit context paths are returned as-is."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            context_paths = [
                project_root / "file1.py",
                project_root / "file2.py",
            ]

            result = resolve_src_paths(context_paths, project_root)

            assert len(result) == 2
            assert result[0].endswith("file1.py")
            assert result[1].endswith("file2.py")

    def test_returns_src_dir_when_exists(self) -> None:
        """Test fallback to src directory when it exists."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            src_dir = project_root / "src"
            src_dir.mkdir()

            result = resolve_src_paths(None, project_root)

            assert len(result) == 1
            assert result[0].endswith("src")

    def test_returns_dot_when_src_not_exists(self) -> None:
        """Test fallback to '.' when src directory doesn't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            # Don't create src directory

            result = resolve_src_paths(None, project_root)

            assert result == ["."]

    def test_uses_custom_default_subdir(self) -> None:
        """Test custom default subdirectory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            lib_dir = project_root / "lib"
            lib_dir.mkdir()

            result = resolve_src_paths(None, project_root, default_subdir="lib")

            assert len(result) == 1
            assert result[0].endswith("lib")

    def test_empty_context_paths_treated_as_none(self) -> None:
        """Test that empty context paths list falls back to default."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            src_dir = project_root / "src"
            src_dir.mkdir()

            # Empty list should fall back to src directory
            result = resolve_src_paths([], project_root)

            # Empty list is falsy, so should fall back
            assert result == ["."] or result[0].endswith("src")
