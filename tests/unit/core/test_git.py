"""Tests for git utilities."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from lucidscan.core.git import (
    filter_files_by_extension,
    get_changed_files,
    get_git_root,
    is_git_repo,
)


class TestIsGitRepo:
    """Tests for is_git_repo function."""

    def test_is_git_repo_true(self, tmp_path: Path) -> None:
        """Test detection of a git repository."""
        # Initialize a git repo
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
        assert is_git_repo(tmp_path) is True

    def test_is_git_repo_false(self, tmp_path: Path) -> None:
        """Test detection of non-git directory."""
        assert is_git_repo(tmp_path) is False

    def test_is_git_repo_git_not_found(self, tmp_path: Path) -> None:
        """Test handling when git is not available."""
        with patch("subprocess.run", side_effect=FileNotFoundError):
            assert is_git_repo(tmp_path) is False


class TestGetGitRoot:
    """Tests for get_git_root function."""

    def test_get_git_root(self, tmp_path: Path) -> None:
        """Test getting git root directory."""
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
        assert get_git_root(tmp_path) == tmp_path

    def test_get_git_root_subdir(self, tmp_path: Path) -> None:
        """Test getting git root from subdirectory."""
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        assert get_git_root(subdir) == tmp_path

    def test_get_git_root_not_repo(self, tmp_path: Path) -> None:
        """Test get_git_root on non-git directory."""
        assert get_git_root(tmp_path) is None


class TestGetChangedFiles:
    """Tests for get_changed_files function."""

    def test_get_changed_files_not_git_repo(self, tmp_path: Path) -> None:
        """Test returns None for non-git directory."""
        result = get_changed_files(tmp_path)
        assert result is None

    def test_get_changed_files_no_changes(self, tmp_path: Path) -> None:
        """Test returns empty list when no changes."""
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
        subprocess.run(
            ["git", "config", "user.email", "test@test.com"],
            cwd=tmp_path,
            capture_output=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Test"],
            cwd=tmp_path,
            capture_output=True,
        )
        result = get_changed_files(tmp_path)
        assert result == []

    def test_get_changed_files_untracked(self, tmp_path: Path) -> None:
        """Test detection of untracked files."""
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)

        # Create an untracked file
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello')")

        result = get_changed_files(tmp_path)
        assert result is not None
        assert test_file in result

    def test_get_changed_files_staged(self, tmp_path: Path) -> None:
        """Test detection of staged files."""
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
        subprocess.run(
            ["git", "config", "user.email", "test@test.com"],
            cwd=tmp_path,
            capture_output=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Test"],
            cwd=tmp_path,
            capture_output=True,
        )

        # Create and stage a file
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello')")
        subprocess.run(["git", "add", "test.py"], cwd=tmp_path, capture_output=True)

        result = get_changed_files(tmp_path)
        assert result is not None
        assert test_file in result

    def test_get_changed_files_modified(self, tmp_path: Path) -> None:
        """Test detection of modified files."""
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
        subprocess.run(
            ["git", "config", "user.email", "test@test.com"],
            cwd=tmp_path,
            capture_output=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Test"],
            cwd=tmp_path,
            capture_output=True,
        )

        # Create, commit, then modify a file
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello')")
        subprocess.run(["git", "add", "test.py"], cwd=tmp_path, capture_output=True)
        subprocess.run(
            ["git", "commit", "-m", "initial"],
            cwd=tmp_path,
            capture_output=True,
        )

        # Modify the file
        test_file.write_text("print('hello world')")

        result = get_changed_files(tmp_path)
        assert result is not None
        assert test_file in result


class TestFilterFilesByExtension:
    """Tests for filter_files_by_extension function."""

    def test_filter_no_extensions(self, tmp_path: Path) -> None:
        """Test filter returns all files when no extensions specified."""
        files = [tmp_path / "a.py", tmp_path / "b.js", tmp_path / "c.txt"]
        result = filter_files_by_extension(files, None)
        assert result == files

    def test_filter_single_extension(self, tmp_path: Path) -> None:
        """Test filter with single extension."""
        files = [tmp_path / "a.py", tmp_path / "b.js", tmp_path / "c.py"]
        result = filter_files_by_extension(files, [".py"])
        assert len(result) == 2
        assert tmp_path / "a.py" in result
        assert tmp_path / "c.py" in result

    def test_filter_multiple_extensions(self, tmp_path: Path) -> None:
        """Test filter with multiple extensions."""
        files = [tmp_path / "a.py", tmp_path / "b.js", tmp_path / "c.ts"]
        result = filter_files_by_extension(files, [".js", ".ts"])
        assert len(result) == 2
        assert tmp_path / "b.js" in result
        assert tmp_path / "c.ts" in result

    def test_filter_extension_without_dot(self, tmp_path: Path) -> None:
        """Test filter handles extensions without leading dot."""
        files = [tmp_path / "a.py", tmp_path / "b.js"]
        result = filter_files_by_extension(files, ["py"])
        assert len(result) == 1
        assert tmp_path / "a.py" in result

    def test_filter_case_insensitive(self, tmp_path: Path) -> None:
        """Test filter is case insensitive."""
        files = [tmp_path / "a.PY", tmp_path / "b.py"]
        result = filter_files_by_extension(files, [".py"])
        assert len(result) == 2
