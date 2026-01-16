"""Git utilities for detecting changed files.

Provides functionality to detect uncommitted changes in a git repository
for partial/incremental scanning.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import List, Optional

from lucidscan.core.logging import get_logger

LOGGER = get_logger(__name__)


def is_git_repo(path: Path) -> bool:
    """Check if the given path is inside a git repository.

    Args:
        path: Path to check.

    Returns:
        True if inside a git repository, False otherwise.
    """
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--git-dir"],
            cwd=path,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return False


def get_git_root(path: Path) -> Optional[Path]:
    """Get the root directory of the git repository.

    Args:
        path: Path inside the repository.

    Returns:
        Path to git root, or None if not a git repository.
    """
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=path,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            return Path(result.stdout.strip())
        return None
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return None


def get_changed_files(
    project_root: Path,
    include_untracked: bool = True,
    include_staged: bool = True,
    include_unstaged: bool = True,
) -> Optional[List[Path]]:
    """Get list of changed files in the git repository.

    Returns files that have uncommitted changes (staged, unstaged, or untracked).

    Args:
        project_root: Root directory of the project.
        include_untracked: Include untracked files.
        include_staged: Include staged (added to index) files.
        include_unstaged: Include unstaged modifications.

    Returns:
        List of changed file paths (absolute), or None if not a git repo
        or git command fails.
    """
    if not is_git_repo(project_root):
        LOGGER.debug(f"Not a git repository: {project_root}")
        return None

    changed_files: set[Path] = set()

    try:
        # Get staged files (files added to index)
        if include_staged:
            result = subprocess.run(
                ["git", "diff", "--cached", "--name-only"],
                cwd=project_root,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if line:
                        file_path = project_root / line
                        if file_path.exists():
                            changed_files.add(file_path)

        # Get unstaged modifications (modified but not staged)
        if include_unstaged:
            result = subprocess.run(
                ["git", "diff", "--name-only"],
                cwd=project_root,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if line:
                        file_path = project_root / line
                        if file_path.exists():
                            changed_files.add(file_path)

        # Get untracked files
        if include_untracked:
            result = subprocess.run(
                ["git", "ls-files", "--others", "--exclude-standard"],
                cwd=project_root,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if line:
                        file_path = project_root / line
                        if file_path.exists():
                            changed_files.add(file_path)

        LOGGER.debug(f"Found {len(changed_files)} changed files in {project_root}")
        return sorted(changed_files)

    except subprocess.TimeoutExpired:
        LOGGER.warning("Git command timed out, falling back to full scan")
        return None
    except (subprocess.SubprocessError, FileNotFoundError, OSError) as e:
        LOGGER.warning(f"Git command failed: {e}, falling back to full scan")
        return None


def filter_files_by_extension(
    files: List[Path],
    extensions: Optional[List[str]] = None,
) -> List[Path]:
    """Filter files by extension.

    Args:
        files: List of file paths.
        extensions: List of extensions to include (e.g., [".py", ".js"]).
            If None, returns all files.

    Returns:
        Filtered list of files.
    """
    if extensions is None:
        return files

    # Normalize extensions to include the dot
    normalized_extensions = set()
    for ext in extensions:
        if not ext.startswith("."):
            ext = f".{ext}"
        normalized_extensions.add(ext.lower())

    return [f for f in files if f.suffix.lower() in normalized_extensions]
