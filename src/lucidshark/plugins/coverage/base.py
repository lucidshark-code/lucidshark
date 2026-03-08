"""Base class for coverage plugins.

All coverage plugins inherit from CoveragePlugin and implement the measure_coverage() method.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from lucidshark.core.models import CoverageSummary, ScanContext, UnifiedIssue, ToolDomain

__all__ = ["CoveragePlugin", "CoverageResult", "FileCoverage"]


@dataclass
class FileCoverage:
    """Coverage statistics for a single file."""

    file_path: Path
    total_lines: int = 0
    covered_lines: int = 0
    missing_lines: List[int] = field(default_factory=list)
    excluded_lines: int = 0

    @property
    def percentage(self) -> float:
        """Coverage percentage for this file."""
        if self.total_lines == 0:
            return 100.0
        return (self.covered_lines / self.total_lines) * 100


@dataclass
class CoverageResult:
    """Result statistics from coverage analysis."""

    total_lines: int = 0
    covered_lines: int = 0
    missing_lines: int = 0
    excluded_lines: int = 0
    threshold: float = 0.0
    files: Dict[str, FileCoverage] = field(default_factory=dict)
    issues: List[UnifiedIssue] = field(default_factory=list)
    tool: str = ""  # Name of the coverage tool that produced this result

    @property
    def percentage(self) -> float:
        """Overall coverage percentage."""
        if self.total_lines == 0:
            return 100.0
        return (self.covered_lines / self.total_lines) * 100

    @property
    def passed(self) -> bool:
        """Whether coverage meets the threshold."""
        return self.percentage >= self.threshold

    def to_summary(self) -> CoverageSummary:
        """Convert to CoverageSummary for CLI output.

        Returns:
            CoverageSummary dataclass with all coverage statistics.
        """
        return CoverageSummary(
            coverage_percentage=round(self.percentage, 2),
            threshold=self.threshold,
            total_lines=self.total_lines,
            covered_lines=self.covered_lines,
            missing_lines=self.missing_lines,
            passed=self.passed,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for MCP/JSON output.

        Returns:
            Dictionary with coverage statistics.
        """
        return {
            "coverage_percentage": round(self.percentage, 2),
            "threshold": self.threshold,
            "total_lines": self.total_lines,
            "covered_lines": self.covered_lines,
            "missing_lines": self.missing_lines,
            "passed": self.passed,
        }

    def filter_to_changed_files(
        self,
        changed_files: List[Path],
        project_root: Path,
    ) -> "CoverageResult":
        """Create filtered copy with only coverage for changed files.

        This is used for PR-based incremental coverage reporting. The full test
        suite still runs, but only coverage for changed files is reported.

        Args:
            changed_files: List of changed file paths (absolute).
            project_root: Project root for path resolution.

        Returns:
            New CoverageResult with filtered files and recalculated stats.
        """
        # Build a set of relative path strings for matching
        changed_set: set[str] = set()
        for f in changed_files:
            try:
                rel_path = f.relative_to(project_root)
                changed_set.add(str(rel_path))
            except ValueError:
                # File is outside project root, use absolute path
                changed_set.add(str(f))

        # Filter files dict to only include changed files
        filtered_files: Dict[str, FileCoverage] = {}
        for path, cov in self.files.items():
            # Check if this file matches any changed file
            if path in changed_set:
                filtered_files[path] = cov
            else:
                # Also check if paths match by suffix (handles src/foo.py vs foo.py)
                # Use Path objects to ensure proper path comparison (not string suffix)
                path_obj = Path(path)
                for changed in changed_set:
                    changed_path = Path(changed)
                    # Check if one path ends with the other's parts
                    # e.g., "src/utils/foo.py" matches "utils/foo.py" or "foo.py"
                    try:
                        # Try to check if path ends with changed or vice versa
                        if path_obj.parts[-len(changed_path.parts):] == changed_path.parts:
                            filtered_files[path] = cov
                            break
                        elif changed_path.parts[-len(path_obj.parts):] == path_obj.parts:
                            filtered_files[path] = cov
                            break
                    except (IndexError, ValueError):
                        continue

        # Recalculate totals from filtered files
        total_lines = sum(f.total_lines for f in filtered_files.values())
        covered_lines = sum(f.covered_lines for f in filtered_files.values())
        missing_lines = sum(len(f.missing_lines) for f in filtered_files.values())

        return CoverageResult(
            total_lines=total_lines,
            covered_lines=covered_lines,
            missing_lines=missing_lines,
            excluded_lines=self.excluded_lines,
            threshold=self.threshold,
            files=filtered_files,
            issues=[],  # Issues will be regenerated if coverage is below threshold
            tool=self.tool,
        )


class CoveragePlugin(ABC):
    """Abstract base class for coverage plugins.

    Coverage plugins provide code coverage analysis functionality.
    Each plugin wraps a specific coverage tool (coverage.py, Istanbul, etc.).
    """

    def __init__(self, project_root: Optional[Path] = None, **kwargs) -> None:
        """Initialize the coverage plugin.

        Args:
            project_root: Optional project root for tool installation.
            **kwargs: Additional arguments for subclasses.
        """
        self._project_root = project_root

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique plugin identifier (e.g., 'coverage_py', 'istanbul').

        Returns:
            Plugin name string.
        """

    @property
    @abstractmethod
    def languages(self) -> List[str]:
        """Languages this coverage tool supports.

        Returns:
            List of language names (e.g., ['python'], ['javascript', 'typescript']).
        """

    @property
    def domain(self) -> ToolDomain:
        """Tool domain (always COVERAGE for coverage plugins).

        Returns:
            ToolDomain.COVERAGE
        """
        return ToolDomain.COVERAGE

    @abstractmethod
    def get_version(self) -> str:
        """Get the version of the underlying coverage tool.

        Returns:
            Version string.
        """

    @abstractmethod
    def ensure_binary(self) -> Path:
        """Ensure the coverage tool is installed.

        Finds or installs the tool if not present.

        Returns:
            Path to the tool binary.

        Raises:
            FileNotFoundError: If the tool cannot be found or installed.
        """

    @abstractmethod
    def measure_coverage(
        self,
        context: ScanContext,
        threshold: float = 80.0,
    ) -> CoverageResult:
        """Parse existing coverage data and return results.

        Coverage plugins only parse existing coverage data files. They never
        run tests independently. If no coverage data is found, the result
        should contain an error issue directing the user to run the testing
        domain first.

        Args:
            context: Scan context with paths and configuration.
            threshold: Coverage percentage threshold (default 80%).

        Returns:
            CoverageResult with coverage statistics and issues if below threshold.
        """
