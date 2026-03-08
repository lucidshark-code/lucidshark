"""Istanbul/NYC coverage plugin.

Istanbul (via NYC) is a JavaScript code coverage tool.
https://istanbul.js.org/
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from lucidshark.core.logging import get_logger
from lucidshark.core.models import (
    ScanContext,
    Severity,
    ToolDomain,
    UnifiedIssue,
)
from lucidshark.plugins.coverage.base import (
    CoveragePlugin,
    CoverageResult,
    FileCoverage,
)
from lucidshark.plugins.utils import (
    ensure_node_binary,
    get_cli_version,
)

LOGGER = get_logger(__name__)

# Standard locations where Jest writes Istanbul-format coverage reports.
_JEST_COVERAGE_PATHS = [
    "coverage/coverage-summary.json",
    "coverage/coverage-final.json",
]


class IstanbulPlugin(CoveragePlugin):
    """Istanbul/NYC coverage plugin for JavaScript/TypeScript coverage analysis."""

    def __init__(self, project_root: Optional[Path] = None):
        """Initialize IstanbulPlugin.

        Args:
            project_root: Optional project root for finding NYC installation.
        """
        self._project_root = project_root

    @property
    def name(self) -> str:
        """Plugin identifier."""
        return "istanbul"

    @property
    def languages(self) -> List[str]:
        """Supported languages."""
        return ["javascript", "typescript"]

    def get_version(self) -> str:
        """Get NYC version."""
        try:
            binary = self.ensure_binary()
            return get_cli_version(binary)
        except FileNotFoundError:
            return "unknown"

    def ensure_binary(self) -> Path:
        """Ensure NYC is available."""
        return ensure_node_binary(
            self._project_root,
            "nyc",
            "NYC (Istanbul) is not installed. Install it with:\n"
            "  npm install nyc --save-dev\n"
            "  OR\n"
            "  npm install -g nyc",
        )

    def measure_coverage(
        self,
        context: ScanContext,
        threshold: float = 80.0,
    ) -> CoverageResult:
        """Parse existing coverage data.

        Looks for existing .nyc_output directory and generates a report from it.
        If no coverage data exists or report generation fails, returns an error
        issue directing the user to run the testing domain first.

        Args:
            context: Scan context with paths and configuration.
            threshold: Coverage percentage threshold (default 80%).

        Returns:
            CoverageResult with coverage statistics and issues if below threshold.
        """
        # First, check if Jest/Istanbul wrote coverage files directly
        # (modern Jest writes to coverage/ without needing .nyc_output)
        for rel_path in _JEST_COVERAGE_PATHS:
            report_file = context.project_root / rel_path
            if report_file.exists():
                if rel_path.endswith("coverage-summary.json"):
                    result = self._parse_json_report(
                        report_file, context.project_root, threshold
                    )
                else:
                    result = self._parse_final_report(
                        report_file, context.project_root, threshold
                    )
                if result.total_lines == 0 and not result.issues:
                    result.issues.append(self._create_no_data_issue())
                return result

        # Fallback: use .nyc_output/ + nyc report (for projects using NYC directly)
        try:
            binary = self.ensure_binary()
        except FileNotFoundError as e:
            LOGGER.warning(str(e))
            result = CoverageResult(threshold=threshold, tool="istanbul")
            result.issues.append(self._create_no_data_issue())
            return result

        # Check if .nyc_output directory exists with coverage data
        nyc_output = context.project_root / ".nyc_output"
        if not nyc_output.exists() or not any(nyc_output.iterdir()):
            LOGGER.warning("No coverage/ or .nyc_output/ directory found with coverage data")
            result = CoverageResult(threshold=threshold, tool="istanbul")
            result.issues.append(self._create_no_data_issue())
            return result

        # Generate JSON report from existing coverage data
        result = self._generate_and_parse_report(binary, context, threshold)

        # If report generation returned an empty result (failure), add no-data issue
        if result.total_lines == 0 and not result.issues:
            result.issues.append(self._create_no_data_issue())

        return result

    def _generate_and_parse_report(
        self,
        binary: Path,
        context: ScanContext,
        threshold: float,
    ) -> CoverageResult:
        """Generate JSON report and parse it.

        Args:
            binary: Path to NYC binary.
            context: Scan context.
            threshold: Coverage percentage threshold.

        Returns:
            CoverageResult with parsed data.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            report_dir = Path(tmpdir)

            cmd = [
                str(binary),
                "report",
                "--reporter=json-summary",
                f"--report-dir={report_dir}",
            ]

            LOGGER.debug(f"Running: {' '.join(cmd)}")

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    cwd=str(context.project_root),
                )

                if result.returncode != 0:
                    LOGGER.warning(f"NYC report failed: {result.stderr}")
                    return CoverageResult(threshold=threshold, tool="istanbul")

            except Exception as e:
                LOGGER.error(f"Failed to generate coverage report: {e}")
                return CoverageResult(threshold=threshold, tool="istanbul")

            # Parse JSON report
            report_file = report_dir / "coverage-summary.json"
            if report_file.exists():
                return self._parse_json_report(report_file, context.project_root, threshold)
            else:
                LOGGER.warning("Coverage JSON report not generated")
                return CoverageResult(threshold=threshold, tool="istanbul")

    def _parse_json_report(
        self,
        report_file: Path,
        project_root: Path,
        threshold: float,
    ) -> CoverageResult:
        """Parse Istanbul JSON summary report.

        Args:
            report_file: Path to JSON report file.
            project_root: Project root directory.
            threshold: Coverage percentage threshold.

        Returns:
            CoverageResult with parsed data.
        """
        try:
            with open(report_file) as f:
                report = json.load(f)
        except Exception as e:
            LOGGER.error(f"Failed to parse Istanbul JSON report: {e}")
            return CoverageResult(threshold=threshold, tool="istanbul")

        # Get total statistics
        total = report.get("total", {})
        lines = total.get("lines", {})
        statements = total.get("statements", {})
        branches = total.get("branches", {})
        functions = total.get("functions", {})

        # Calculate overall coverage (use lines as primary metric)
        total_lines = lines.get("total", 0)
        covered_lines = lines.get("covered", 0)
        percent_covered = lines.get("pct", 0.0)

        result = CoverageResult(
            total_lines=total_lines,
            covered_lines=covered_lines,
            missing_lines=total_lines - covered_lines,
            excluded_lines=0,
            threshold=threshold,
            tool="istanbul",
        )

        # Parse per-file coverage (all keys except "total")
        for file_path, file_data in report.items():
            if file_path == "total":
                continue

            file_lines = file_data.get("lines", {})
            file_total = file_lines.get("total", 0)
            file_covered = file_lines.get("covered", 0)

            file_coverage = FileCoverage(
                file_path=project_root / file_path,
                total_lines=file_total,
                covered_lines=file_covered,
                missing_lines=[],  # Istanbul doesn't provide specific line numbers in summary
                excluded_lines=0,
            )
            result.files[file_path] = file_coverage

        # Generate issue if below threshold
        if percent_covered < threshold:
            issue = self._create_coverage_issue(
                percent_covered,
                threshold,
                total_lines,
                covered_lines,
                total_lines - covered_lines,
                statements,
                branches,
                functions,
            )
            result.issues.append(issue)

        LOGGER.info(
            f"Coverage: {percent_covered:.1f}% ({covered_lines}/{total_lines} lines) "
            f"- threshold: {threshold}%"
        )

        return result

    def _parse_final_report(
        self,
        report_file: Path,
        project_root: Path,
        threshold: float,
    ) -> CoverageResult:
        """Parse Istanbul-format coverage-final.json report.

        This format contains per-file statement/branch/function maps.
        We extract statement-level coverage from the ``s`` dict and use
        ``statementMap`` to identify missing lines.

        Args:
            report_file: Path to coverage-final.json.
            project_root: Project root directory.
            threshold: Coverage percentage threshold.

        Returns:
            CoverageResult with parsed data.
        """
        try:
            with open(report_file) as f:
                report = json.load(f)
        except Exception as e:
            LOGGER.error(f"Failed to parse Istanbul coverage-final.json: {e}")
            return CoverageResult(threshold=threshold, tool="istanbul")

        total_statements = 0
        covered_statements = 0
        files: Dict[str, FileCoverage] = {}

        for file_path, file_data in report.items():
            s_map = file_data.get("s", {})
            statement_map = file_data.get("statementMap", {})
            file_total = len(s_map)
            file_covered = sum(1 for v in s_map.values() if v > 0)

            # Collect missing lines from statementMap where s[key] == 0
            missing_lines: list[int] = []
            for key, count in s_map.items():
                if count == 0 and key in statement_map:
                    start_line = statement_map[key].get("start", {}).get("line")
                    if start_line is not None:
                        missing_lines.append(start_line)
            missing_lines.sort()

            total_statements += file_total
            covered_statements += file_covered

            try:
                rel_path = str(Path(file_path).relative_to(project_root))
            except ValueError:
                rel_path = file_path

            files[rel_path] = FileCoverage(
                file_path=project_root / rel_path,
                total_lines=file_total,
                covered_lines=file_covered,
                missing_lines=missing_lines,
                excluded_lines=0,
            )

        percent_covered = (
            (covered_statements / total_statements * 100)
            if total_statements > 0
            else 100.0
        )

        result = CoverageResult(
            total_lines=total_statements,
            covered_lines=covered_statements,
            missing_lines=total_statements - covered_statements,
            excluded_lines=0,
            threshold=threshold,
            files=files,
            tool="istanbul",
        )

        if percent_covered < threshold:
            issue = self._create_coverage_issue(
                percent_covered,
                threshold,
                total_statements,
                covered_statements,
                total_statements - covered_statements,
                statements={},
                branches={},
                functions={},
            )
            result.issues.append(issue)

        LOGGER.info(
            f"Coverage: {percent_covered:.1f}% "
            f"({covered_statements}/{total_statements} statements) "
            f"- threshold: {threshold}%"
        )

        return result

    def _create_coverage_issue(
        self,
        percentage: float,
        threshold: float,
        total_lines: int,
        covered_lines: int,
        missing_lines: int,
        statements: Dict[str, Any],
        branches: Dict[str, Any],
        functions: Dict[str, Any],
    ) -> UnifiedIssue:
        """Create a UnifiedIssue for coverage below threshold.

        Args:
            percentage: Actual coverage percentage.
            threshold: Required coverage threshold.
            total_lines: Total number of lines.
            covered_lines: Number of covered lines.
            missing_lines: Number of missing lines.
            statements: Statement coverage data.
            branches: Branch coverage data.
            functions: Function coverage data.

        Returns:
            UnifiedIssue for coverage failure.
        """
        # Determine severity based on how far below threshold
        if percentage < 50:
            severity = Severity.HIGH
        elif percentage < threshold - 10:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        # Generate deterministic ID
        issue_id = self._generate_issue_id(percentage, threshold)

        gap = threshold - percentage

        return UnifiedIssue(
            id=issue_id,
            domain=ToolDomain.COVERAGE,
            source_tool="istanbul",
            severity=severity,
            rule_id="coverage_below_threshold",
            title=f"Coverage {percentage:.1f}% is below threshold {threshold}%",
            description=(
                f"Project coverage is {percentage:.1f}%, which is {gap:.1f}% below "
                f"the required threshold of {threshold}%. "
                f"Lines: {covered_lines}/{total_lines} ({percentage:.1f}%), "
                f"Statements: {statements.get('covered', 0)}/{statements.get('total', 0)} ({statements.get('pct', 0):.1f}%), "
                f"Branches: {branches.get('covered', 0)}/{branches.get('total', 0)} ({branches.get('pct', 0):.1f}%), "
                f"Functions: {functions.get('covered', 0)}/{functions.get('total', 0)} ({functions.get('pct', 0):.1f}%)"
            ),
            recommendation=f"Add tests to cover at least {gap:.1f}% more of the codebase.",
            file_path=None,  # Project-level issue
            line_start=None,
            line_end=None,
            fixable=False,
            metadata={
                "coverage_percentage": round(percentage, 2),
                "threshold": threshold,
                "total_lines": total_lines,
                "covered_lines": covered_lines,
                "missing_lines": missing_lines,
                "gap_percentage": round(gap, 2),
                "statements": statements,
                "branches": branches,
                "functions": functions,
            },
        )

    def _generate_issue_id(self, percentage: float, threshold: float) -> str:
        """Generate deterministic issue ID.

        Args:
            percentage: Coverage percentage.
            threshold: Coverage threshold.

        Returns:
            Unique issue ID.
        """
        # ID based on rounded percentage and threshold for stability
        content = f"istanbul:{round(percentage)}:{threshold}"
        hash_val = hashlib.sha256(content.encode()).hexdigest()[:12]
        return f"istanbul-{hash_val}"

    def _create_no_data_issue(self) -> UnifiedIssue:
        """Create a UnifiedIssue when no coverage data is found."""
        return UnifiedIssue(
            id="no-coverage-data-istanbul",
            domain=ToolDomain.COVERAGE,
            source_tool="istanbul",
            severity=Severity.HIGH,
            rule_id="no_coverage_data",
            title="No coverage data found",
            description=(
                "No coverage data found for istanbul. "
                "Looked for coverage/coverage-summary.json, coverage/coverage-final.json, "
                "and .nyc_output/ but none were found. "
                "Ensure the testing domain is active and has run before coverage analysis. "
                "Test runners generate coverage data automatically when they execute."
            ),
            fixable=False,
        )
