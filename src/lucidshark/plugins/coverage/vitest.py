"""Vitest coverage plugin.

Vitest has built-in coverage support via @vitest/coverage-v8 or
@vitest/coverage-istanbul, outputting Istanbul-compatible JSON reports.
https://vitest.dev/guide/coverage
"""

from __future__ import annotations

import hashlib
import json
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

# Standard locations where Vitest writes coverage-summary.json
_COVERAGE_REPORT_PATHS = [
    "coverage/coverage-summary.json",
    "coverage/coverage-final.json",
]


class VitestCoveragePlugin(CoveragePlugin):
    """Vitest coverage plugin for JavaScript/TypeScript coverage analysis.

    Uses Vitest's built-in coverage support which outputs Istanbul-compatible
    JSON reports. Requires @vitest/coverage-v8 or @vitest/coverage-istanbul
    to be installed in the project.
    """

    def __init__(self, project_root: Optional[Path] = None):
        """Initialize VitestCoveragePlugin.

        Args:
            project_root: Optional project root for finding Vitest installation.
        """
        self._project_root = project_root

    @property
    def name(self) -> str:
        """Plugin identifier."""
        return "vitest_coverage"

    @property
    def languages(self) -> List[str]:
        """Supported languages."""
        return ["javascript", "typescript"]

    def get_version(self) -> str:
        """Get Vitest version."""
        try:
            binary = self.ensure_binary()
            return get_cli_version(binary)
        except FileNotFoundError:
            return "unknown"

    def ensure_binary(self) -> Path:
        """Ensure Vitest is available."""
        return ensure_node_binary(
            self._project_root,
            "vitest",
            "Vitest is not installed. Install it with:\n"
            "  npm install vitest --save-dev\n"
            "\n"
            "For coverage support, also install a coverage provider:\n"
            "  npm install @vitest/coverage-v8 --save-dev\n"
            "  OR\n"
            "  npm install @vitest/coverage-istanbul --save-dev",
        )

    def measure_coverage(
        self,
        context: ScanContext,
        threshold: float = 80.0,
    ) -> CoverageResult:
        """Parse existing Vitest coverage data.

        Looks for existing coverage data in the coverage/ directory.
        If no coverage data is found, returns an error issue directing
        the user to run the testing domain first.

        Args:
            context: Scan context with paths and configuration.
            threshold: Coverage percentage threshold (default 80%).

        Returns:
            CoverageResult with coverage statistics and issues if below threshold.
        """
        # Find and parse the coverage report
        result = self._find_and_parse_report(context.project_root, threshold)

        # If no data was found, add a no-data error issue
        if result.total_lines == 0 and not result.issues:
            result.issues.append(self._create_no_data_issue())

        return result

    def _find_and_parse_report(
        self,
        project_root: Path,
        threshold: float,
    ) -> CoverageResult:
        """Find and parse the coverage JSON report.

        Vitest writes coverage reports to the coverage/ directory by default.

        Args:
            project_root: Project root directory.
            threshold: Coverage percentage threshold.

        Returns:
            CoverageResult with parsed data.
        """
        for rel_path in _COVERAGE_REPORT_PATHS:
            report_file = project_root / rel_path
            if report_file.exists():
                if rel_path.endswith("coverage-summary.json"):
                    return self._parse_summary_report(
                        report_file, project_root, threshold
                    )
                else:
                    return self._parse_final_report(
                        report_file, project_root, threshold
                    )

        LOGGER.warning(
            "No Vitest coverage report found. Ensure a coverage provider is installed:\n"
            "  npm install @vitest/coverage-v8 --save-dev"
        )
        return CoverageResult(threshold=threshold, tool="vitest_coverage")

    def _parse_summary_report(
        self,
        report_file: Path,
        project_root: Path,
        threshold: float,
    ) -> CoverageResult:
        """Parse Istanbul-format coverage-summary.json report.

        Args:
            report_file: Path to coverage-summary.json.
            project_root: Project root directory.
            threshold: Coverage percentage threshold.

        Returns:
            CoverageResult with parsed data.
        """
        try:
            with open(report_file) as f:
                report = json.load(f)
        except Exception as e:
            LOGGER.error(f"Failed to parse Vitest coverage report: {e}")
            return CoverageResult(threshold=threshold, tool="vitest_coverage")

        return self._process_istanbul_summary(report, project_root, threshold)

    def _parse_final_report(
        self,
        report_file: Path,
        project_root: Path,
        threshold: float,
    ) -> CoverageResult:
        """Parse Istanbul-format coverage-final.json report.

        This format contains per-file statement/branch/function maps.
        We extract line-level coverage from the statement map.

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
            LOGGER.error(f"Failed to parse Vitest coverage report: {e}")
            return CoverageResult(threshold=threshold, tool="vitest_coverage")

        total_lines = 0
        covered_lines = 0
        files: Dict[str, FileCoverage] = {}

        for file_path, file_data in report.items():
            s_map = file_data.get("s", {})
            file_total = len(s_map)
            file_covered = sum(1 for v in s_map.values() if v > 0)
            missing = [
                int(k) for k, v in s_map.items() if v == 0
            ]

            total_lines += file_total
            covered_lines += file_covered

            try:
                rel_path = str(Path(file_path).relative_to(project_root))
            except ValueError:
                rel_path = file_path

            files[rel_path] = FileCoverage(
                file_path=project_root / rel_path,
                total_lines=file_total,
                covered_lines=file_covered,
                missing_lines=missing,
                excluded_lines=0,
            )

        percent_covered = (covered_lines / total_lines * 100) if total_lines > 0 else 100.0

        result = CoverageResult(
            total_lines=total_lines,
            covered_lines=covered_lines,
            missing_lines=total_lines - covered_lines,
            excluded_lines=0,
            threshold=threshold,
            files=files,
            tool="vitest_coverage",
        )

        if percent_covered < threshold:
            result.issues.append(
                self._create_coverage_issue(percent_covered, threshold, total_lines, covered_lines)
            )

        LOGGER.info(
            f"Vitest coverage: {percent_covered:.1f}% ({covered_lines}/{total_lines} lines) "
            f"- threshold: {threshold}%"
        )

        return result

    def _process_istanbul_summary(
        self,
        report: Dict[str, Any],
        project_root: Path,
        threshold: float,
    ) -> CoverageResult:
        """Process Istanbul-format summary report.

        This is the same format produced by Istanbul/NYC, making the Vitest
        coverage output directly compatible.

        Args:
            report: Parsed JSON report.
            project_root: Project root directory.
            threshold: Coverage percentage threshold.

        Returns:
            CoverageResult with parsed data.
        """
        total = report.get("total", {})
        lines = total.get("lines", {})
        statements = total.get("statements", {})
        branches = total.get("branches", {})
        functions = total.get("functions", {})

        total_lines = lines.get("total", 0)
        covered_lines = lines.get("covered", 0)
        percent_covered = lines.get("pct", 0.0)

        result = CoverageResult(
            total_lines=total_lines,
            covered_lines=covered_lines,
            missing_lines=total_lines - covered_lines,
            excluded_lines=0,
            threshold=threshold,
            tool="vitest_coverage",
        )

        # Parse per-file coverage
        for file_path, file_data in report.items():
            if file_path == "total":
                continue

            file_lines = file_data.get("lines", {})
            file_total = file_lines.get("total", 0)
            file_covered = file_lines.get("covered", 0)

            try:
                rel_path = str(Path(file_path).relative_to(project_root))
            except ValueError:
                rel_path = file_path

            file_coverage = FileCoverage(
                file_path=project_root / rel_path,
                total_lines=file_total,
                covered_lines=file_covered,
                missing_lines=[],
                excluded_lines=0,
            )
            result.files[rel_path] = file_coverage

        if percent_covered < threshold:
            result.issues.append(
                self._create_coverage_issue(
                    percent_covered,
                    threshold,
                    total_lines,
                    covered_lines,
                    statements=statements,
                    branches=branches,
                    functions=functions,
                )
            )

        LOGGER.info(
            f"Vitest coverage: {percent_covered:.1f}% ({covered_lines}/{total_lines} lines) "
            f"- threshold: {threshold}%"
        )

        return result

    def _create_coverage_issue(
        self,
        percentage: float,
        threshold: float,
        total_lines: int,
        covered_lines: int,
        statements: Optional[Dict[str, Any]] = None,
        branches: Optional[Dict[str, Any]] = None,
        functions: Optional[Dict[str, Any]] = None,
    ) -> UnifiedIssue:
        """Create a UnifiedIssue for coverage below threshold.

        Args:
            percentage: Actual coverage percentage.
            threshold: Required coverage threshold.
            total_lines: Total number of lines.
            covered_lines: Number of covered lines.
            statements: Optional statement coverage data.
            branches: Optional branch coverage data.
            functions: Optional function coverage data.

        Returns:
            UnifiedIssue for coverage failure.
        """
        if percentage < 50:
            severity = Severity.HIGH
        elif percentage < threshold - 10:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        content = f"vitest_coverage:{round(percentage)}:{threshold}"
        hash_val = hashlib.sha256(content.encode()).hexdigest()[:12]
        issue_id = f"vitest-cov-{hash_val}"

        gap = threshold - percentage
        missing_lines = total_lines - covered_lines

        desc_parts = [
            f"Project coverage is {percentage:.1f}%, which is {gap:.1f}% below "
            f"the required threshold of {threshold}%. "
            f"Lines: {covered_lines}/{total_lines} ({percentage:.1f}%)"
        ]

        if statements:
            desc_parts.append(
                f", Statements: {statements.get('covered', 0)}/{statements.get('total', 0)} "
                f"({statements.get('pct', 0):.1f}%)"
            )
        if branches:
            desc_parts.append(
                f", Branches: {branches.get('covered', 0)}/{branches.get('total', 0)} "
                f"({branches.get('pct', 0):.1f}%)"
            )
        if functions:
            desc_parts.append(
                f", Functions: {functions.get('covered', 0)}/{functions.get('total', 0)} "
                f"({functions.get('pct', 0):.1f}%)"
            )

        return UnifiedIssue(
            id=issue_id,
            domain=ToolDomain.COVERAGE,
            source_tool="vitest_coverage",
            severity=severity,
            rule_id="coverage_below_threshold",
            title=f"Coverage {percentage:.1f}% is below threshold {threshold}%",
            description="".join(desc_parts),
            recommendation=f"Add tests to cover at least {gap:.1f}% more of the codebase.",
            file_path=None,
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
            },
        )

    def _create_no_data_issue(self) -> UnifiedIssue:
        """Create a UnifiedIssue when no coverage data is found."""
        return UnifiedIssue(
            id="no-coverage-data-vitest_coverage",
            domain=ToolDomain.COVERAGE,
            source_tool="vitest_coverage",
            severity=Severity.HIGH,
            rule_id="no_coverage_data",
            title="No coverage data found",
            description=(
                "No coverage data found for vitest. "
                "Ensure the testing domain is active and has run before coverage analysis. "
                "Test runners generate coverage data automatically when they execute."
            ),
            fixable=False,
        )
