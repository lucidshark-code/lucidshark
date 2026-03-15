"""Jest test runner plugin.

Jest is a delightful JavaScript Testing Framework.
https://jestjs.io/
"""

from __future__ import annotations

import hashlib
import re
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional

from lucidshark.core.logging import get_logger
from lucidshark.core.models import (
    ScanContext,
    Severity,
    SkipReason,
    ToolDomain,
    UnifiedIssue,
)
from lucidshark.plugins.test_runners.base import TestRunnerPlugin, TestResult
from lucidshark.plugins.utils import ensure_node_binary

LOGGER = get_logger(__name__)


class JestRunner(TestRunnerPlugin):
    """Jest test runner plugin for JavaScript/TypeScript test execution."""

    def __init__(self, project_root: Optional[Path] = None):
        """Initialize JestRunner.

        Args:
            project_root: Optional project root for finding Jest installation.
        """
        self._project_root = project_root

    @property
    def name(self) -> str:
        """Plugin identifier."""
        return "jest"

    @property
    def languages(self) -> List[str]:
        """Supported languages."""
        return ["javascript", "typescript"]

    def ensure_binary(self) -> Path:
        """Ensure Jest is available."""
        return ensure_node_binary(
            self._project_root,
            "jest",
            "Jest is not installed. Install it with:\n"
            "  npm install jest --save-dev\n"
            "  OR\n"
            "  npm install -g jest",
        )

    def run_tests(self, context: ScanContext) -> TestResult:
        """Run Jest on the specified paths.

        Always runs with --coverage to generate coverage data.

        Args:
            context: Scan context with paths and configuration.

        Returns:
            TestResult with test statistics and issues for failures.
        """
        try:
            binary = self.ensure_binary()
        except FileNotFoundError as e:
            LOGGER.warning(str(e))
            return TestResult()

        with tempfile.TemporaryDirectory() as tmpdir:
            report_file = Path(tmpdir) / "jest-results.json"

            cmd = [
                str(binary),
                "--json",
                f"--outputFile={report_file}",
                "--passWithNoTests",  # Don't fail if no tests found
                "--coverage",  # Always generate coverage data
            ]

            if context.paths:
                paths = [str(p) for p in context.paths]
                cmd.extend(paths)

            LOGGER.debug(f"Running: {' '.join(cmd)}")

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    cwd=str(context.project_root),
                    timeout=600,
                )
            except subprocess.TimeoutExpired:
                LOGGER.warning("Jest timed out after 600 seconds")
                context.record_skip(
                    tool_name=self.name,
                    domain=ToolDomain.TESTING,
                    reason=SkipReason.EXECUTION_FAILED,
                    message="Jest timed out after 600 seconds",
                )
                return TestResult()
            except Exception as e:
                LOGGER.error(f"Failed to run Jest: {e}")
                context.record_skip(
                    tool_name=self.name,
                    domain=ToolDomain.TESTING,
                    reason=SkipReason.EXECUTION_FAILED,
                    message=f"Failed to run Jest: {e}",
                )
                return TestResult()

            if report_file.exists():
                parsed_report = self._parse_json_report(report_file, context.project_root)
                # Even with a report file, check for TS compilation errors when
                # Jest exits non-zero. ts-jest may produce a partial report
                # (e.g. 0 tests) while compilation diagnostics appear in stderr.
                if result.returncode != 0:
                    compilation_result = self._check_compilation_errors(
                        result.stderr, result.stdout, context.project_root
                    )
                    if compilation_result is not None:
                        # Merge compilation issues into the parsed report
                        parsed_report.issues.extend(compilation_result.issues)
                        parsed_report.errors += compilation_result.errors
                return parsed_report

            # If stdout contains JSON, parse it normally
            if result.stdout and result.stdout.strip():
                parsed = self._parse_json_output(
                    result.stdout, context.project_root
                )
                if parsed.total > 0 or parsed.issues:
                    return parsed

            # No report file and no parseable JSON output.
            # Check for compilation errors (e.g. ts-jest TypeScript failures).
            if result.returncode != 0:
                compilation_result = self._check_compilation_errors(
                    result.stderr, result.stdout, context.project_root
                )
                if compilation_result is not None:
                    return compilation_result

                # Non-zero exit with no recognizable output — generic failure
                LOGGER.warning(
                    f"Jest exited with code {result.returncode} but produced "
                    f"no test results"
                )
                error_snippet = (result.stderr or result.stdout or "")[:500]
                return TestResult(
                    errors=1,
                    issues=[
                        UnifiedIssue(
                            id=f"jest-exit-{result.returncode}",
                            domain=ToolDomain.TESTING,
                            source_tool=self.name,
                            severity=Severity.HIGH,
                            rule_id="execution-error",
                            title=(
                                f"Jest exited with code {result.returncode} "
                                f"without producing test results"
                            ),
                            description=error_snippet,
                            fixable=False,
                        )
                    ],
                )

            return TestResult()

    def _parse_json_report(
        self,
        report_file: Path,
        project_root: Path,
    ) -> TestResult:
        """Parse Jest JSON report file.

        Delegates to base class _parse_json_report_file.
        """
        return self._parse_json_report_file(report_file, project_root)

    def _process_report(
        self,
        report,
        project_root,
    ) -> TestResult:
        """Process Jest JSON report (Jest-compatible format)."""
        return self._process_jest_report(report, project_root)

    # -- TypeScript compilation error detection --

    # Matches ts-jest / TypeScript diagnostic lines like:
    #   src/foo.ts:12:5 - error TS2322: Type 'string' is not assignable ...
    #   src/foo.ts(12,5): error TS2322: Type 'string' is not assignable ...
    _TS_ERROR_COLON = re.compile(
        r"^(?P<file>[^\s(]+\.tsx?):(?P<line>\d+):(?P<col>\d+)"
        r"\s*-\s*error\s+(?P<code>TS\d+):\s*(?P<msg>.+)$",
        re.MULTILINE,
    )
    _TS_ERROR_PAREN = re.compile(
        r"^(?P<file>[^\s(]+\.tsx?)\((?P<line>\d+),(?P<col>\d+)\)"
        r":\s*error\s+(?P<code>TS\d+):\s*(?P<msg>.+)$",
        re.MULTILINE,
    )

    def _check_compilation_errors(
        self,
        stderr: str,
        stdout: str,
        project_root: Path,
    ) -> Optional[TestResult]:
        """Parse stderr/stdout for TypeScript compilation errors.

        When ts-jest encounters TypeScript errors, Jest exits non-zero with
        compilation diagnostics in stderr (and sometimes stdout) but produces
        no JSON report. This method detects those diagnostics and converts
        them to proper TestResult issues.

        Args:
            stderr: Jest stderr output.
            stdout: Jest stdout output.
            project_root: Project root directory.

        Returns:
            TestResult with compilation error issues, or None if no
            compilation errors were detected.
        """
        combined = (stderr or "") + "\n" + (stdout or "")

        errors: list[dict] = []
        for pattern in (self._TS_ERROR_COLON, self._TS_ERROR_PAREN):
            for match in pattern.finditer(combined):
                errors.append(match.groupdict())

        if not errors:
            # Also check for generic ts-jest / tsc compilation failure
            # markers that may not follow the structured diagnostic format.
            ts_markers = [
                "TypeScript diagnostics",
                "error TS",
                "Cannot find module",
                "has no exported member",
                "ts-jest[ts-compiler]",
            ]
            if any(marker in combined for marker in ts_markers):
                # We know it is a TS compilation failure but could not parse
                # individual diagnostics — emit a single summary issue.
                snippet = combined.strip()[:2000]
                issue_hash = hashlib.sha256(
                    snippet.encode()
                ).hexdigest()[:12]
                return TestResult(
                    errors=1,
                    issues=[
                        UnifiedIssue(
                            id=f"jest-ts-compile-{issue_hash}",
                            domain=ToolDomain.TESTING,
                            source_tool=self.name,
                            severity=Severity.HIGH,
                            rule_id="ts-compilation-error",
                            title="TypeScript compilation failed",
                            description=snippet,
                            fixable=False,
                        )
                    ],
                )
            return None

        # De-duplicate by (file, line, code)
        seen: set[tuple[str, str, str]] = set()
        issues: list[UnifiedIssue] = []
        for err in errors:
            key = (err["file"], err["line"], err["code"])
            if key in seen:
                continue
            seen.add(key)

            file_path = Path(err["file"])
            if not file_path.is_absolute():
                file_path = project_root / file_path

            line_num = int(err["line"])
            col_num = int(err["col"])
            issue_hash = hashlib.sha256(
                f"{err['file']}:{err['line']}:{err['code']}".encode()
            ).hexdigest()[:12]

            issues.append(
                UnifiedIssue(
                    id=f"jest-ts-{issue_hash}",
                    domain=ToolDomain.TESTING,
                    source_tool=self.name,
                    severity=Severity.HIGH,
                    rule_id=err["code"],
                    title=f"TypeScript compilation error {err['code']}: {err['msg']}",
                    description=f"{err['file']}:{err['line']}:{err['col']} - error {err['code']}: {err['msg']}",
                    file_path=file_path,
                    line_start=line_num,
                    line_end=line_num,
                    column_start=col_num,
                    fixable=False,
                )
            )

        LOGGER.warning(
            f"Jest failed with {len(issues)} TypeScript compilation error(s)"
        )
        return TestResult(
            errors=len(issues),
            issues=issues,
        )
