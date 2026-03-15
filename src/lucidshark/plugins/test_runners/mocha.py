"""Mocha test runner plugin.

Mocha is a feature-rich JavaScript test framework running on Node.js,
making asynchronous testing simple and fun.
https://mochajs.org/
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from lucidshark.core.logging import get_logger
from lucidshark.core.paths import resolve_node_bin
from lucidshark.core.models import (
    ScanContext,
    Severity,
    SkipReason,
    ToolDomain,
    UnifiedIssue,
)
from lucidshark.plugins.test_runners.base import TestResult, TestRunnerPlugin
from lucidshark.plugins.utils import ensure_node_binary

LOGGER = get_logger(__name__)


class MochaRunner(TestRunnerPlugin):
    """Mocha test runner plugin for JavaScript/TypeScript test execution.

    Mocha does not have built-in coverage support. Use NYC/Istanbul
    separately (``nyc mocha``) for coverage instrumentation, or configure
    coverage via the ``coverage`` domain with the ``istanbul`` tool.
    """

    def __init__(self, project_root: Optional[Path] = None):
        """Initialize MochaRunner.

        Args:
            project_root: Optional project root for finding Mocha installation.
        """
        self._project_root = project_root

    @property
    def name(self) -> str:
        """Plugin identifier."""
        return "mocha"

    @property
    def languages(self) -> List[str]:
        """Supported languages."""
        return ["javascript", "typescript"]

    def ensure_binary(self) -> Path:
        """Ensure Mocha is available."""
        return ensure_node_binary(
            self._project_root,
            "mocha",
            "Mocha is not installed. Install it with:\n"
            "  npm install mocha --save-dev\n"
            "  OR\n"
            "  npm install -g mocha",
        )

    def _find_nyc(self) -> Optional[Path]:
        """Find the NYC binary for coverage instrumentation.

        Checks project node_modules/.bin/ first, then system PATH.

        Returns:
            Path to nyc binary, or None if not found.
        """
        if self._project_root:
            local_nyc = resolve_node_bin(self._project_root, "nyc")
            if local_nyc:
                return local_nyc

        system_nyc = shutil.which("nyc")
        if system_nyc:
            return Path(system_nyc)

        return None

    def run_tests(self, context: ScanContext) -> TestResult:
        """Run Mocha on the specified paths.

        Uses the built-in JSON reporter which outputs to stdout.
        When the coverage domain is enabled and NYC is available, wraps
        the Mocha command with NYC to generate coverage data.

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

        # Check if coverage is enabled and NYC is available
        coverage_enabled = ToolDomain.COVERAGE in context.enabled_domains
        nyc_binary = self._find_nyc() if coverage_enabled else None
        if coverage_enabled and nyc_binary is None:
            LOGGER.info(
                "Coverage domain is enabled but NYC is not installed. "
                "Install it with: npm install nyc --save-dev"
            )

        # Build the command: optionally wrap with NYC for coverage
        cmd: List[str] = []
        if nyc_binary is not None:
            cmd.extend([
                str(nyc_binary),
                "--reporter=json-summary",
                "--report-dir=coverage",
            ])

        # Mocha's built-in JSON reporter writes to stdout only.
        # We parse stdout directly — no temp file needed.
        cmd.extend([
            str(binary),
            "--reporter=json",
            "--recursive",  # Search test dirs recursively
            "--exit",  # Force exit after tests (prevents hanging on open handles)
        ])

        # Mocha auto-discovers .mocharc.* files; no need to pass --config
        # explicitly. This ensures the user's config (spec patterns, require
        # hooks like ts-node/register, timeouts, etc.) is respected.

        if context.paths:
            # Only pass actual test files, not directories.  Mocha auto-
            # discovers test files via its config (.mocharc.*); passing a
            # directory like the project root causes it to recursively
            # require every .js file (including node_modules), which breaks.
            file_paths = [
                str(p)
                for p in context.paths
                if p.is_file()
                and p.suffix in (".js", ".ts", ".mjs", ".cjs", ".mts", ".cts")
            ]
            if file_paths:
                cmd.extend(file_paths)

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
            LOGGER.warning("Mocha timed out after 600 seconds")
            context.record_skip(
                tool_name=self.name,
                domain=ToolDomain.TESTING,
                reason=SkipReason.EXECUTION_FAILED,
                message="Mocha timed out after 600 seconds",
            )
            return TestResult()
        except Exception as e:
            LOGGER.error(f"Failed to run Mocha: {e}")
            context.record_skip(
                tool_name=self.name,
                domain=ToolDomain.TESTING,
                reason=SkipReason.EXECUTION_FAILED,
                message=f"Failed to run Mocha: {e}",
            )
            return TestResult()

        # Check for no-tests-found scenario: non-zero exit with no JSON output
        if result.returncode != 0 and not result.stdout.strip():
            stderr = result.stderr.strip()
            LOGGER.warning(
                f"Mocha exited with code {result.returncode} and no output. "
                f"stderr: {stderr[:200] if stderr else '(empty)'}"
            )
            context.record_skip(
                tool_name=self.name,
                domain=ToolDomain.TESTING,
                reason=SkipReason.NO_APPLICABLE_FILES,
                message=(
                    f"Mocha exited with code {result.returncode} "
                    "and produced no JSON output. "
                    "This may indicate no test files were found."
                ),
            )
            return TestResult()

        return self._parse_json_output(result.stdout, context.project_root)

    @staticmethod
    def has_mocha_config(project_root: Path) -> bool:
        """Check if project has Mocha configuration.

        Checks for ``.mocharc.*`` files and the ``mocha`` key in
        ``package.json``.

        Args:
            project_root: Project root directory.

        Returns:
            True if Mocha configuration is found.
        """
        config_names = [
            ".mocharc.yml",
            ".mocharc.yaml",
            ".mocharc.json",
            ".mocharc.js",
            ".mocharc.cjs",
            ".mocharc.mjs",
        ]
        for name in config_names:
            if (project_root / name).exists():
                return True

        # Check package.json for "mocha" key
        pkg_json = project_root / "package.json"
        if pkg_json.exists():
            try:
                data = json.loads(pkg_json.read_text())
                if "mocha" in data:
                    return True
            except Exception:
                pass

        return False

    def _parse_json_output(
        self,
        output: str,
        project_root: Path,
    ) -> TestResult:
        """Parse Mocha JSON output from stdout.

        Args:
            output: JSON output string.
            project_root: Project root directory.

        Returns:
            TestResult with parsed data.
        """
        if not output.strip():
            return TestResult()

        try:
            report = json.loads(output)
        except json.JSONDecodeError as e:
            LOGGER.warning(f"Failed to parse Mocha JSON output: {e}")
            return TestResult()

        return self._process_report(report, project_root)

    def _process_report(
        self,
        report: Dict[str, Any],
        project_root: Path,
    ) -> TestResult:
        """Process Mocha JSON report.

        Mocha JSON reporter format::

            {
                "stats": {
                    "suites": N, "tests": N, "passes": N,
                    "pending": N, "failures": N, "duration": N
                },
                "passes": [...],
                "failures": [...],
                "pending": [...]
            }

        Args:
            report: Parsed JSON report.
            project_root: Project root directory.

        Returns:
            TestResult with processed data.
        """
        stats = report.get("stats", {})
        num_passed = stats.get("passes", 0)
        num_failed = stats.get("failures", 0)
        num_pending = stats.get("pending", 0)
        duration_ms = stats.get("duration", 0)

        result = TestResult(
            passed=num_passed,
            failed=num_failed,
            skipped=num_pending,
            errors=0,
            duration_ms=int(duration_ms),
        )

        # Convert failures to issues
        for failure in report.get("failures", []):
            issue = self._failure_to_issue(failure, project_root)
            if issue:
                result.issues.append(issue)

        LOGGER.info(
            f"Mocha: {result.passed} passed, {result.failed} failed, "
            f"{result.skipped} pending"
        )
        return result

    def _failure_to_issue(
        self,
        failure: Dict[str, Any],
        project_root: Path,
    ) -> Optional[UnifiedIssue]:
        """Convert a Mocha test failure to UnifiedIssue.

        Args:
            failure: Failure dict from Mocha JSON report.
            project_root: Project root directory.

        Returns:
            UnifiedIssue or None.
        """
        try:
            full_title = failure.get("fullTitle", "")
            title = failure.get("title", "")
            err = failure.get("err", {})
            message = err.get("message", "Test failed")
            stack = err.get("stack", "")

            # Extract file and line from the stack trace
            file_path, line_number = self._extract_location(stack, project_root)

            # Generate deterministic ID
            issue_id = self._generate_issue_id(full_title, message)

            # Truncate message for title
            short_msg = self._truncate(message, 80)

            return UnifiedIssue(
                id=issue_id,
                domain=ToolDomain.TESTING,
                source_tool="mocha",
                severity=Severity.HIGH,
                rule_id="failed",
                title=f"{full_title}: {short_msg}",
                description=f"{message}\n\n{stack}" if stack else message,
                file_path=file_path,
                line_start=line_number,
                line_end=line_number,
                fixable=False,
                metadata={
                    "full_title": full_title,
                    "title": title,
                    "duration": failure.get("duration", 0),
                    "err_message": message,
                    "err_stack": stack,
                },
            )
        except Exception as e:
            LOGGER.warning(f"Failed to parse Mocha test failure: {e}")
            return None

    def _extract_location(
        self,
        stack: str,
        project_root: Path,
    ) -> tuple[Optional[Path], Optional[int]]:
        """Extract file path and line number from error stack trace.

        Iterates through stack trace lines looking for project-local file
        references, skipping ``node_modules`` paths.

        Args:
            stack: Error stack trace string.
            project_root: Project root directory.

        Returns:
            Tuple of (file_path, line_number) or (None, None).
        """
        if not stack:
            return None, None

        # Look for patterns like "at Context.<anonymous> (test/foo.test.js:42:15)"
        # or "at /abs/path/test/foo.test.js:42:15"
        # or "test/foo.test.js:42:15"
        patterns = [
            r"\(([^)]+\.(?:spec|test)\.(?:js|ts|mjs|cjs|mts|cts)):(\d+):\d+\)",
            r"at\s+([^\s]+\.(?:spec|test)\.(?:js|ts|mjs|cjs|mts|cts)):(\d+):\d+",
            r"\(([^)]+\.(?:js|ts|mjs|cjs|mts|cts)):(\d+):\d+\)",
            r"at\s+([^\s]+\.(?:js|ts|mjs|cjs|mts|cts)):(\d+):\d+",
            r"([^\s(]+\.(?:js|ts|mjs|cjs|mts|cts)):(\d+):\d+",
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, stack):
                file_str = match.group(1)
                # Skip node_modules paths
                if "node_modules" in file_str:
                    continue
                line_num = int(match.group(2))
                file_path = Path(file_str)
                if not file_path.is_absolute():
                    file_path = project_root / file_path
                return file_path, line_num

        return None, None

    def _truncate(self, text: str, max_length: int) -> str:
        """Truncate text to max length.

        Args:
            text: Text to truncate.
            max_length: Maximum length.

        Returns:
            Truncated text.
        """
        text = text.replace("\n", " ").strip()
        if len(text) <= max_length:
            return text
        return text[: max_length - 3] + "..."

    def _generate_issue_id(self, full_title: str, message: str) -> str:
        """Generate deterministic issue ID.

        Args:
            full_title: Full test title with suite hierarchy.
            message: Failure message.

        Returns:
            Unique issue ID.
        """
        content = f"{full_title}:{message[:100]}"
        hash_val = hashlib.sha256(content.encode()).hexdigest()[:12]
        return f"mocha-{hash_val}"
