"""Unit tests for Playwright runner plugin."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from lucidscan.core.models import ToolDomain
from lucidscan.plugins.test_runners.playwright import PlaywrightRunner


class TestPlaywrightRunner:
    """Tests for PlaywrightRunner class."""

    def test_name(self) -> None:
        """Test plugin name."""
        runner = PlaywrightRunner()
        assert runner.name == "playwright"

    def test_languages(self) -> None:
        """Test supported languages."""
        runner = PlaywrightRunner()
        assert runner.languages == ["javascript", "typescript"]

    def test_domain(self) -> None:
        """Test domain is TESTING."""
        runner = PlaywrightRunner()
        assert runner.domain == ToolDomain.TESTING


class TestPlaywrightRunnerBinaryFinding:
    """Tests for binary finding logic."""

    def test_find_in_node_modules(self) -> None:
        """Test finding playwright in project node_modules."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            node_bin = project_root / "node_modules" / ".bin"
            node_bin.mkdir(parents=True)
            playwright_bin = node_bin / "playwright"
            playwright_bin.touch()
            playwright_bin.chmod(0o755)

            runner = PlaywrightRunner(project_root=project_root)
            binary = runner.ensure_binary()

            assert binary == playwright_bin

    @patch("shutil.which")
    def test_find_in_system_path(self, mock_which: MagicMock) -> None:
        """Test finding playwright in system PATH."""
        mock_which.return_value = "/usr/local/bin/playwright"

        runner = PlaywrightRunner()
        binary = runner.ensure_binary()

        assert binary == Path("/usr/local/bin/playwright")

    @patch("shutil.which")
    def test_not_found_raises_error(self, mock_which: MagicMock) -> None:
        """Test FileNotFoundError when playwright not found."""
        mock_which.return_value = None

        runner = PlaywrightRunner()
        with pytest.raises(FileNotFoundError) as exc:
            runner.ensure_binary()

        assert "Playwright is not installed" in str(exc.value)


class TestPlaywrightReportProcessing:
    """Tests for Playwright report processing."""

    def test_process_report_with_failures(self) -> None:
        """Test processing Playwright JSON report with failures."""
        runner = PlaywrightRunner()

        report = {
            "stats": {
                "expected": 5,
                "unexpected": 2,
                "skipped": 1,
                "flaky": 0,
                "duration": 15000,
            },
            "suites": [
                {
                    "title": "Login Page",
                    "file": "tests/login.spec.ts",
                    "specs": [
                        {
                            "title": "should display login form",
                            "file": "tests/login.spec.ts",
                            "line": 10,
                            "tests": [
                                {
                                    "status": "expected",
                                    "projectName": "chromium",
                                    "results": [],
                                },
                            ],
                        },
                        {
                            "title": "should show error on invalid credentials",
                            "file": "tests/login.spec.ts",
                            "line": 25,
                            "tests": [
                                {
                                    "status": "unexpected",
                                    "projectName": "chromium",
                                    "results": [
                                        {
                                            "status": "unexpected",
                                            "error": {
                                                "message": "Expected element to be visible",
                                                "stack": "Error: Expected element to be visible\n    at tests/login.spec.ts:30:5",
                                            },
                                        },
                                    ],
                                },
                            ],
                        },
                    ],
                    "suites": [],
                },
            ],
        }

        project_root = Path("/project")
        result = runner._process_report(report, project_root)

        assert result.passed == 5
        assert result.failed == 2
        assert result.skipped == 1
        assert result.duration_ms == 15000
        assert len(result.issues) == 1

        issue = result.issues[0]
        assert "should show error on invalid credentials" in issue.title
        assert issue.source_tool == "playwright"

    def test_process_report_all_passed(self) -> None:
        """Test processing Playwright report with all tests passed."""
        runner = PlaywrightRunner()

        report = {
            "stats": {
                "expected": 10,
                "unexpected": 0,
                "skipped": 0,
                "flaky": 0,
                "duration": 5000,
            },
            "suites": [],
        }

        project_root = Path("/project")
        result = runner._process_report(report, project_root)

        assert result.passed == 10
        assert result.failed == 0
        assert result.success is True
        assert len(result.issues) == 0

    def test_process_report_with_flaky_tests(self) -> None:
        """Test that flaky tests are counted as passed."""
        runner = PlaywrightRunner()

        report = {
            "stats": {
                "expected": 8,
                "unexpected": 0,
                "skipped": 0,
                "flaky": 2,
                "duration": 10000,
            },
            "suites": [],
        }

        project_root = Path("/project")
        result = runner._process_report(report, project_root)

        assert result.passed == 10  # 8 expected + 2 flaky
        assert result.failed == 0


class TestPlaywrightNestedSuites:
    """Tests for nested suite processing."""

    def test_process_nested_suites(self) -> None:
        """Test processing nested test suites."""
        runner = PlaywrightRunner()

        report = {
            "stats": {
                "expected": 0,
                "unexpected": 1,
                "skipped": 0,
                "flaky": 0,
            },
            "suites": [
                {
                    "title": "E2E Tests",
                    "suites": [
                        {
                            "title": "Authentication",
                            "specs": [
                                {
                                    "title": "should logout user",
                                    "tests": [
                                        {
                                            "status": "unexpected",
                                            "projectName": "firefox",
                                            "results": [
                                                {
                                                    "status": "unexpected",
                                                    "error": {
                                                        "message": "Timeout exceeded",
                                                    },
                                                },
                                            ],
                                        },
                                    ],
                                },
                            ],
                            "suites": [],
                        },
                    ],
                    "specs": [],
                },
            ],
        }

        project_root = Path("/project")
        result = runner._process_report(report, project_root)

        assert len(result.issues) == 1
        issue = result.issues[0]
        # Should include full ancestor path
        assert "Authentication" in issue.title or "E2E Tests" in issue.title
        assert "should logout user" in issue.title


class TestPlaywrightLocationExtraction:
    """Tests for extracting file location from stack traces."""

    def test_extract_spec_ts_location(self) -> None:
        """Test extracting location from .spec.ts file."""
        runner = PlaywrightRunner()

        stack = """
Error: Expected element to be visible
    at tests/e2e/login.spec.ts:42:15
    at Object.<anonymous>
        """

        file_path, line = runner._extract_location(stack, Path("/project"))

        assert file_path == Path("/project/tests/e2e/login.spec.ts")
        assert line == 42

    def test_extract_test_ts_location(self) -> None:
        """Test extracting location from .test.ts file."""
        runner = PlaywrightRunner()

        stack = """
Error: Timeout
    at /project/tests/app.test.ts:10:5
        """

        file_path, line = runner._extract_location(stack, Path("/project"))

        assert file_path == Path("/project/tests/app.test.ts")
        assert line == 10

    def test_no_location_returns_none(self) -> None:
        """Test returns None when no location found."""
        runner = PlaywrightRunner()

        stack = "Some error without file location"

        file_path, line = runner._extract_location(stack, Path("/project"))

        assert file_path is None
        assert line is None


class TestPlaywrightTruncation:
    """Tests for text truncation."""

    def test_truncate_short_text(self) -> None:
        """Test that short text is not truncated."""
        runner = PlaywrightRunner()

        text = "Short error"
        result = runner._truncate(text, 50)

        assert result == "Short error"

    def test_truncate_long_text(self) -> None:
        """Test that long text is truncated."""
        runner = PlaywrightRunner()

        text = "A" * 100
        result = runner._truncate(text, 50)

        assert len(result) == 50
        assert result.endswith("...")

    def test_truncate_empty_text(self) -> None:
        """Test that empty text returns default."""
        runner = PlaywrightRunner()

        result = runner._truncate("", 50)

        assert result == "Test failed"


class TestPlaywrightIssueIdGeneration:
    """Tests for deterministic issue ID generation."""

    def test_same_input_same_id(self) -> None:
        """Test same input produces same ID."""
        runner = PlaywrightRunner()

        id1 = runner._generate_issue_id("Suite > should work", "Expected true")
        id2 = runner._generate_issue_id("Suite > should work", "Expected true")

        assert id1 == id2

    def test_different_input_different_id(self) -> None:
        """Test different input produces different ID."""
        runner = PlaywrightRunner()

        id1 = runner._generate_issue_id("Suite > should work", "Expected 1")
        id2 = runner._generate_issue_id("Suite > should fail", "Expected 2")

        assert id1 != id2

    def test_id_format(self) -> None:
        """Test ID format starts with playwright-."""
        runner = PlaywrightRunner()

        issue_id = runner._generate_issue_id("Suite > should work", "expect")

        assert issue_id.startswith("playwright-")
        assert len(issue_id) == len("playwright-") + 12  # 12 char hash

    def test_id_with_empty_message(self) -> None:
        """Test ID generation with empty message."""
        runner = PlaywrightRunner()

        issue_id = runner._generate_issue_id("Suite > should work", "")

        assert issue_id.startswith("playwright-")
