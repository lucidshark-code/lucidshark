"""Unit tests for Karma runner plugin."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from lucidscan.core.models import ToolDomain
from lucidscan.plugins.test_runners.karma import KarmaRunner


class TestKarmaRunner:
    """Tests for KarmaRunner class."""

    def test_name(self) -> None:
        """Test plugin name."""
        runner = KarmaRunner()
        assert runner.name == "karma"

    def test_languages(self) -> None:
        """Test supported languages."""
        runner = KarmaRunner()
        assert runner.languages == ["javascript", "typescript"]

    def test_domain(self) -> None:
        """Test domain is TESTING."""
        runner = KarmaRunner()
        assert runner.domain == ToolDomain.TESTING


class TestKarmaRunnerBinaryFinding:
    """Tests for binary finding logic."""

    def test_find_in_node_modules(self) -> None:
        """Test finding karma in project node_modules."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            node_bin = project_root / "node_modules" / ".bin"
            node_bin.mkdir(parents=True)
            karma_bin = node_bin / "karma"
            karma_bin.touch()
            karma_bin.chmod(0o755)

            runner = KarmaRunner(project_root=project_root)
            binary = runner.ensure_binary()

            assert binary == karma_bin

    @patch("shutil.which")
    def test_find_in_system_path(self, mock_which: MagicMock) -> None:
        """Test finding karma in system PATH."""
        mock_which.return_value = "/usr/local/bin/karma"

        runner = KarmaRunner()
        binary = runner.ensure_binary()

        assert binary == Path("/usr/local/bin/karma")

    @patch("shutil.which")
    def test_not_found_raises_error(self, mock_which: MagicMock) -> None:
        """Test FileNotFoundError when karma not found."""
        mock_which.return_value = None

        runner = KarmaRunner()
        with pytest.raises(FileNotFoundError) as exc:
            runner.ensure_binary()

        assert "Karma is not installed" in str(exc.value)


class TestKarmaConfigFinding:
    """Tests for karma config file detection."""

    def test_find_karma_conf_js(self) -> None:
        """Test finding karma.conf.js."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            karma_conf = project_root / "karma.conf.js"
            karma_conf.touch()

            runner = KarmaRunner(project_root=project_root)
            config = runner._find_karma_config(project_root)

            assert config == karma_conf

    def test_find_karma_conf_ts(self) -> None:
        """Test finding karma.conf.ts."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            karma_conf = project_root / "karma.conf.ts"
            karma_conf.touch()

            runner = KarmaRunner(project_root=project_root)
            config = runner._find_karma_config(project_root)

            assert config == karma_conf

    def test_no_config_returns_none(self) -> None:
        """Test returns None when no config found."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)

            runner = KarmaRunner(project_root=project_root)
            config = runner._find_karma_config(project_root)

            assert config is None


class TestKarmaReportProcessing:
    """Tests for Karma report processing."""

    def test_process_report_with_failures(self) -> None:
        """Test processing Karma JSON report with failures."""
        runner = KarmaRunner()

        report = {
            "summary": {
                "success": 5,
                "failed": 2,
                "skipped": 1,
                "error": 0,
                "totalTime": 5000,
            },
            "browsers": {
                "Chrome": {
                    "results": [
                        {
                            "suite": ["AppComponent"],
                            "description": "should create the app",
                            "success": True,
                        },
                        {
                            "suite": ["AppComponent"],
                            "description": "should fail",
                            "success": False,
                            "log": ["Expected true to be false"],
                        },
                    ],
                },
            },
        }

        project_root = Path("/project")
        result = runner._process_report(report, project_root)

        assert result.passed == 5
        assert result.failed == 2
        assert result.skipped == 1
        assert result.duration_ms == 5000
        assert len(result.issues) == 1

        issue = result.issues[0]
        assert "should fail" in issue.title
        assert issue.source_tool == "karma"

    def test_process_report_all_passed(self) -> None:
        """Test processing Karma report with all tests passed."""
        runner = KarmaRunner()

        report = {
            "summary": {
                "success": 10,
                "failed": 0,
                "skipped": 0,
                "error": 0,
            },
            "browsers": {},
        }

        project_root = Path("/project")
        result = runner._process_report(report, project_root)

        assert result.passed == 10
        assert result.failed == 0
        assert result.success is True
        assert len(result.issues) == 0


class TestKarmaStdoutParsing:
    """Tests for Karma stdout parsing fallback."""

    def test_parse_success_output(self) -> None:
        """Test parsing successful Karma output."""
        runner = KarmaRunner()

        stdout = """
Executed 42 of 42 SUCCESS (5.234 secs / 4.123 secs)
        """

        result = runner._parse_stdout(stdout, "", Path("/project"))

        assert result.passed == 42
        assert result.failed == 0

    def test_parse_failure_output(self) -> None:
        """Test parsing Karma output with failures."""
        runner = KarmaRunner()

        stdout = """
Executed 42 of 42 (3 FAILED) (5.234 secs / 4.123 secs)
        """

        result = runner._parse_stdout(stdout, "", Path("/project"))

        assert result.passed == 39
        assert result.failed == 3

    def test_parse_skipped_output(self) -> None:
        """Test parsing Karma output with skipped tests."""
        runner = KarmaRunner()

        stdout = """
Executed 40 of 42 (2 skipped) SUCCESS
        """

        result = runner._parse_stdout(stdout, "", Path("/project"))

        assert result.passed == 40
        assert result.skipped == 2


class TestKarmaLocationExtraction:
    """Tests for extracting file location from error messages."""

    def test_extract_spec_ts_location(self) -> None:
        """Test extracting location from .spec.ts file."""
        runner = KarmaRunner()

        message = """
Error: Expected true to be false
    at Context.<anonymous> (src/app/app.component.spec.ts:42:15)
        """

        file_path, line = runner._extract_location(message, Path("/project"))

        assert file_path == Path("/project/src/app/app.component.spec.ts")
        assert line == 42

    def test_extract_test_ts_location(self) -> None:
        """Test extracting location from .test.ts file."""
        runner = KarmaRunner()

        message = """
Error: Expected 1 to equal 2
    at src/app/utils.test.ts:10:5
        """

        file_path, line = runner._extract_location(message, Path("/project"))

        assert file_path == Path("/project/src/app/utils.test.ts")
        assert line == 10

    def test_no_location_returns_none(self) -> None:
        """Test returns None when no location found."""
        runner = KarmaRunner()

        message = "Some error without file location"

        file_path, line = runner._extract_location(message, Path("/project"))

        assert file_path is None
        assert line is None


class TestKarmaIssueIdGeneration:
    """Tests for deterministic issue ID generation."""

    def test_same_input_same_id(self) -> None:
        """Test same input produces same ID."""
        runner = KarmaRunner()

        id1 = runner._generate_issue_id("Suite > should work", "Expected true")
        id2 = runner._generate_issue_id("Suite > should work", "Expected true")

        assert id1 == id2

    def test_different_input_different_id(self) -> None:
        """Test different input produces different ID."""
        runner = KarmaRunner()

        id1 = runner._generate_issue_id("Suite > should work", "Expected 1")
        id2 = runner._generate_issue_id("Suite > should fail", "Expected 2")

        assert id1 != id2

    def test_id_format(self) -> None:
        """Test ID format starts with karma-."""
        runner = KarmaRunner()

        issue_id = runner._generate_issue_id("Suite > should work", "expect")

        assert issue_id.startswith("karma-")
        assert len(issue_id) == len("karma-") + 12  # 12 char hash
