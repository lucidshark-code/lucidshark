"""Unit tests for JaCoCo coverage plugin."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from lucidshark.core.models import Severity, ToolDomain
from lucidshark.plugins.coverage.jacoco import JaCoCoPlugin


class TestJaCoCoPlugin:
    """Tests for JaCoCoPlugin class."""

    def test_name(self) -> None:
        """Test plugin name."""
        plugin = JaCoCoPlugin()
        assert plugin.name == "jacoco"

    def test_languages(self) -> None:
        """Test supported languages."""
        plugin = JaCoCoPlugin()
        assert "java" in plugin.languages
        assert "kotlin" in plugin.languages

    def test_domain(self) -> None:
        """Test domain is COVERAGE."""
        plugin = JaCoCoPlugin()
        assert plugin.domain == ToolDomain.COVERAGE


class TestJaCoCoBuildSystemDetection:
    """Tests for build system detection logic."""

    def test_detect_maven_wrapper(self) -> None:
        """Test detecting Maven wrapper (mvnw)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            mvnw = project_root / "mvnw"
            mvnw.touch()

            plugin = JaCoCoPlugin(project_root=project_root)
            binary, build_system = plugin._detect_build_system()

            assert binary == mvnw
            assert build_system == "maven"

    def test_detect_gradle_wrapper(self) -> None:
        """Test detecting Gradle wrapper (gradlew)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            gradlew = project_root / "gradlew"
            gradlew.touch()

            plugin = JaCoCoPlugin(project_root=project_root)
            binary, build_system = plugin._detect_build_system()

            assert binary == gradlew
            assert build_system == "gradle"

    def test_no_build_system_raises_error(self) -> None:
        """Test FileNotFoundError when no build system found."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)

            with patch("shutil.which") as mock_which:
                mock_which.return_value = None
                plugin = JaCoCoPlugin(project_root=project_root)

                with pytest.raises(FileNotFoundError) as exc:
                    plugin._detect_build_system()

                assert "No build system found" in str(exc.value)


class TestJaCoCoXmlParsing:
    """Tests for JaCoCo XML report parsing."""

    def test_parse_xml_report(self) -> None:
        """Test parsing JaCoCo XML report."""
        plugin = JaCoCoPlugin()

        xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN" "report.dtd">
<report name="user-service">
    <counter type="INSTRUCTION" missed="100" covered="400"/>
    <counter type="BRANCH" missed="10" covered="30"/>
    <counter type="LINE" missed="50" covered="200"/>
    <counter type="COMPLEXITY" missed="20" covered="80"/>
    <counter type="METHOD" missed="5" covered="45"/>
    <counter type="CLASS" missed="1" covered="9"/>
    <package name="com/example/service">
        <sourcefile name="UserService.java">
            <line nr="10" mi="0" ci="5" mb="0" cb="2"/>
            <line nr="15" mi="2" ci="0" mb="1" cb="0"/>
            <counter type="LINE" missed="5" covered="25"/>
        </sourcefile>
    </package>
</report>
        """

        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            report_file = project_root / "jacoco.xml"
            report_file.write_text(xml_content)

            result = plugin._parse_xml_report(report_file, project_root, threshold=80.0)

            assert result.total_lines == 250  # 50 + 200
            assert result.covered_lines == 200
            assert result.missing_lines == 50
            assert result.threshold == 80.0

            # 200/250 = 80%, should pass at 80% threshold
            assert result.percentage == 80.0
            assert result.passed is True
            assert len(result.issues) == 0

    def test_parse_xml_report_below_threshold(self) -> None:
        """Test parsing report with coverage below threshold."""
        plugin = JaCoCoPlugin()

        xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<report name="test">
    <counter type="LINE" missed="60" covered="40"/>
</report>
        """

        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            report_file = project_root / "jacoco.xml"
            report_file.write_text(xml_content)

            result = plugin._parse_xml_report(report_file, project_root, threshold=80.0)

            assert result.total_lines == 100
            assert result.covered_lines == 40
            assert result.percentage == 40.0
            assert result.passed is False
            assert len(result.issues) == 1

            issue = result.issues[0]
            assert issue.domain == ToolDomain.COVERAGE
            assert issue.source_tool == "jacoco"
            assert issue.rule_id == "coverage_below_threshold"
            assert "40.0%" in issue.title
            assert "80.0%" in issue.title

    def test_parse_xml_report_per_file_coverage(self) -> None:
        """Test parsing per-file coverage data."""
        plugin = JaCoCoPlugin()

        xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<report name="test">
    <counter type="LINE" missed="20" covered="80"/>
    <package name="com/example">
        <sourcefile name="Service.java">
            <line nr="10" mi="2" ci="0"/>
            <line nr="20" mi="0" ci="5"/>
            <counter type="LINE" missed="10" covered="40"/>
        </sourcefile>
    </package>
</report>
        """

        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            report_file = project_root / "jacoco.xml"
            report_file.write_text(xml_content)

            # Create source file
            src_dir = project_root / "src" / "main" / "java" / "com" / "example"
            src_dir.mkdir(parents=True)
            (src_dir / "Service.java").touch()

            result = plugin._parse_xml_report(report_file, project_root, threshold=80.0)

            assert len(result.files) == 1


class TestJaCoCoCoverageIssue:
    """Tests for coverage issue creation."""

    def test_create_coverage_issue_below_50(self) -> None:
        """Test HIGH severity when coverage below 50%."""
        plugin = JaCoCoPlugin()

        issue = plugin._create_coverage_issue(
            percentage=30.0,
            threshold=80.0,
            total_lines=100,
            covered_lines=30,
            missing_lines=70,
        )

        assert issue.severity == Severity.HIGH
        assert "30.0%" in issue.title
        assert "80.0%" in issue.title

    def test_create_coverage_issue_moderately_below(self) -> None:
        """Test MEDIUM severity when coverage moderately below threshold."""
        plugin = JaCoCoPlugin()

        issue = plugin._create_coverage_issue(
            percentage=60.0,
            threshold=80.0,
            total_lines=100,
            covered_lines=60,
            missing_lines=40,
        )

        assert issue.severity == Severity.MEDIUM

    def test_create_coverage_issue_slightly_below(self) -> None:
        """Test LOW severity when coverage slightly below threshold."""
        plugin = JaCoCoPlugin()

        issue = plugin._create_coverage_issue(
            percentage=75.0,
            threshold=80.0,
            total_lines=100,
            covered_lines=75,
            missing_lines=25,
        )

        assert issue.severity == Severity.LOW


class TestJaCoCoSourcePathResolution:
    """Tests for source file path resolution."""

    def test_resolve_source_path_standard(self) -> None:
        """Test resolving standard Maven/Gradle source path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            src_dir = project_root / "src" / "main" / "java" / "com" / "example"
            src_dir.mkdir(parents=True)
            (src_dir / "Service.java").touch()

            plugin = JaCoCoPlugin()
            resolved = plugin._resolve_source_path(
                project_root, "com/example", "Service.java"
            )

            assert resolved == src_dir / "Service.java"

    def test_resolve_source_path_test_directory(self) -> None:
        """Test resolving test source path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            test_dir = project_root / "src" / "test" / "java" / "com" / "example"
            test_dir.mkdir(parents=True)
            (test_dir / "ServiceTest.java").touch()

            plugin = JaCoCoPlugin()
            resolved = plugin._resolve_source_path(
                project_root, "com/example", "ServiceTest.java"
            )

            assert resolved == test_dir / "ServiceTest.java"


class TestJaCoCoTestStatsParsing:
    """Tests for parsing test statistics from build output."""

    def test_parse_maven_test_output(self) -> None:
        """Test parsing Maven test output."""
        plugin = JaCoCoPlugin()

        # The pattern sums all matches, so use unique output
        output = """
[INFO] --- maven-surefire-plugin:3.0.0:test (default-test) @ user-service ---
[INFO] Tests run: 10, Failures: 1, Errors: 0, Skipped: 2
        """

        stats = plugin._parse_maven_test_output(output)

        assert stats.total == 10
        assert stats.failed == 1
        assert stats.errors == 0
        assert stats.skipped == 2
        assert stats.passed == 7

    def test_parse_gradle_test_output(self) -> None:
        """Test parsing Gradle test output."""
        plugin = JaCoCoPlugin()

        output = """
> Task :test
10 tests completed, 2 failed, 1 skipped
        """

        stats = plugin._parse_gradle_test_output(output)

        assert stats.total == 10
        assert stats.failed == 2
        assert stats.skipped == 1
