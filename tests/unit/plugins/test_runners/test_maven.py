"""Unit tests for Maven/Gradle test runner plugin."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from lucidshark.core.models import Severity, ToolDomain
from lucidshark.plugins.test_runners.maven import MavenTestRunner


class TestMavenTestRunner:
    """Tests for MavenTestRunner class."""

    def test_name(self) -> None:
        """Test plugin name."""
        runner = MavenTestRunner()
        assert runner.name == "maven"

    def test_languages(self) -> None:
        """Test supported languages."""
        runner = MavenTestRunner()
        assert "java" in runner.languages
        assert "kotlin" in runner.languages

    def test_domain(self) -> None:
        """Test domain is TESTING."""
        runner = MavenTestRunner()
        assert runner.domain == ToolDomain.TESTING


class TestMavenBuildSystemDetection:
    """Tests for build system detection logic."""

    def test_detect_maven_wrapper(self) -> None:
        """Test detecting Maven wrapper (mvnw)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            mvnw = project_root / "mvnw"
            mvnw.touch()

            runner = MavenTestRunner(project_root=project_root)
            binary, build_system = runner._detect_build_system()

            assert binary == mvnw
            assert build_system == "maven"

    def test_detect_gradle_wrapper(self) -> None:
        """Test detecting Gradle wrapper (gradlew)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            gradlew = project_root / "gradlew"
            gradlew.touch()

            runner = MavenTestRunner(project_root=project_root)
            binary, build_system = runner._detect_build_system()

            assert binary == gradlew
            assert build_system == "gradle"

    def test_detect_pom_xml_with_mvn(self) -> None:
        """Test detecting Maven via pom.xml and mvn in PATH."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            pom_xml = project_root / "pom.xml"
            pom_xml.write_text("<project></project>")

            with patch("shutil.which") as mock_which:
                mock_which.return_value = "/usr/bin/mvn"
                runner = MavenTestRunner(project_root=project_root)
                binary, build_system = runner._detect_build_system()

                assert binary == Path("/usr/bin/mvn")
                assert build_system == "maven"

    def test_detect_build_gradle_with_gradle(self) -> None:
        """Test detecting Gradle via build.gradle and gradle in PATH."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            build_gradle = project_root / "build.gradle"
            build_gradle.write_text("// Gradle build")

            with patch("shutil.which") as mock_which:
                mock_which.return_value = "/usr/bin/gradle"
                runner = MavenTestRunner(project_root=project_root)
                binary, build_system = runner._detect_build_system()

                assert binary == Path("/usr/bin/gradle")
                assert build_system == "gradle"

    def test_no_build_system_raises_error(self) -> None:
        """Test FileNotFoundError when no build system found."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)

            with patch("shutil.which") as mock_which:
                mock_which.return_value = None
                runner = MavenTestRunner(project_root=project_root)

                with pytest.raises(FileNotFoundError) as exc:
                    runner._detect_build_system()

                assert "No build system found" in str(exc.value)


class TestMavenJunitXmlParsing:
    """Tests for JUnit XML parsing."""

    def test_parse_junit_xml_with_failures(self) -> None:
        """Test parsing JUnit XML with test failures."""
        runner = MavenTestRunner()

        junit_xml = """<?xml version="1.0" encoding="UTF-8"?>
        <testsuite name="com.example.MyTest" tests="3" failures="1" errors="0" skipped="0" time="1.5">
            <testcase classname="com.example.MyTest" name="testSuccess" time="0.1"/>
            <testcase classname="com.example.MyTest" name="testFailure" time="0.05">
                <failure type="java.lang.AssertionError" message="expected: true but was: false">
java.lang.AssertionError: expected: true but was: false
    at com.example.MyTest.testFailure(MyTest.java:25)
                </failure>
            </testcase>
            <testcase classname="com.example.MyTest" name="testAnother" time="0.02"/>
        </testsuite>
        """

        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            report_file = project_root / "junit.xml"
            report_file.write_text(junit_xml)

            result = runner._parse_junit_xml(report_file, project_root)

            assert result.passed == 2
            assert result.failed == 1
            assert result.errors == 0
            assert result.duration_ms == 1500
            assert len(result.issues) == 1

            issue = result.issues[0]
            assert "testFailure" in issue.title
            assert issue.severity == Severity.HIGH
            assert issue.domain == ToolDomain.TESTING
            assert issue.source_tool == "maven"

    def test_parse_junit_xml_all_passed(self) -> None:
        """Test parsing JUnit XML with all tests passed."""
        runner = MavenTestRunner()

        junit_xml = """<?xml version="1.0" encoding="UTF-8"?>
        <testsuite name="com.example.MyTest" tests="5" failures="0" errors="0" skipped="0" time="2.0">
            <testcase classname="com.example.MyTest" name="test1" time="0.1"/>
            <testcase classname="com.example.MyTest" name="test2" time="0.1"/>
            <testcase classname="com.example.MyTest" name="test3" time="0.1"/>
            <testcase classname="com.example.MyTest" name="test4" time="0.1"/>
            <testcase classname="com.example.MyTest" name="test5" time="0.1"/>
        </testsuite>
        """

        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            report_file = project_root / "junit.xml"
            report_file.write_text(junit_xml)

            result = runner._parse_junit_xml(report_file, project_root)

            assert result.passed == 5
            assert result.failed == 0
            assert result.success is True
            assert len(result.issues) == 0

    def test_parse_junit_xml_with_errors(self) -> None:
        """Test parsing JUnit XML with test errors."""
        runner = MavenTestRunner()

        junit_xml = """<?xml version="1.0" encoding="UTF-8"?>
        <testsuite name="com.example.MyTest" tests="2" failures="0" errors="1" skipped="0" time="0.5">
            <testcase classname="com.example.MyTest" name="testSuccess" time="0.1"/>
            <testcase classname="com.example.MyTest" name="testError" time="0.05">
                <error type="java.lang.NullPointerException" message="NPE">
java.lang.NullPointerException
    at com.example.MyTest.testError(MyTest.java:30)
                </error>
            </testcase>
        </testsuite>
        """

        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            report_file = project_root / "junit.xml"
            report_file.write_text(junit_xml)

            result = runner._parse_junit_xml(report_file, project_root)

            assert result.passed == 1
            assert result.errors == 1
            assert len(result.issues) == 1

            issue = result.issues[0]
            assert "testError" in issue.title
            assert issue.severity == Severity.MEDIUM


class TestMavenLineExtraction:
    """Tests for line number extraction from stacktrace."""

    def test_extract_line_from_stacktrace(self) -> None:
        """Test extracting line number from Java stacktrace."""
        runner = MavenTestRunner()

        stacktrace = """java.lang.AssertionError: expected: true but was: false
    at org.junit.Assert.fail(Assert.java:88)
    at com.example.service.UserServiceTest.testLogin(UserServiceTest.java:42)
    at sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
        """

        line = runner._extract_line_from_stacktrace(
            stacktrace, "com.example.service.UserServiceTest"
        )

        assert line == 42

    def test_extract_line_no_match(self) -> None:
        """Test no line number when class not in stacktrace."""
        runner = MavenTestRunner()

        stacktrace = """java.lang.NullPointerException
    at java.util.HashMap.get(HashMap.java:100)
        """

        line = runner._extract_line_from_stacktrace(
            stacktrace, "com.example.MyTest"
        )

        assert line is None


class TestMavenIssueIdGeneration:
    """Tests for deterministic issue ID generation."""

    def test_same_input_same_id(self) -> None:
        """Test same input produces same ID."""
        runner = MavenTestRunner()

        id1 = runner._generate_issue_id("com.example.Test#testFoo", "expected true")
        id2 = runner._generate_issue_id("com.example.Test#testFoo", "expected true")

        assert id1 == id2

    def test_different_input_different_id(self) -> None:
        """Test different input produces different ID."""
        runner = MavenTestRunner()

        id1 = runner._generate_issue_id("com.example.Test#testFoo", "expected true")
        id2 = runner._generate_issue_id("com.example.Test#testBar", "expected true")

        assert id1 != id2

    def test_id_format(self) -> None:
        """Test ID format starts with maven-test-."""
        runner = MavenTestRunner()

        issue_id = runner._generate_issue_id("com.example.Test#testFoo", "msg")

        assert issue_id.startswith("maven-test-")


class TestMavenResultMerging:
    """Tests for merging multiple TestResults."""

    def test_merge_results(self) -> None:
        """Test merging two TestResults."""
        from lucidshark.plugins.test_runners.base import TestResult

        runner = MavenTestRunner()

        result1 = TestResult(passed=5, failed=1, skipped=0, errors=0, duration_ms=1000)
        result2 = TestResult(passed=3, failed=2, skipped=1, errors=1, duration_ms=500)

        merged = runner._merge_results(result1, result2)

        assert merged.passed == 8
        assert merged.failed == 3
        assert merged.skipped == 1
        assert merged.errors == 1
        assert merged.duration_ms == 1500
