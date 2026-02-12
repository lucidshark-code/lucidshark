"""Unit tests for SpotBugs type checker plugin."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from lucidshark.core.models import Severity, ToolDomain
from lucidshark.plugins.type_checkers.spotbugs import SpotBugsChecker


class TestSpotBugsChecker:
    """Tests for SpotBugsChecker class."""

    def test_name(self) -> None:
        """Test plugin name."""
        checker = SpotBugsChecker()
        assert checker.name == "spotbugs"

    def test_languages(self) -> None:
        """Test supported languages."""
        checker = SpotBugsChecker()
        assert checker.languages == ["java"]

    def test_domain(self) -> None:
        """Test domain is TYPE_CHECKING."""
        checker = SpotBugsChecker()
        assert checker.domain == ToolDomain.TYPE_CHECKING

    def test_supports_strict_mode(self) -> None:
        """Test strict mode support."""
        checker = SpotBugsChecker()
        assert checker.supports_strict_mode is True


class TestSpotBugsJavaDetection:
    """Tests for Java detection logic."""

    @patch("shutil.which")
    def test_check_java_available(self, mock_which) -> None:
        """Test Java detection when available."""
        mock_which.return_value = "/usr/bin/java"
        checker = SpotBugsChecker()
        java_path = checker._check_java_available()
        assert java_path == Path("/usr/bin/java")

    @patch("shutil.which")
    def test_check_java_not_available(self, mock_which) -> None:
        """Test Java detection when not available."""
        mock_which.return_value = None
        checker = SpotBugsChecker()
        java_path = checker._check_java_available()
        assert java_path is None

    @patch("shutil.which")
    def test_ensure_binary_no_java_raises(self, mock_which) -> None:
        """Test ensure_binary raises when Java not available."""
        mock_which.return_value = None
        checker = SpotBugsChecker()

        with pytest.raises(FileNotFoundError) as exc:
            checker.ensure_binary()

        assert "Java is not installed" in str(exc.value)


class TestSpotBugsClassDirectoryFinding:
    """Tests for finding compiled class directories."""

    def test_find_maven_class_directories(self) -> None:
        """Test finding Maven target/classes directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            target_classes = project_root / "target" / "classes"
            target_classes.mkdir(parents=True)

            checker = SpotBugsChecker()
            class_dirs = checker._find_class_directories(project_root)

            assert target_classes in class_dirs

    def test_find_gradle_class_directories(self) -> None:
        """Test finding Gradle build/classes directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            build_classes = project_root / "build" / "classes" / "java" / "main"
            build_classes.mkdir(parents=True)

            checker = SpotBugsChecker()
            class_dirs = checker._find_class_directories(project_root)

            assert build_classes in class_dirs

    def test_find_multi_module_class_directories(self) -> None:
        """Test finding class directories in multi-module project."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            module_classes = project_root / "module-a" / "target" / "classes"
            module_classes.mkdir(parents=True)

            checker = SpotBugsChecker()
            class_dirs = checker._find_class_directories(project_root)

            assert module_classes in class_dirs

    def test_no_class_directories(self) -> None:
        """Test empty list when no class directories found."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)

            checker = SpotBugsChecker()
            class_dirs = checker._find_class_directories(project_root)

            assert class_dirs == []


class TestSpotBugsSourceDirectoryFinding:
    """Tests for finding source directories."""

    def test_find_standard_source_directory(self) -> None:
        """Test finding src/main/java directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            src_main_java = project_root / "src" / "main" / "java"
            src_main_java.mkdir(parents=True)

            checker = SpotBugsChecker()
            source_dirs = checker._find_source_directories(project_root)

            assert src_main_java in source_dirs


class TestSpotBugsXmlParsing:
    """Tests for SpotBugs XML output parsing."""

    def test_parse_xml_with_bugs(self) -> None:
        """Test parsing SpotBugs XML output with bugs."""
        checker = SpotBugsChecker()

        xml_output = """<?xml version="1.0" encoding="UTF-8"?>
<BugCollection version="4.8.6" timestamp="1704067200000">
    <BugInstance type="NP_NULL_ON_SOME_PATH" priority="1" rank="5" category="CORRECTNESS">
        <ShortMessage>Possible null pointer dereference</ShortMessage>
        <LongMessage>Possible null pointer dereference of user in method processUser</LongMessage>
        <SourceLine classname="com.example.UserService" start="42" end="42"
                    sourcepath="com/example/UserService.java"/>
    </BugInstance>
    <BugInstance type="DM_STRING_VOID_CTOR" priority="2" rank="15" category="PERFORMANCE">
        <ShortMessage>String constructor creates unnecessary object</ShortMessage>
        <LongMessage>Method creates unnecessary String object</LongMessage>
        <SourceLine classname="com.example.Utils" start="15" end="15"
                    sourcepath="com/example/Utils.java"/>
    </BugInstance>
</BugCollection>
        """

        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            src_main_java = project_root / "src" / "main" / "java"
            src_main_java.mkdir(parents=True)

            issues = checker._parse_output(xml_output, project_root, [src_main_java])

            assert len(issues) == 2

            # First issue (high priority, low rank = HIGH severity)
            issue1 = issues[0]
            assert issue1.rule_id == "NP_NULL_ON_SOME_PATH"
            assert issue1.severity == Severity.HIGH
            assert issue1.domain == ToolDomain.TYPE_CHECKING
            assert issue1.source_tool == "spotbugs"
            assert issue1.line_start == 42

            # Second issue (medium priority, high rank = MEDIUM severity)
            issue2 = issues[1]
            assert issue2.rule_id == "DM_STRING_VOID_CTOR"
            assert issue2.severity == Severity.MEDIUM

    def test_parse_xml_no_bugs(self) -> None:
        """Test parsing SpotBugs XML output with no bugs."""
        checker = SpotBugsChecker()

        xml_output = """<?xml version="1.0" encoding="UTF-8"?>
<BugCollection version="4.8.6" timestamp="1704067200000">
</BugCollection>
        """

        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            issues = checker._parse_output(xml_output, project_root, [])

            assert len(issues) == 0

    def test_parse_empty_output(self) -> None:
        """Test parsing empty output."""
        checker = SpotBugsChecker()
        issues = checker._parse_output("", Path("/tmp"), [])
        assert len(issues) == 0

    def test_parse_no_xml_in_output(self) -> None:
        """Test parsing output without XML."""
        checker = SpotBugsChecker()
        issues = checker._parse_output("Some text without XML", Path("/tmp"), [])
        assert len(issues) == 0


class TestSpotBugsSeverityMapping:
    """Tests for priority/rank to severity mapping."""

    def test_priority_1_high_severity(self) -> None:
        """Test priority 1 maps to HIGH severity."""
        checker = SpotBugsChecker()

        xml_output = """<?xml version="1.0" encoding="UTF-8"?>
<BugCollection>
    <BugInstance type="TEST" priority="1" rank="10" category="CORRECTNESS">
        <LongMessage>Test message</LongMessage>
    </BugInstance>
</BugCollection>
        """

        issues = checker._parse_output(xml_output, Path("/tmp"), [])
        assert issues[0].severity == Severity.HIGH

    def test_priority_2_medium_severity(self) -> None:
        """Test priority 2 maps to MEDIUM severity."""
        checker = SpotBugsChecker()

        xml_output = """<?xml version="1.0" encoding="UTF-8"?>
<BugCollection>
    <BugInstance type="TEST" priority="2" rank="15" category="PERFORMANCE">
        <LongMessage>Test message</LongMessage>
    </BugInstance>
</BugCollection>
        """

        issues = checker._parse_output(xml_output, Path("/tmp"), [])
        assert issues[0].severity == Severity.MEDIUM

    def test_priority_3_low_severity(self) -> None:
        """Test priority 3 maps to LOW severity."""
        checker = SpotBugsChecker()

        xml_output = """<?xml version="1.0" encoding="UTF-8"?>
<BugCollection>
    <BugInstance type="TEST" priority="3" rank="18" category="STYLE">
        <LongMessage>Test message</LongMessage>
    </BugInstance>
</BugCollection>
        """

        issues = checker._parse_output(xml_output, Path("/tmp"), [])
        assert issues[0].severity == Severity.LOW

    def test_low_rank_upgrades_severity(self) -> None:
        """Test low rank (scary) upgrades severity to HIGH."""
        checker = SpotBugsChecker()

        # Priority 3 (LOW) but rank 3 (very scary) should upgrade to HIGH
        xml_output = """<?xml version="1.0" encoding="UTF-8"?>
<BugCollection>
    <BugInstance type="TEST" priority="3" rank="3" category="SECURITY">
        <LongMessage>Test message</LongMessage>
    </BugInstance>
</BugCollection>
        """

        issues = checker._parse_output(xml_output, Path("/tmp"), [])
        assert issues[0].severity == Severity.HIGH


class TestSpotBugsIssueIdGeneration:
    """Tests for deterministic issue ID generation."""

    def test_same_input_same_id(self) -> None:
        """Test same input produces same ID."""
        checker = SpotBugsChecker()

        id1 = checker._generate_issue_id("NP_NULL", "file.java", 42, "message")
        id2 = checker._generate_issue_id("NP_NULL", "file.java", 42, "message")

        assert id1 == id2

    def test_different_input_different_id(self) -> None:
        """Test different input produces different ID."""
        checker = SpotBugsChecker()

        id1 = checker._generate_issue_id("NP_NULL", "file.java", 42, "message")
        id2 = checker._generate_issue_id("NP_NULL", "other.java", 42, "message")

        assert id1 != id2

    def test_id_format(self) -> None:
        """Test ID format starts with spotbugs-."""
        checker = SpotBugsChecker()

        issue_id = checker._generate_issue_id("NP_NULL", "file.java", 42, "msg")

        assert issue_id.startswith("spotbugs-NP_NULL-")
