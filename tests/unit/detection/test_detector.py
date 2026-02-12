"""Unit tests for codebase detector."""

from __future__ import annotations

import tempfile
from pathlib import Path

from lucidshark.detection.detector import CodebaseDetector, ProjectContext
from lucidshark.detection.languages import LanguageInfo


class TestProjectContext:
    """Tests for ProjectContext dataclass."""

    def test_primary_language_returns_none_when_empty(self) -> None:
        """Test primary_language returns None when no languages detected."""
        context = ProjectContext(root=Path("/tmp"))

        assert context.primary_language is None

    def test_primary_language_returns_highest_file_count(self) -> None:
        """Test primary_language returns language with most files."""
        context = ProjectContext(
            root=Path("/tmp"),
            languages=[
                LanguageInfo(name="python", file_count=100),
                LanguageInfo(name="javascript", file_count=50),
            ],
        )

        assert context.primary_language == "python"

    def test_has_go_property(self) -> None:
        """Test has_go property."""
        context_with_go = ProjectContext(
            root=Path("/tmp"),
            languages=[LanguageInfo(name="go", file_count=10)],
        )
        context_without_go = ProjectContext(
            root=Path("/tmp"),
            languages=[LanguageInfo(name="python", file_count=10)],
        )

        assert context_with_go.has_go is True
        assert context_without_go.has_go is False

    def test_has_java_property(self) -> None:
        """Test has_java property."""
        context = ProjectContext(
            root=Path("/tmp"),
            languages=[LanguageInfo(name="java", file_count=10)],
        )

        assert context.has_java is True

    def test_has_kotlin_property(self) -> None:
        """Test has_kotlin property."""
        context = ProjectContext(
            root=Path("/tmp"),
            languages=[LanguageInfo(name="kotlin", file_count=10)],
        )

        assert context.has_kotlin is True


class TestCodebaseDetector:
    """Tests for CodebaseDetector class."""

    def test_detect_pipenv_project(self) -> None:
        """Test detection of Pipenv package manager."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            (project_root / "Pipfile").touch()
            (project_root / "app.py").touch()

            detector = CodebaseDetector()
            context = detector.detect(project_root)

            assert "pipenv" in context.package_managers

    def test_detect_poetry_project(self) -> None:
        """Test detection of Poetry package manager."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            (project_root / "poetry.lock").touch()
            (project_root / "app.py").touch()

            detector = CodebaseDetector()
            context = detector.detect(project_root)

            assert "poetry" in context.package_managers

    def test_detect_yarn_project(self) -> None:
        """Test detection of Yarn package manager."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            (project_root / "yarn.lock").touch()
            (project_root / "index.js").touch()

            detector = CodebaseDetector()
            context = detector.detect(project_root)

            assert "yarn" in context.package_managers

    def test_detect_pnpm_project(self) -> None:
        """Test detection of pnpm package manager."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            (project_root / "pnpm-lock.yaml").touch()
            (project_root / "index.js").touch()

            detector = CodebaseDetector()
            context = detector.detect(project_root)

            assert "pnpm" in context.package_managers

    def test_detect_go_modules(self) -> None:
        """Test detection of Go modules."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            (project_root / "go.mod").write_text("module example.com/test")
            (project_root / "main.go").write_text("package main")

            detector = CodebaseDetector()
            context = detector.detect(project_root)

            assert "go" in context.package_managers

    def test_detect_cargo_project(self) -> None:
        """Test detection of Cargo (Rust) package manager."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            (project_root / "Cargo.toml").write_text('[package]\nname = "test"')
            (project_root / "src").mkdir()
            (project_root / "src" / "main.rs").touch()

            detector = CodebaseDetector()
            context = detector.detect(project_root)

            assert "cargo" in context.package_managers

    def test_detect_maven_project(self) -> None:
        """Test detection of Maven (Java) build tool."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            (project_root / "pom.xml").write_text("<project></project>")
            (project_root / "src" / "main" / "java").mkdir(parents=True)
            (project_root / "src" / "main" / "java" / "App.java").touch()

            detector = CodebaseDetector()
            context = detector.detect(project_root)

            assert "maven" in context.package_managers

    def test_detect_gradle_project(self) -> None:
        """Test detection of Gradle (Java/Kotlin) build tool."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            (project_root / "build.gradle").write_text("apply plugin: 'java'")
            (project_root / "src" / "main" / "java").mkdir(parents=True)
            (project_root / "src" / "main" / "java" / "App.java").touch()

            detector = CodebaseDetector()
            context = detector.detect(project_root)

            assert "gradle" in context.package_managers

    def test_detect_gradle_kotlin_dsl(self) -> None:
        """Test detection of Gradle with Kotlin DSL."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            (project_root / "build.gradle.kts").write_text("plugins { }")
            (project_root / "src" / "main" / "kotlin").mkdir(parents=True)
            (project_root / "src" / "main" / "kotlin" / "App.kt").touch()

            detector = CodebaseDetector()
            context = detector.detect(project_root)

            assert "gradle" in context.package_managers
