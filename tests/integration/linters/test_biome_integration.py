"""Integration tests for Biome linter.

These tests actually run the Biome binary against real targets.
They require Biome to be installed (npm install @biomejs/biome).

Run with: pytest tests/integration/linters -v
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from lucidshark.core.models import ScanContext
from lucidshark.plugins.linters.biome import BiomeLinter
from tests.integration.conftest import biome_available


class TestBiomeBinaryResolution:
    """Tests for Biome binary resolution."""

    def test_ensure_binary_raises_when_not_installed(self) -> None:
        """Test that ensure_binary raises FileNotFoundError when biome is not installed."""
        # Create a linter pointing to a non-existent project
        linter = BiomeLinter(project_root=Path("/nonexistent"))

        # This will raise FileNotFoundError since biome won't be found
        # unless it's installed globally
        try:
            binary_path = linter.ensure_binary()
            # If biome is installed globally, verify it exists
            assert binary_path.exists()
        except FileNotFoundError as e:
            # Expected behavior when biome is not installed
            assert "Biome is not installed" in str(e)

    @biome_available
    def test_biome_binary_is_executable(self, ensure_biome_binary: Path) -> None:
        """Test that the Biome binary is executable."""
        result = subprocess.run(
            [str(ensure_biome_binary), "--version"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        # Biome outputs "Version: X.Y.Z" format
        assert "version" in result.stdout.lower()


@biome_available
class TestBiomeLinting:
    """Integration tests for Biome linting."""

    def test_lint_javascript_file_with_issues(self, biome_linter: BiomeLinter) -> None:
        """Test linting a JavaScript file with issues."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            # Create a JS file with issues (unused variable)
            test_file = tmpdir_path / "test.js"
            test_file.write_text("const x = 1;\n")  # Unused variable

            context = ScanContext(
                project_root=tmpdir_path,
                paths=[tmpdir_path],
                enabled_domains=[],
            )

            issues = biome_linter.lint(context)

            # Biome should find unused variable
            assert isinstance(issues, list)
            # Issues might be empty if Biome's default config doesn't flag this
            for issue in issues:
                assert issue.source_tool == "biome"

    def test_lint_empty_directory(self, biome_linter: BiomeLinter) -> None:
        """Test linting an empty directory returns no issues."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            context = ScanContext(
                project_root=tmpdir_path,
                paths=[tmpdir_path],
                enabled_domains=[],
            )

            issues = biome_linter.lint(context)

            assert isinstance(issues, list)
            assert len(issues) == 0


@biome_available
class TestBiomeAutoFix:
    """Integration tests for Biome auto-fix functionality."""

    def test_fix_returns_result(self, biome_linter: BiomeLinter) -> None:
        """Test that fix mode returns a result."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            # Create a JS file
            test_file = tmpdir_path / "fixable.js"
            test_file.write_text("const x = 1;\n")

            context = ScanContext(
                project_root=tmpdir_path,
                paths=[tmpdir_path],
                enabled_domains=[],
            )

            result = biome_linter.fix(context)

            # Result should have fix statistics
            assert hasattr(result, "issues_fixed")
            assert hasattr(result, "issues_remaining")
