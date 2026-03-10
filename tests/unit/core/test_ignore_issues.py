"""Tests for lucidshark.core.ignore_issues."""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path
from typing import Optional

from lucidshark.config.models import IgnoreIssueEntry
from lucidshark.core.ignore_issues import apply_ignore_issues
from lucidshark.core.models import Severity, ToolDomain, UnifiedIssue


def _make_issue(
    rule_id: str = "TEST001",
    domain=ToolDomain.LINTING,
    severity=Severity.MEDIUM,
    file_path: Optional[Path] = None,
) -> UnifiedIssue:
    return UnifiedIssue(
        id=f"test-{rule_id}",
        domain=domain,
        source_tool="test",
        severity=severity,
        rule_id=rule_id,
        title=f"Issue {rule_id}",
        description=f"Description for {rule_id}",
        file_path=file_path,
    )


class TestApplyIgnoreIssuesBasic:
    """Basic matching behavior."""

    def test_matching_rule_id_marks_ignored(self) -> None:
        issues = [_make_issue("E501")]
        entries = [IgnoreIssueEntry(rule_id="E501")]

        warnings = apply_ignore_issues(issues, entries)

        assert issues[0].ignored is True
        assert warnings == []

    def test_non_matching_rule_id_not_ignored(self) -> None:
        issues = [_make_issue("E501")]
        entries = [IgnoreIssueEntry(rule_id="E502")]

        apply_ignore_issues(issues, entries)

        assert issues[0].ignored is False

    def test_reason_is_set(self) -> None:
        issues = [_make_issue("CVE-2021-1234")]
        entries = [
            IgnoreIssueEntry(
                rule_id="CVE-2021-1234",
                reason="Accepted risk per security review",
            )
        ]

        apply_ignore_issues(issues, entries)

        assert issues[0].ignored is True
        assert issues[0].ignore_reason == "Accepted risk per security review"

    def test_no_reason_leaves_none(self) -> None:
        issues = [_make_issue("E501")]
        entries = [IgnoreIssueEntry(rule_id="E501")]

        apply_ignore_issues(issues, entries)

        assert issues[0].ignore_reason is None

    def test_empty_entries_no_changes(self) -> None:
        issues = [_make_issue("E501")]

        warnings = apply_ignore_issues(issues, [])

        assert issues[0].ignored is False
        assert warnings == []

    def test_empty_issues_no_warnings_for_unmatched(self) -> None:
        """No issues means entries don't match -> warnings."""
        entries = [IgnoreIssueEntry(rule_id="E501")]

        warnings = apply_ignore_issues([], entries)

        assert len(warnings) == 1
        assert "did not match" in warnings[0]


class TestApplyIgnoreIssuesMultiple:
    """Multiple entries and issues."""

    def test_multiple_issues_same_rule(self) -> None:
        issues = [_make_issue("E501"), _make_issue("E501")]
        entries = [IgnoreIssueEntry(rule_id="E501")]

        warnings = apply_ignore_issues(issues, entries)

        assert all(i.ignored for i in issues)
        assert warnings == []

    def test_multiple_entries_different_rules(self) -> None:
        issues = [
            _make_issue("E501"),
            _make_issue("CVE-2021-1234"),
            _make_issue("W503"),
        ]
        entries = [
            IgnoreIssueEntry(rule_id="E501"),
            IgnoreIssueEntry(rule_id="CVE-2021-1234", reason="accepted"),
        ]

        warnings = apply_ignore_issues(issues, entries)

        assert issues[0].ignored is True
        assert issues[1].ignored is True
        assert issues[1].ignore_reason == "accepted"
        assert issues[2].ignored is False
        assert warnings == []

    def test_mixed_simple_and_structured_entries(self) -> None:
        issues = [_make_issue("E501"), _make_issue("W503")]
        entries = [
            IgnoreIssueEntry(rule_id="E501"),  # simple
            IgnoreIssueEntry(rule_id="W503", reason="known issue"),  # structured
        ]

        apply_ignore_issues(issues, entries)

        assert issues[0].ignored is True
        assert issues[0].ignore_reason is None
        assert issues[1].ignored is True
        assert issues[1].ignore_reason == "known issue"


class TestApplyIgnoreIssuesExpiry:
    """Expiry date handling."""

    def test_expired_entry_does_not_suppress(self) -> None:
        issues = [_make_issue("E501")]
        yesterday = (date.today() - timedelta(days=1)).isoformat()
        entries = [IgnoreIssueEntry(rule_id="E501", expires=yesterday)]

        warnings = apply_ignore_issues(issues, entries)

        assert issues[0].ignored is False
        assert len(warnings) == 1
        assert "expired" in warnings[0]

    def test_future_expiry_still_suppresses(self) -> None:
        issues = [_make_issue("E501")]
        tomorrow = (date.today() + timedelta(days=1)).isoformat()
        entries = [IgnoreIssueEntry(rule_id="E501", expires=tomorrow)]

        warnings = apply_ignore_issues(issues, entries)

        assert issues[0].ignored is True
        # No expiry warning, but possible unmatched warning won't fire
        assert not any("expired" in w for w in warnings)

    def test_today_expiry_still_suppresses(self) -> None:
        """Expiry date == today means it hasn't expired yet."""
        issues = [_make_issue("E501")]
        today = date.today().isoformat()
        entries = [IgnoreIssueEntry(rule_id="E501", expires=today)]

        apply_ignore_issues(issues, entries)

        assert issues[0].ignored is True

    def test_invalid_expires_format_warns_but_still_applies(self) -> None:
        issues = [_make_issue("E501")]
        entries = [IgnoreIssueEntry(rule_id="E501", expires="not-a-date")]

        warnings = apply_ignore_issues(issues, entries)

        # Invalid date -> warning about format, but entry is still active
        assert issues[0].ignored is True
        assert len(warnings) == 1
        assert "invalid" in warnings[0].lower()


class TestApplyIgnoreIssuesUnmatched:
    """Unmatched entry warnings."""

    def test_unmatched_entry_produces_warning(self) -> None:
        issues = [_make_issue("E501")]
        entries = [
            IgnoreIssueEntry(rule_id="E501"),
            IgnoreIssueEntry(rule_id="NONEXISTENT"),
        ]

        warnings = apply_ignore_issues(issues, entries)

        assert len(warnings) == 1
        assert "NONEXISTENT" in warnings[0]
        assert "did not match" in warnings[0]

    def test_all_matched_no_warning(self) -> None:
        issues = [_make_issue("E501"), _make_issue("W503")]
        entries = [
            IgnoreIssueEntry(rule_id="E501"),
            IgnoreIssueEntry(rule_id="W503"),
        ]

        warnings = apply_ignore_issues(issues, entries)

        assert warnings == []


class TestApplyIgnoreIssuesPaths:
    """Path-scoped ignore behavior."""

    def test_paths_filter_matches_file(self, tmp_path: Path) -> None:
        """Issue in matching path is ignored."""
        issues = [_make_issue("S101", file_path=tmp_path / "tests" / "test_foo.py")]
        entries = [IgnoreIssueEntry(rule_id="S101", paths=["tests/**"])]

        warnings = apply_ignore_issues(issues, entries, project_root=tmp_path)

        assert issues[0].ignored is True
        assert warnings == []

    def test_paths_filter_does_not_match(self, tmp_path: Path) -> None:
        """Issue in non-matching path is NOT ignored."""
        issues = [_make_issue("S101", file_path=tmp_path / "src" / "main.py")]
        entries = [IgnoreIssueEntry(rule_id="S101", paths=["tests/**"])]

        warnings = apply_ignore_issues(issues, entries, project_root=tmp_path)

        assert issues[0].ignored is False
        # Entry doesn't match any issues
        assert len(warnings) == 1
        assert "did not match" in warnings[0]

    def test_paths_empty_list_is_global(self, tmp_path: Path) -> None:
        """Empty paths list means global ignore (backward compat)."""
        issues = [_make_issue("E501", file_path=tmp_path / "src" / "main.py")]
        entries = [IgnoreIssueEntry(rule_id="E501", paths=[])]

        warnings = apply_ignore_issues(issues, entries, project_root=tmp_path)

        # Empty list = no filtering = global
        assert issues[0].ignored is True
        assert warnings == []

    def test_paths_none_is_global(self, tmp_path: Path) -> None:
        """No paths = global ignore (backward compat)."""
        issues = [_make_issue("E501", file_path=tmp_path / "anywhere" / "file.py")]
        entries = [IgnoreIssueEntry(rule_id="E501", paths=None)]

        warnings = apply_ignore_issues(issues, entries, project_root=tmp_path)

        assert issues[0].ignored is True
        assert warnings == []

    def test_paths_with_no_file_path(self, tmp_path: Path) -> None:
        """Issue without file_path is NOT ignored when paths are specified."""
        issues = [_make_issue("CVE-2024-1234", file_path=None)]
        entries = [IgnoreIssueEntry(rule_id="CVE-2024-1234", paths=["**/*"])]

        apply_ignore_issues(issues, entries, project_root=tmp_path)

        # Issue has no file_path, so can't match path filter
        assert issues[0].ignored is False

    def test_paths_multiple_patterns(self, tmp_path: Path) -> None:
        """Multiple patterns - matches any."""
        issues = [
            _make_issue("S101", file_path=tmp_path / "tests" / "test_a.py"),
            _make_issue("S101", file_path=tmp_path / "scripts" / "dev.py"),
            _make_issue("S101", file_path=tmp_path / "src" / "main.py"),
        ]
        entries = [IgnoreIssueEntry(rule_id="S101", paths=["tests/**", "scripts/**"])]

        apply_ignore_issues(issues, entries, project_root=tmp_path)

        assert issues[0].ignored is True  # tests/test_a.py matches tests/**
        assert issues[1].ignored is True  # scripts/dev.py matches scripts/**
        assert issues[2].ignored is False  # src/main.py doesn't match

    def test_paths_recursive_glob(self, tmp_path: Path) -> None:
        """Pattern like tests/** matches nested files."""
        issues = [
            _make_issue(
                "S101", file_path=tmp_path / "tests" / "unit" / "deep" / "test.py"
            ),
        ]
        entries = [IgnoreIssueEntry(rule_id="S101", paths=["tests/**"])]

        apply_ignore_issues(issues, entries, project_root=tmp_path)

        assert issues[0].ignored is True

    def test_paths_with_expiry(self, tmp_path: Path) -> None:
        """Both expires and paths constraints apply."""
        issues = [_make_issue("E501", file_path=tmp_path / "tests" / "test.py")]
        tomorrow = (date.today() + timedelta(days=1)).isoformat()
        entries = [
            IgnoreIssueEntry(rule_id="E501", paths=["tests/**"], expires=tomorrow)
        ]

        apply_ignore_issues(issues, entries, project_root=tmp_path)

        assert issues[0].ignored is True

    def test_paths_with_expired_entry(self, tmp_path: Path) -> None:
        """Expired entry doesn't suppress even if path matches."""
        issues = [_make_issue("E501", file_path=tmp_path / "tests" / "test.py")]
        yesterday = (date.today() - timedelta(days=1)).isoformat()
        entries = [
            IgnoreIssueEntry(rule_id="E501", paths=["tests/**"], expires=yesterday)
        ]

        warnings = apply_ignore_issues(issues, entries, project_root=tmp_path)

        assert issues[0].ignored is False
        assert any("expired" in w for w in warnings)

    def test_paths_wildcard_extension(self, tmp_path: Path) -> None:
        """Pattern like **/test_*.py works."""
        issues = [
            _make_issue("S101", file_path=tmp_path / "src" / "test_utils.py"),
            _make_issue("S101", file_path=tmp_path / "src" / "utils.py"),
        ]
        entries = [IgnoreIssueEntry(rule_id="S101", paths=["**/test_*.py"])]

        apply_ignore_issues(issues, entries, project_root=tmp_path)

        assert issues[0].ignored is True  # test_utils.py matches
        assert issues[1].ignored is False  # utils.py doesn't match

    def test_paths_absolute_file_path(self, tmp_path: Path) -> None:
        """Issue with absolute file path should match correctly."""
        abs_path = (tmp_path / "tests" / "test_foo.py").resolve()
        issues = [_make_issue("S101", file_path=abs_path)]
        entries = [IgnoreIssueEntry(rule_id="S101", paths=["tests/**"])]

        apply_ignore_issues(issues, entries, project_root=tmp_path)

        assert issues[0].ignored is True

    def test_paths_relative_file_path(self, tmp_path: Path) -> None:
        """Issue with relative file path (not rooted at project) still works."""
        # Path that's already relative - common for some scanners
        issues = [_make_issue("S101", file_path=Path("tests/test_foo.py"))]
        entries = [IgnoreIssueEntry(rule_id="S101", paths=["tests/**"])]

        apply_ignore_issues(issues, entries, project_root=tmp_path)

        assert issues[0].ignored is True

    def test_paths_outside_project_root(self, tmp_path: Path) -> None:
        """Issue with path outside project root uses path as-is for matching."""
        # Path that's not under project root - exercises ValueError catch
        external_path = Path("/some/other/location/test.py")
        issues = [_make_issue("S101", file_path=external_path)]
        entries = [IgnoreIssueEntry(rule_id="S101", paths=["**/test.py"])]

        apply_ignore_issues(issues, entries, project_root=tmp_path)

        # Should still try to match using the original path
        assert issues[0].ignored is True

    def test_paths_single_file_exact_match(self, tmp_path: Path) -> None:
        """Exact file path pattern matches only that file."""
        issues = [
            _make_issue("S101", file_path=tmp_path / "src" / "specific.py"),
            _make_issue("S101", file_path=tmp_path / "src" / "other.py"),
        ]
        entries = [IgnoreIssueEntry(rule_id="S101", paths=["src/specific.py"])]

        apply_ignore_issues(issues, entries, project_root=tmp_path)

        assert issues[0].ignored is True  # specific.py matches
        assert issues[1].ignored is False  # other.py doesn't match

    def test_paths_no_project_root_uses_cwd(self, tmp_path: Path, monkeypatch) -> None:
        """When project_root is None, cwd is used."""
        monkeypatch.chdir(tmp_path)
        issues = [_make_issue("S101", file_path=tmp_path / "tests" / "test.py")]
        entries = [IgnoreIssueEntry(rule_id="S101", paths=["tests/**"])]

        # Don't pass project_root - should use cwd
        warnings = apply_ignore_issues(issues, entries, project_root=None)

        assert issues[0].ignored is True
        assert warnings == []

    def test_paths_negation_pattern(self, tmp_path: Path) -> None:
        """Negation patterns (!) work with gitignore-style pathspec."""
        issues = [
            _make_issue("S101", file_path=tmp_path / "tests" / "test_fast.py"),
            _make_issue("S101", file_path=tmp_path / "tests" / "test_slow.py"),
        ]
        # Match all tests except slow ones using negation
        entries = [
            IgnoreIssueEntry(rule_id="S101", paths=["tests/**", "!tests/test_slow.py"])
        ]

        apply_ignore_issues(issues, entries, project_root=tmp_path)

        assert issues[0].ignored is True  # test_fast.py matches
        assert issues[1].ignored is False  # test_slow.py excluded by negation
