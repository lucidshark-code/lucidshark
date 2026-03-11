"""Summary reporter plugin for lucidshark."""

from __future__ import annotations

from typing import IO, List, Set

from lucidshark.core.models import ScanResult
from lucidshark.plugins.reporters.base import ReporterPlugin


class SummaryReporter(ReporterPlugin):
    """Reporter plugin that outputs a brief scan summary.

    Produces a concise summary with:
    - Total issue count
    - Breakdown by severity
    - Breakdown by scanner domain (all configured domains)
    - Scan duration and project info
    """

    @property
    def name(self) -> str:
        return "summary"

    def report(self, result: ScanResult, output: IO[str]) -> None:
        """Format scan result as a summary and write to output.

        Args:
            result: The scan result to format.
            output: Output stream to write to.
        """
        lines = self._format_summary(result)
        output.write("\n".join(lines))
        output.write("\n")

    def _format_summary(self, result: ScanResult) -> List[str]:
        """Format scan result as a brief summary."""
        lines: List[str] = []

        if result.summary:
            # total is active issues count, ignored_total is separately tracked
            if result.summary.ignored_total > 0:
                lines.append(
                    f"Total issues: {result.summary.total} "
                    f"({result.summary.ignored_total} ignored)"
                )
            else:
                lines.append(f"Total issues: {result.summary.total}")

            if result.summary.by_severity:
                lines.append("\nBy severity:")
                for sev in ["critical", "high", "medium", "low", "info"]:
                    count = result.summary.by_severity.get(sev, 0)
                    if count > 0:
                        lines.append(f"  {sev.upper()}: {count}")

            # Show all configured domains with their status
            lines.extend(self._format_domain_status(result))
        else:
            lines.append("All checks passed. No issues found.")

        # Coverage summary
        if result.coverage_summary:
            cs = result.coverage_summary
            status = "PASSED" if cs.passed else "FAILED"
            lines.append(f"\nCoverage: {cs.coverage_percentage:.1f}% ({status})")
            lines.append(f"  Threshold: {cs.threshold}%")
            lines.append(f"  Lines: {cs.covered_lines}/{cs.total_lines} covered")

        # Duplication summary
        if result.duplication_summary:
            ds = result.duplication_summary
            if ds.execution_failed:
                lines.append("\nDuplication: FAILED (tool crashed)")
            else:
                status = "PASSED" if ds.passed else "FAILED"
                lines.append(f"\nDuplication: {ds.duplication_percent:.1f}% ({status})")
                lines.append(f"  Threshold: {ds.threshold}%")
                lines.append(
                    f"  Blocks: {ds.duplicate_blocks}, Lines: {ds.duplicate_lines}"
                )

        # Skipped tools
        if result.tool_skips:
            lines.append("\nSkipped tools:")
            mandatory_skips = [s for s in result.tool_skips if s.mandatory]
            info_skips = [s for s in result.tool_skips if not s.mandatory]

            if mandatory_skips:
                lines.append("  MANDATORY FAILURES:")
                for skip in mandatory_skips:
                    lines.append(f"    - {skip.tool_name}: {skip.message}")
                    if skip.suggestion:
                        lines.append(f"      Fix: {skip.suggestion}")

            if info_skips:
                if mandatory_skips:
                    lines.append("  Informational:")
                for skip in info_skips:
                    lines.append(f"  - {skip.tool_name}: {skip.message}")

        if result.metadata:
            lines.append(f"\nScan duration: {result.metadata.duration_ms}ms")
            lines.append(f"Project: {result.metadata.project_root}")

        return lines

    def _format_domain_status(self, result: ScanResult) -> List[str]:
        """Format domain status showing all configured domains.

        Shows pass/fail/skipped status for each configured domain.
        """
        lines: List[str] = []

        # Get configured and executed domains from metadata
        enabled_domains: List[str] = []
        executed_domains: Set[str] = set()

        if result.metadata:
            enabled_domains = result.metadata.enabled_domains or []
            executed_domains = set(result.metadata.executed_domains or [])

        # If no metadata, fall back to showing domains with issues
        if not enabled_domains:
            if result.summary and result.summary.by_scanner:
                lines.append("\nBy domain:")
                for domain, count in result.summary.by_scanner.items():
                    lines.append(f"  {domain.upper()}: {count} issues")
            return lines

        # Build issue counts by domain
        issues_by_domain: dict[str, int] = {}
        if result.summary and result.summary.by_scanner:
            issues_by_domain = result.summary.by_scanner

        lines.append("\nBy domain:")
        for domain in enabled_domains:
            issue_count = issues_by_domain.get(domain, 0)

            if domain not in executed_domains:
                status = "SKIPPED"
            elif domain == "coverage":
                # Coverage uses summary.passed, not issue count
                if result.coverage_summary:
                    status = "PASS" if result.coverage_summary.passed else "FAIL"
                else:
                    status = "SKIPPED"
            elif domain == "duplication":
                # Duplication uses summary.passed, not issue count
                if result.duplication_summary:
                    status = "PASS" if result.duplication_summary.passed else "FAIL"
                else:
                    status = "SKIPPED"
            elif issue_count == 0:
                status = "PASS"
            else:
                status = f"{issue_count} issues"

            lines.append(f"  {domain.upper()}: {status}")

        return lines
