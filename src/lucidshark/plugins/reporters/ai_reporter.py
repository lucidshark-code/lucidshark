"""AI-friendly reporter plugin for lucidshark.

Produces output optimized for AI agents with:
- Structured fix instructions sorted by priority
- Actionable fix steps
- Clear domain pass/fail status
- Recommended next actions
"""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import IO, Any, Dict, List

from lucidshark.core.models import ScanResult
from lucidshark.mcp.formatter import InstructionFormatter
from lucidshark.plugins.coverage.base import CoverageResult
from lucidshark.plugins.duplication.base import DuplicationResult
from lucidshark.plugins.reporters.base import ReporterPlugin


class AIReporter(ReporterPlugin):
    """Reporter plugin that outputs AI-friendly scan results.

    Produces structured JSON with:
    - Fix instructions sorted by priority
    - Actionable fix steps for each issue
    - Domain pass/fail status
    - Recommended next actions

    Delegates formatting to InstructionFormatter for consistency with MCP tools.
    """

    def __init__(self) -> None:
        self._formatter = InstructionFormatter()

    @property
    def name(self) -> str:
        return "ai"

    def report(self, result: ScanResult, output: IO[str]) -> None:
        """Format scan result as AI-friendly JSON.

        Args:
            result: The scan result to format.
            output: Output stream to write to.
        """
        formatted = self._format_result(result)
        json.dump(formatted, output, indent=2)
        output.write("\n")

    def _format_result(self, result: ScanResult) -> Dict[str, Any]:
        """Convert ScanResult to AI-friendly format."""
        # Get checked domains from metadata
        checked_domains = self._get_checked_domains(result)
        # Get executed domains (subset of checked that were actually run)
        executed_domains = self._get_executed_domains(result)

        # Convert coverage summary to CoverageResult if present
        coverage_result = None
        if result.coverage_summary:
            cov = result.coverage_summary
            # CoverageResult computes percentage and passed as properties
            coverage_result = CoverageResult(
                total_lines=cov.total_lines,
                covered_lines=cov.covered_lines,
                missing_lines=cov.missing_lines,
                threshold=cov.threshold,
            )

        # Convert duplication summary to DuplicationResult if present
        duplication_result = None
        if result.duplication_summary:
            dup = result.duplication_summary
            # DuplicationResult computes duplication_percent and passed as properties
            duplication_result = DuplicationResult(
                files_analyzed=dup.files_analyzed,
                total_lines=dup.total_lines,
                duplicate_blocks=dup.duplicate_blocks,
                duplicate_lines=dup.duplicate_lines,
                threshold=dup.threshold,
                duplicates=[],  # Not needed for formatting
                execution_failed=dup.execution_failed,
            )

        # Use InstructionFormatter for the main formatting
        output = self._formatter.format_scan_result(
            issues=result.issues,
            checked_domains=checked_domains,
            executed_domains=executed_domains,
            coverage_result=coverage_result,
            duplication_result=duplication_result,
        )

        # Add coverage and duplication summaries from result
        if result.coverage_summary:
            output["coverage_summary"] = asdict(result.coverage_summary)

        if result.duplication_summary:
            output["duplication_summary"] = asdict(result.duplication_summary)

        # Add skipped tools information
        if result.tool_skips:
            output["skipped_tools"] = [
                {
                    "tool": skip.tool_name,
                    "domain": skip.domain.value
                    if hasattr(skip.domain, "value")
                    else str(skip.domain),
                    "reason": skip.reason.value,
                    "message": skip.message,
                    "suggestion": skip.suggestion,
                    "mandatory": skip.mandatory,
                }
                for skip in result.tool_skips
            ]
            mandatory_skips = [s for s in result.tool_skips if s.mandatory]
            if mandatory_skips:
                output["mandatory_tool_failures"] = len(mandatory_skips)

        return output

    def _get_checked_domains(self, result: ScanResult) -> List[str]:
        """Extract checked domains from scan result metadata."""
        # Prefer explicit enabled_domains from metadata (set by CLI scan)
        if result.metadata and result.metadata.enabled_domains:
            return result.metadata.enabled_domains

        # Fall back to extracting from scanners_used
        checked_domains: List[str] = []

        if result.metadata and result.metadata.scanners_used:
            for scanner in result.metadata.scanners_used:
                if scanner.get("domains"):
                    checked_domains.extend(scanner["domains"])

        # Infer from issues if metadata missing
        if not checked_domains:
            seen_domains: set[str] = set()
            for issue in result.issues:
                domain_name = issue.domain.value if issue.domain else "unknown"
                seen_domains.add(domain_name)
            checked_domains = list(seen_domains)

        return checked_domains

    def _get_executed_domains(self, result: ScanResult) -> List[str]:
        """Extract executed domains from scan result metadata.

        Returns the list of domains that were actually run (as opposed to
        just configured). If executed_domains is not set, falls back to
        enabled_domains for backward compatibility.
        """
        if result.metadata and result.metadata.executed_domains:
            return result.metadata.executed_domains

        # Fall back to enabled_domains (assume all enabled were executed)
        return self._get_checked_domains(result)
