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
from typing import IO, Any, Dict, List, Optional

from lucidshark.core.models import (
    ScanDomain,
    ScanResult,
    ToolDomain,
    UnifiedIssue,
)
from lucidshark.mcp.formatter import (
    FixInstruction,
    SEVERITY_PRIORITY,
    DOMAIN_ACTION_PREFIX,
)
from lucidshark.plugins.reporters.base import ReporterPlugin


class AIReporter(ReporterPlugin):
    """Reporter plugin that outputs AI-friendly scan results.

    Produces structured JSON with:
    - Fix instructions sorted by priority
    - Actionable fix steps for each issue
    - Domain pass/fail status
    - Recommended next actions
    """

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
        issues = result.issues
        instructions = [self._issue_to_instruction(issue) for issue in issues]
        instructions.sort(key=lambda x: x.priority)

        # Count by severity
        severity_counts: dict[str, int] = {}
        for issue in issues:
            sev_name = issue.severity.value if issue.severity else "unknown"
            severity_counts[sev_name] = severity_counts.get(sev_name, 0) + 1

        # Group issues by domain
        issues_by_domain: Dict[str, List[Dict[str, Any]]] = {}
        for issue in issues:
            domain_name = issue.domain.value if issue.domain else "unknown"
            if domain_name not in issues_by_domain:
                issues_by_domain[domain_name] = []
            issues_by_domain[domain_name].append(self._issue_to_brief(issue))

        # Build domain status from metadata
        domain_status = self._build_domain_status(result, issues_by_domain)

        # Generate recommended action
        recommended_action = self._generate_recommended_action(
            issues, severity_counts, domain_status
        )

        output: Dict[str, Any] = {
            "total_issues": len(issues),
            "blocking": any(i.priority <= 2 for i in instructions),
            "summary": self._generate_summary(issues, severity_counts),
            "severity_counts": severity_counts,
            "domain_status": domain_status,
            "issues_by_domain": issues_by_domain,
            "instructions": [asdict(i) for i in instructions],
            "recommended_action": recommended_action,
        }

        if result.coverage_summary:
            output["coverage_summary"] = asdict(result.coverage_summary)

        if result.duplication_summary:
            output["duplication_summary"] = asdict(result.duplication_summary)

        return output

    def _build_domain_status(
        self,
        result: ScanResult,
        issues_by_domain: Dict[str, List[Dict[str, Any]]],
    ) -> Dict[str, Dict[str, Any]]:
        """Build domain pass/fail status."""
        domain_status: Dict[str, Dict[str, Any]] = {}

        # Get checked domains from metadata
        checked_domains: List[str] = []
        if result.metadata and result.metadata.scanners_used:
            # scanners_used is a list of dicts with "domains" key
            for scanner in result.metadata.scanners_used:
                if scanner.get("domains"):
                    checked_domains.extend(scanner["domains"])

        # Infer domains from issues if metadata missing
        if not checked_domains:
            checked_domains = list(issues_by_domain.keys())

        for domain in checked_domains:
            # Special handling for duplication
            if domain == "duplication" and result.duplication_summary:
                dup = result.duplication_summary
                passed = dup.passed
                status = "pass" if passed else "fail"
                pct = dup.duplication_percent
                threshold = dup.threshold
                domain_status[domain] = {
                    "status": status,
                    "display": f"{pct:.1f}% duplication (threshold: {threshold:.0f}%)",
                    "duplication_percent": round(pct, 2),
                    "threshold": threshold,
                }
                continue

            domain_issues = issues_by_domain.get(domain, [])
            issue_count = len(domain_issues)
            fixable_count = sum(1 for i in domain_issues if i.get("fixable", False))

            if issue_count == 0:
                status = "pass"
                status_display = "Pass"
            else:
                status = "fail"
                if fixable_count > 0:
                    status_display = f"{issue_count} issues ({fixable_count} auto-fixable)"
                else:
                    status_display = f"{issue_count} issues"

            domain_status[domain] = {
                "status": status,
                "display": status_display,
                "issue_count": issue_count,
                "fixable_count": fixable_count,
            }

        return domain_status

    def _issue_to_instruction(self, issue: UnifiedIssue) -> FixInstruction:
        """Convert UnifiedIssue to FixInstruction."""
        file_path = str(issue.file_path) if issue.file_path else ""

        return FixInstruction(
            priority=SEVERITY_PRIORITY.get(issue.severity, 3),
            action=self._generate_action(issue),
            summary=self._generate_summary_line(issue),
            file=file_path,
            line=issue.line_start or 0,
            column=issue.column_start,
            problem=issue.description or "",
            fix_steps=self._generate_fix_steps(issue),
            suggested_fix=self._generate_suggested_fix(issue),
            current_code=issue.code_snippet,
            documentation_url=issue.documentation_url,
            related_issues=[],
            issue_id=issue.id,
        )

    def _generate_action(self, issue: UnifiedIssue) -> str:
        """Generate action type from issue."""
        prefix = DOMAIN_ACTION_PREFIX.get(issue.domain, "FIX_")
        title_lower = issue.title.lower() if issue.title else ""
        domain = issue.domain

        if domain in (ScanDomain.SAST, ToolDomain.SECURITY):
            if "hardcoded" in title_lower or "secret" in title_lower:
                return f"{prefix}HARDCODED_SECRET"
            elif "injection" in title_lower:
                return f"{prefix}INJECTION"
            elif "xss" in title_lower:
                return f"{prefix}XSS"
            return f"{prefix}VULNERABILITY"

        if domain == ScanDomain.SCA:
            return f"{prefix}VULNERABILITY"

        if domain == ScanDomain.IAC:
            if "exposed" in title_lower or "public" in title_lower:
                return f"{prefix}EXPOSURE"
            return f"{prefix}MISCONFIGURATION"

        if domain == ScanDomain.CONTAINER:
            return f"{prefix}VULNERABILITY"

        if domain == ToolDomain.LINTING:
            return f"{prefix}ERROR"

        if domain == ToolDomain.TYPE_CHECKING:
            return f"{prefix}ERROR"

        if domain == ToolDomain.TESTING:
            return f"{prefix}FAILURE"

        if domain == ToolDomain.COVERAGE:
            return f"{prefix}GAP"

        return "FIX_ISSUE"

    def _generate_summary_line(self, issue: UnifiedIssue) -> str:
        """Generate one-line summary for issue."""
        file_part = ""
        if issue.file_path:
            file_name = (
                issue.file_path.name
                if hasattr(issue.file_path, "name")
                else str(issue.file_path).split("/")[-1]
            )
            if issue.line_start:
                file_part = f" in {file_name}:{issue.line_start}"
            else:
                file_part = f" in {file_name}"

        return f"{issue.title}{file_part}"

    def _generate_summary(
        self,
        issues: List[UnifiedIssue],
        severity_counts: Dict[str, int],
    ) -> str:
        """Generate overall summary string."""
        if not issues:
            return "No issues found"

        parts = []
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                parts.append(f"{count} {sev}")

        return f"{len(issues)} issues found: {', '.join(parts)}"

    def _generate_fix_steps(self, issue: UnifiedIssue) -> List[str]:
        """Generate fix steps from issue context."""
        steps = []

        if issue.recommendation:
            steps.append(issue.recommendation)

        ai_explanation = issue.metadata.get("ai_explanation")
        if ai_explanation:
            steps.extend(self._parse_ai_explanation(ai_explanation))

        if not steps:
            steps = self._generate_generic_steps(issue)

        return steps

    def _parse_ai_explanation(self, explanation: str) -> List[str]:
        """Parse AI explanation into steps."""
        if not explanation:
            return []

        lines = explanation.strip().split("\n")
        steps = []

        for line in lines:
            line = line.strip()
            if not line:
                continue
            if line[0].isdigit() and "." in line[:3]:
                line = line.split(".", 1)[1].strip()
            elif line.startswith("-") or line.startswith("*"):
                line = line[1:].strip()

            if line and len(line) > 5:
                steps.append(line)

        return steps[:5]

    def _generate_generic_steps(self, issue: UnifiedIssue) -> List[str]:
        """Generate generic fix steps based on domain."""
        file_ref = (
            f"{issue.file_path}:{issue.line_start}"
            if issue.file_path and issue.line_start
            else str(issue.file_path or "the file")
        )
        domain = issue.domain

        if domain in (ScanDomain.SAST, ToolDomain.SECURITY):
            return [
                f"Review the security issue at {file_ref}",
                "Apply the recommended fix from the scanner",
                "Verify the fix doesn't break functionality",
                "Consider adding tests to prevent regression",
            ]

        if domain == ScanDomain.SCA:
            return [
                f"Update the vulnerable dependency mentioned in {issue.title}",
                "Run tests to ensure compatibility with new version",
                "Check for breaking changes in the changelog",
            ]

        if domain == ScanDomain.IAC:
            return [
                f"Review the infrastructure issue at {file_ref}",
                "Apply security best practices for the resource",
                "Test the changes in a non-production environment",
            ]

        if domain == ScanDomain.CONTAINER:
            return [
                f"Review the container vulnerability at {file_ref}",
                "Update the base image or vulnerable packages",
                "Rebuild and test the container",
            ]

        if domain == ToolDomain.LINTING:
            return [
                f"Fix the linting issue at {file_ref}",
                "Run 'lucidshark scan --linting --fix' for auto-fix",
            ]

        if domain == ToolDomain.TYPE_CHECKING:
            return [
                f"Fix the type error at {file_ref}",
                "Ensure type annotations are correct and complete",
                "Check for None values that need handling",
            ]

        if domain == ToolDomain.TESTING:
            return [
                f"Review the failing test at {file_ref}",
                "Determine if the test or the code needs to be fixed",
                "Run the test in isolation to verify the fix",
            ]

        if domain == ToolDomain.COVERAGE:
            return [
                f"Add tests to cover the uncovered code at {file_ref}",
                "Focus on critical paths and edge cases",
                "Verify coverage threshold is met after adding tests",
            ]

        return [f"Address the issue at {file_ref}"]

    def _generate_suggested_fix(self, issue: UnifiedIssue) -> Optional[str]:
        """Generate suggested fix code if available."""
        if issue.suggested_fix:
            return issue.suggested_fix

        if issue.domain == ToolDomain.LINTING:
            auto_fix = issue.metadata.get("auto_fix")
            if auto_fix:
                return auto_fix

        return None

    def _issue_to_brief(self, issue: UnifiedIssue) -> Dict[str, Any]:
        """Convert issue to brief format for domain grouping."""
        file_path = str(issue.file_path) if issue.file_path else ""
        location = file_path
        if issue.line_start:
            location = f"{file_path}:{issue.line_start}"

        return {
            "id": issue.id,
            "location": location,
            "severity": issue.severity.value if issue.severity else "unknown",
            "title": issue.title or "",
            "fixable": issue.fixable,
        }

    def _generate_recommended_action(
        self,
        issues: List[UnifiedIssue],
        severity_counts: Dict[str, int],
        domain_status: Dict[str, Dict[str, Any]],
    ) -> str:
        """Generate recommended next action based on scan results."""
        if not issues:
            return "All checks passed. Ready to proceed."

        fixable_count = sum(1 for i in issues if i.fixable)
        linting_fixable = sum(
            1 for i in issues if i.domain == ToolDomain.LINTING and i.fixable
        )

        critical_count = severity_counts.get("critical", 0)
        high_count = severity_counts.get("high", 0)

        if critical_count > 0:
            return f"Fix {critical_count} critical issue(s) immediately before proceeding."

        if high_count > 0:
            return f"Address {high_count} high-severity issue(s) before committing."

        if linting_fixable > 0:
            return (
                f"Run `lucidshark scan --fix` to auto-fix {linting_fixable} linting "
                "issue(s), then address remaining issues manually."
            )

        if fixable_count > 0:
            return f"Run `lucidshark scan --fix` to auto-fix {fixable_count} issue(s)."

        type_issues = sum(1 for i in issues if i.domain == ToolDomain.TYPE_CHECKING)
        if type_issues > 0:
            return (
                f"Fix {type_issues} type error(s) by updating type annotations "
                "or handling None values."
            )

        return f"Review and fix {len(issues)} issue(s), then re-scan to verify."
