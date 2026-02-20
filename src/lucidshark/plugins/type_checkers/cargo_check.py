"""Cargo check type checker plugin.

Uses the Rust compiler's diagnostics via `cargo check` to detect
type errors, lifetime issues, and other compile-time problems.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional

from lucidshark.core.logging import get_logger
from lucidshark.core.models import (
    ScanContext,
    Severity,
    ToolDomain,
    UnifiedIssue,
)
from lucidshark.core.subprocess_runner import run_with_streaming
from lucidshark.plugins.type_checkers.base import TypeCheckerPlugin

LOGGER = get_logger(__name__)

# Compiler diagnostic level to severity mapping
LEVEL_SEVERITY = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "help": Severity.INFO,
    "ice": Severity.HIGH,
}


class CargoCheckChecker(TypeCheckerPlugin):
    """Cargo check plugin for Rust type checking and compiler diagnostics."""

    def __init__(self, project_root: Optional[Path] = None, **kwargs) -> None:
        """Initialize CargoCheckChecker.

        Args:
            project_root: Optional project root for tool resolution.
        """
        self._project_root = project_root

    @property
    def name(self) -> str:
        """Plugin identifier."""
        return "cargo_check"

    @property
    def languages(self) -> List[str]:
        """Supported languages."""
        return ["rust"]

    @property
    def supports_strict_mode(self) -> bool:
        """Rust compiler is always strict about types."""
        return False

    def get_version(self) -> str:
        """Get Rust compiler version."""
        try:
            cargo = self._find_cargo()
            result = subprocess.run(
                [str(cargo), "--version"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return "unknown"

    def _find_cargo(self) -> Path:
        """Find cargo binary in PATH.

        Returns:
            Path to cargo binary.

        Raises:
            FileNotFoundError: If cargo is not found.
        """
        cargo = shutil.which("cargo")
        if cargo:
            return Path(cargo)
        raise FileNotFoundError(
            "cargo not found in PATH. Install Rust via https://rustup.rs/"
        )

    def ensure_binary(self) -> Path:
        """Ensure cargo is available.

        Returns:
            Path to cargo binary.

        Raises:
            FileNotFoundError: If cargo is not available.
        """
        return self._find_cargo()

    def check(self, context: ScanContext) -> List[UnifiedIssue]:
        """Run cargo check for type checking.

        Args:
            context: Scan context with paths and configuration.

        Returns:
            List of type checking issues.
        """
        try:
            cargo = self.ensure_binary()
        except FileNotFoundError as e:
            LOGGER.warning(str(e))
            return []

        # Check for Cargo.toml
        if not (context.project_root / "Cargo.toml").exists():
            LOGGER.info("No Cargo.toml found, skipping cargo check")
            return []

        cmd = [
            str(cargo),
            "check",
            "--message-format=json",
            "--quiet",
        ]

        LOGGER.debug(f"Running: {' '.join(cmd)}")

        try:
            result = run_with_streaming(
                cmd=cmd,
                cwd=context.project_root,
                tool_name="cargo-check",
                stream_handler=context.stream_handler,
                timeout=300,
            )
        except subprocess.TimeoutExpired:
            LOGGER.warning("cargo check timed out after 300 seconds")
            return []
        except Exception as e:
            LOGGER.error(f"Failed to run cargo check: {e}")
            return []

        issues = self._parse_output(result.stdout, context.project_root)
        LOGGER.info(f"cargo check found {len(issues)} issues")
        return issues

    def _parse_output(self, output: str, project_root: Path) -> List[UnifiedIssue]:
        """Parse cargo check JSON output.

        Cargo outputs one JSON object per line. We only process lines
        where "reason" == "compiler-message" and filter out clippy lints.

        Args:
            output: Raw stdout from cargo check.
            project_root: Project root directory.

        Returns:
            List of UnifiedIssue objects.
        """
        if not output.strip():
            return []

        issues = []
        seen_ids = set()

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            if data.get("reason") != "compiler-message":
                continue

            message = data.get("message")
            if not message:
                continue

            # Skip clippy lints - those belong to the linting domain
            code_obj = message.get("code") or {}
            code = code_obj.get("code", "")
            if code.startswith("clippy::"):
                continue

            issue = self._message_to_issue(message, project_root)
            if issue and issue.id not in seen_ids:
                issues.append(issue)
                seen_ids.add(issue.id)

        return issues

    def _message_to_issue(
        self, message: dict, project_root: Path
    ) -> Optional[UnifiedIssue]:
        """Convert a cargo diagnostic message to UnifiedIssue.

        Args:
            message: Parsed JSON message object.
            project_root: Project root directory.

        Returns:
            UnifiedIssue or None.
        """
        try:
            level = message.get("level", "")
            text = message.get("message", "")
            code_obj = message.get("code") or {}
            code = code_obj.get("code", "")

            # Only process errors and warnings
            if level not in ("error", "warning"):
                return None

            # Get spans for location info
            spans = message.get("spans", [])
            primary_span = None
            for span in spans:
                if span.get("is_primary", False):
                    primary_span = span
                    break
            if not primary_span and spans:
                primary_span = spans[0]

            # Extract location
            file_path = None
            line_start = None
            line_end = None
            column_start = None
            column_end = None
            code_snippet = None

            if primary_span:
                file_name = primary_span.get("file_name", "")
                if file_name and not file_name.startswith("/rustc/"):
                    file_path = Path(file_name)
                    if not file_path.is_absolute():
                        file_path = project_root / file_path

                line_start = primary_span.get("line_start")
                line_end = primary_span.get("line_end")
                column_start = primary_span.get("column_start")
                column_end = primary_span.get("column_end")

                span_text = primary_span.get("text", [])
                if span_text:
                    code_snippet = "\n".join(
                        t.get("text", "") for t in span_text
                    )

            # Skip if no file (internal compiler messages)
            if not file_path:
                return None

            severity = LEVEL_SEVERITY.get(level, Severity.MEDIUM)

            title = f"[{code}] {text}" if code else text
            issue_id = self._generate_issue_id(
                code, str(file_path), line_start, column_start, text
            )

            # Extract suggestion from children
            suggestion = None
            children = message.get("children", [])
            for child in children:
                if child.get("level") == "help":
                    suggestion = child.get("message", "")
                    break

            return UnifiedIssue(
                id=issue_id,
                domain=ToolDomain.TYPE_CHECKING,
                source_tool="cargo_check",
                severity=severity,
                rule_id=code or "compiler",
                title=title,
                description=text,
                file_path=file_path,
                line_start=line_start,
                line_end=line_end,
                column_start=column_start,
                column_end=column_end,
                code_snippet=code_snippet,
                fixable=False,
                suggested_fix=suggestion,
                recommendation=suggestion,
                metadata={
                    "level": level,
                    "code": code,
                },
            )
        except Exception as e:
            LOGGER.warning(f"Failed to parse cargo check message: {e}")
            return None

    def _generate_issue_id(
        self,
        code: str,
        file: str,
        line: Optional[int],
        column: Optional[int],
        message: str,
    ) -> str:
        """Generate deterministic issue ID.

        Args:
            code: Error code.
            file: File path.
            line: Line number.
            column: Column number.
            message: Error message.

        Returns:
            Unique issue ID.
        """
        content = f"{code}:{file}:{line or 0}:{column or 0}:{message}"
        hash_val = hashlib.sha256(content.encode()).hexdigest()[:12]
        return f"cargo-check-{hash_val}"
