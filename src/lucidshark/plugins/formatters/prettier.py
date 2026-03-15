"""Prettier formatter plugin.

Wraps `prettier` for JavaScript, TypeScript, CSS, JSON, and Markdown formatting.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from pathlib import Path
from typing import List

from lucidshark.core.logging import get_logger
from lucidshark.core.models import (
    ScanContext,
    Severity,
    SkipReason,
    ToolDomain,
    UnifiedIssue,
)
from lucidshark.core.paths import resolve_node_bin
from lucidshark.core.subprocess_runner import run_with_streaming
from lucidshark.plugins.formatters.base import FormatterPlugin
from lucidshark.plugins.linters.base import FixResult
from lucidshark.plugins.utils import get_cli_version

LOGGER = get_logger(__name__)

PRETTIER_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".css", ".json", ".md"}


class PrettierFormatter(FormatterPlugin):
    """Prettier formatter plugin for JS/TS/CSS/JSON/Markdown formatting."""

    @property
    def name(self) -> str:
        return "prettier"

    @property
    def languages(self) -> List[str]:
        return ["javascript", "typescript", "css", "json", "markdown"]

    def get_version(self) -> str:
        try:
            binary = self.ensure_binary()
            return get_cli_version(binary)
        except FileNotFoundError:
            return "unknown"

    def ensure_binary(self) -> Path:
        # Check project node_modules first
        if self._project_root:
            node_binary = resolve_node_bin(self._project_root, "prettier")
            if node_binary:
                return node_binary

        # Check system PATH
        system_binary = shutil.which("prettier")
        if system_binary:
            return Path(system_binary)

        raise FileNotFoundError(
            "Prettier is not installed. Install it with:\n"
            "  npm install --save-dev prettier\n"
            "  OR\n"
            "  yarn add --dev prettier"
        )

    # Patterns that indicate a line is an error/info message, not a file path.
    _NON_PATH_PATTERNS: List[re.Pattern[str]] = [
        # Prettier info/summary messages
        re.compile(r"^Checking formatting", re.IGNORECASE),
        re.compile(r"^All matched files", re.IGNORECASE),
        re.compile(r"^Code style issues", re.IGNORECASE),
        # Error messages from Prettier
        re.compile(r"^Error", re.IGNORECASE),
        re.compile(r"^SyntaxError", re.IGNORECASE),
        re.compile(r"^TypeError", re.IGNORECASE),
        re.compile(r"^Invalid", re.IGNORECASE),
        re.compile(r"^Unable to", re.IGNORECASE),
        # Lines containing common error-message phrases unlikely in file paths
        re.compile(r"error occurred", re.IGNORECASE),
        re.compile(r"failed to", re.IGNORECASE),
        re.compile(r"No parser could be inferred", re.IGNORECASE),
        re.compile(r"No files matching", re.IGNORECASE),
        # Prettier stderr diagnostic lines
        re.compile(r"^\[error\]", re.IGNORECASE),
        re.compile(r"^\[info\]", re.IGNORECASE),
        re.compile(r"^\[debug\]", re.IGNORECASE),
    ]

    @staticmethod
    def _looks_like_file_path(text: str) -> bool:
        """Return True if *text* looks like a real file path rather than an error message.

        Prettier --check outputs one file path per line for unformatted files.
        Error or informational messages should not be treated as file paths.
        """
        # Reject empty or whitespace-only strings
        if not text or not text.strip():
            return False

        # Reject lines matching known non-path patterns
        for pattern in PrettierFormatter._NON_PATH_PATTERNS:
            if pattern.search(text):
                return False

        # Reject lines that contain characters not found in file paths.
        # Periods and spaces are fine, but sentences with multiple spaces
        # or punctuation like '!' '?' ',' are likely error messages.
        if any(ch in text for ch in ("!", "?", ",")):
            return False

        # A valid prettier output line should have a recognisable file extension
        # or at least look like a relative/absolute path (contains / or \).
        has_extension = bool(re.search(r"\.\w{1,10}$", text))
        has_path_separator = "/" in text or "\\" in text
        if not has_extension and not has_path_separator:
            return False

        return True

    def check(self, context: ScanContext) -> List[UnifiedIssue]:
        try:
            binary = self.ensure_binary()
        except FileNotFoundError as e:
            LOGGER.warning(str(e))
            return []

        cmd = [str(binary), "--check"]

        paths = self._resolve_paths(context, PRETTIER_EXTENSIONS, fallback_to_cwd=True)
        if not paths:
            LOGGER.debug("No files to format-check with Prettier")
            return []

        cmd.extend(paths)

        try:
            result = run_with_streaming(
                cmd=cmd,
                cwd=context.project_root,
                tool_name="prettier",
                stream_handler=context.stream_handler,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            LOGGER.warning("Prettier check timed out after 120 seconds")
            context.record_skip(
                tool_name=self.name,
                domain=ToolDomain.FORMATTING,
                reason=SkipReason.EXECUTION_FAILED,
                message="Prettier check timed out after 120 seconds",
            )
            return []
        except Exception as e:
            LOGGER.error(f"Failed to run prettier: {e}")
            context.record_skip(
                tool_name=self.name,
                domain=ToolDomain.FORMATTING,
                reason=SkipReason.EXECUTION_FAILED,
                message=f"Failed to run prettier: {e}",
            )
            return []

        if result.returncode == 0:
            return []

        # Parse output: prettier outputs file paths that aren't formatted
        # Prettier v3+ outputs unformatted file paths to stderr, not stdout.
        # Combine both streams to catch all reported files.
        issues = []
        stdout = result.stdout.strip() if result.stdout else ""
        stderr = result.stderr.strip() if result.stderr else ""
        combined = "\n".join(filter(None, [stdout, stderr]))
        for line in combined.splitlines():
            line = line.strip()
            if not line:
                continue
            # prettier --check outputs "[warn] path/to/file.js" for unformatted files
            file_path_str = line
            if line.startswith("[warn]"):
                file_path_str = line.replace("[warn]", "").strip()
            if not file_path_str:
                continue

            # Skip lines that are clearly not file paths: info/summary/error
            # messages from Prettier's output.
            if not self._looks_like_file_path(file_path_str):
                LOGGER.debug(
                    "Skipping non-file-path line from prettier output: %s",
                    file_path_str,
                )
                continue

            file_path = Path(file_path_str)
            if not file_path.is_absolute():
                file_path = context.project_root / file_path

            content = f"prettier:{file_path_str}"
            hash_val = hashlib.sha256(content.encode()).hexdigest()[:12]

            issues.append(
                UnifiedIssue(
                    id=f"prettier-format-{hash_val}",
                    domain=ToolDomain.FORMATTING,
                    source_tool="prettier",
                    severity=Severity.LOW,
                    rule_id="format",
                    title=f"File needs formatting: {file_path_str}",
                    description=f"File {file_path_str} does not match Prettier style.",
                    file_path=file_path,
                    fixable=True,
                    suggested_fix="Run prettier --write to fix formatting.",
                )
            )

        LOGGER.info(f"Prettier found {len(issues)} issues")
        return issues

    def fix(self, context: ScanContext) -> FixResult:
        try:
            binary = self.ensure_binary()
        except FileNotFoundError as e:
            LOGGER.warning(str(e))
            return FixResult()

        cmd = [str(binary), "--write"]

        paths = self._resolve_paths(context, PRETTIER_EXTENSIONS, fallback_to_cwd=True)
        if not paths:
            return FixResult()

        cmd.extend(paths)

        try:
            run_with_streaming(
                cmd=cmd,
                cwd=context.project_root,
                tool_name="prettier-fix",
                stream_handler=context.stream_handler,
                timeout=120,
            )
        except Exception as e:
            LOGGER.error(f"Failed to run prettier --write: {e}")
            return FixResult()

        # Domain runner calls check() after fix to get remaining issues
        return FixResult()
