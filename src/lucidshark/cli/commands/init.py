"""Init command implementation.

Configure AI tools (Claude Code) to use LucidShark.
Supports both CLI-first (recommended) and optional MCP modes.
"""

from __future__ import annotations

import json
import shutil
import sys
from argparse import Namespace
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

if TYPE_CHECKING:
    from lucidshark.config.models import LucidSharkConfig

from lucidshark.cli.commands import Command
from lucidshark.cli.exit_codes import EXIT_INVALID_USAGE, EXIT_SUCCESS
from lucidshark.core.logging import get_logger

LOGGER = get_logger(__name__)

# MCP server arguments for LucidShark
LUCIDSHARK_MCP_ARGS = ["serve", "--mcp"]

# Claude skill content for proactive lucidshark usage (CLI-first)
LUCIDSHARK_SKILL_CONTENT = """---
name: lucidshark
description: "Unified code quality pipeline: linting, type checking, security (SAST/SCA/IaC/container), testing, coverage, duplication. Run proactively after code changes."
---

# LucidShark - Unified Code Quality Pipeline

Run scans proactively after code changes. Don't wait for user to ask.

## What It Can Do

| Domain | What It Does | Tools |
|--------|--------------|-------|
| **linting** | Style issues, code smells, auto-fix | Ruff, ESLint, Biome, Checkstyle, Clippy |
| **type_checking** | Type errors, static analysis | mypy, Pyright, tsc, SpotBugs, cargo check |
| **sast** | Security vulnerabilities in code | OpenGrep |
| **sca** | Dependency vulnerabilities | Trivy |
| **iac** | Infrastructure misconfigurations | Checkov |
| **container** | Container image vulnerabilities | Trivy |
| **testing** | Run tests, report failures | pytest, Jest, Karma, Playwright, JUnit, cargo test |
| **coverage** | Code coverage analysis | coverage.py, Istanbul, JaCoCo, Tarpaulin |
| **duplication** | Detect code clones | Duplo |

## When to Scan

| Trigger | Command |
|---------|---------|
| After editing code | `lucidshark scan --fix --format ai` |
| After fixing bugs | `lucidshark scan --fix --format ai` to verify no new issues |
| User asks to run tests | `lucidshark scan --testing --format ai` |
| User asks about coverage | `lucidshark scan --testing --coverage --format ai` |
| Security concerns | `lucidshark scan --sast --sca --format ai` |
| Before commits | `lucidshark scan --all --format ai` |

**Skip scanning** if user explicitly says "don't scan" or "skip checks".

## Smart Domain Selection

Pick domains based on what files changed:

| Files Changed | Flags to use |
|---|---|
| `.py`, `.js`, `.ts`, `.rs`, `.go`, `.java`, `.kt` | `--linting --type-checking` |
| `Dockerfile`, `docker-compose.*` | `--container` |
| `.tf`, `.yaml`/`.yml` (k8s/CloudFormation) | `--iac` |
| `package.json`, `requirements.txt`, `Cargo.toml`, `go.mod` | `--sca` |
| Auth, crypto, input handling, SQL code | `--sast` |
| Mixed / many file types / before commit | `--all` |

## Commands

```bash
# Default after code changes (auto-fixes linting)
lucidshark scan --fix --format ai

# Run tests
lucidshark scan --testing --format ai

# Check test coverage (requires testing)
lucidshark scan --testing --coverage --format ai

# Security scan (code + dependencies)
lucidshark scan --sast --sca --format ai

# Full scan including tests, coverage, duplication
lucidshark scan --all --format ai

# Scan specific files
lucidshark scan --files path/to/file.py --format ai
```

**Default:** Scans only uncommitted changes. Use `--all-files` for full project.

## Workflow

1. Make code changes
2. Run `lucidshark scan --fix --format ai`
3. Fix remaining issues
4. Re-scan if needed
5. Report done

**Task is complete when scan shows zero issues.**
"""

# CLAUDE.md section for always-in-context proactive scanning instructions
# This is the most impactful integration point because CLAUDE.md is loaded
# into Claude's system prompt for every conversation.
# CLI-first approach: use bash commands instead of MCP tools.
LUCIDSHARK_CLAUDE_MD_SECTION = """\

<!-- lucidshark:start - managed by lucidshark init, do not edit manually -->
## LucidShark - Unified Code Quality Pipeline

LucidShark provides comprehensive code quality checks via CLI. Use `--format ai` for AI-optimized output.

### What It Can Do

| Domain | What It Does | Tools Used |
|--------|--------------|------------|
| **linting** | Style issues, code smells, auto-fix available | Ruff, ESLint, Biome, Checkstyle, Clippy |
| **type_checking** | Type errors, static analysis | mypy, Pyright, tsc, SpotBugs, cargo check |
| **sast** | Security vulnerabilities in code | OpenGrep |
| **sca** | Dependency vulnerabilities | Trivy |
| **iac** | Infrastructure misconfigurations | Checkov |
| **container** | Container image vulnerabilities | Trivy |
| **testing** | Run tests, report failures | pytest, Jest, Karma, Playwright, JUnit, cargo test |
| **coverage** | Code coverage analysis | coverage.py, Istanbul, JaCoCo, Tarpaulin |
| **duplication** | Detect code clones | Duplo |

### Automatic Scan Triggers

Run scans **proactively** after code changes — do not wait for the user to ask:

1. **After editing/writing code files** — `lucidshark scan --fix --format ai` with targeted domains
2. **After fixing a bug** — scan to verify the fix didn't introduce new issues
3. **Before reporting any task as complete** — always scan your changes before saying "done"
4. **Before creating a commit** — `lucidshark scan --all --format ai` for comprehensive check
5. **After refactoring** — scan to catch regressions or style issues

### Smart Domain Selection

Choose domains based on file types changed. Targeted scans are fast:

| Files edited | Flags to use |
|---|---|
| Python (`.py`) | `--linting --type-checking` |
| JavaScript/TypeScript (`.js`, `.ts`, `.tsx`, `.jsx`) | `--linting --type-checking` |
| Rust (`.rs`) | `--linting --type-checking` |
| Go (`.go`) | `--linting --type-checking` |
| Java/Kotlin (`.java`, `.kt`) | `--linting --type-checking` |
| Dockerfile / docker-compose | `--container` |
| Terraform / K8s / IaC YAML | `--iac` |
| Dependency files (`package.json`, `requirements.txt`, etc.) | `--sca` |
| Security-sensitive code (auth, crypto, SQL) | `--sast` |
| User asks to run tests | `--testing` |
| User asks about coverage | `--coverage` |
| Before commit/PR or mixed changes | `--all` |

### Quick Reference

```bash
# Scan after edits (auto-fixes linting, scans changed files only)
lucidshark scan --fix --format ai

# Scan specific domains
lucidshark scan --linting --type-checking --format ai

# Run tests
lucidshark scan --testing --format ai

# Check coverage (requires --testing)
lucidshark scan --testing --coverage --format ai

# Security scan
lucidshark scan --sast --sca --format ai

# Full scan (all checks)
lucidshark scan --all --format ai

# Scan specific files
lucidshark scan --files path/to/file.py --format ai

# Scan all files (not just changed)
lucidshark scan --all-files --format ai
```

### When NOT to Scan

- User explicitly says "don't scan", "skip checks", or "no linting"
- You only read/explored code without making any changes
- You only edited non-code files (markdown, docs, comments-only)
<!-- lucidshark:end -->
"""


class InitCommand(Command):
    """Configure AI tools to use LucidShark via MCP."""

    def __init__(self, version: str):
        """Initialize InitCommand.

        Args:
            version: Current lucidshark version string.
        """
        self._version = version

    @property
    def name(self) -> str:
        """Command identifier."""
        return "init"

    def execute(self, args: Namespace, config: "LucidSharkConfig | None" = None) -> int:
        """Execute the init command.

        Args:
            args: Parsed command-line arguments.
            config: Optional LucidShark configuration (unused).

        Returns:
            Exit code.
        """
        # Claude Code is the default (and currently only) target
        configure_claude = True

        dry_run = getattr(args, "dry_run", False)
        force = getattr(args, "force", False)
        remove = getattr(args, "remove", False)

        success = True

        if configure_claude:
            if not self._setup_claude_code(dry_run, force, remove):
                success = False

        if success and not dry_run:
            print("\nRestart your AI tool to apply changes.")

        return EXIT_SUCCESS if success else EXIT_INVALID_USAGE

    def _setup_claude_code(
        self,
        dry_run: bool = False,
        force: bool = False,
        remove: bool = False,
    ) -> bool:
        """Configure Claude Code MCP settings in project .mcp.json.

        Args:
            dry_run: If True, only show what would be done.
            force: If True, overwrite existing config.
            remove: If True, remove LucidShark from config.

        Returns:
            True if successful.
        """
        print("Configuring Claude Code (.mcp.json)...")

        config_path = self._get_claude_code_config_path()
        if config_path is None:
            print("  Could not determine Claude Code config location.")
            return False

        mcp_success = self._configure_mcp_tool(
            tool_name="Claude Code",
            config_path=config_path,
            config_key="mcpServers",
            dry_run=dry_run,
            force=force,
            remove=remove,
            use_portable_path=True,  # .mcp.json is version controlled
        )

        # Configure Claude skill
        skill_success = self._configure_claude_skill(
            dry_run=dry_run,
            force=force,
            remove=remove,
        )

        # Configure CLAUDE.md with proactive scanning instructions
        claude_md_success = self._configure_claude_md(
            dry_run=dry_run,
            force=force,
            remove=remove,
        )

        return mcp_success and skill_success and claude_md_success

    def _find_lucidshark_path(self, portable: bool = False) -> Optional[str]:
        """Find the lucidshark executable path.

        Searches in order:
        1. Local binary in project root (./lucidshark) - for standalone installs
        2. PATH via shutil.which (only if not portable)
        3. Same directory as current Python interpreter (for venv installs)
        4. Scripts directory on Windows

        Args:
            portable: If True, return a relative path suitable for version control.

        Returns:
            Path to lucidshark executable, or None if not found.
        """
        cwd = Path.cwd()

        # First check for local binary in project root (standalone install)
        if sys.platform == "win32":
            local_binary = cwd / "lucidshark.exe"
        else:
            local_binary = cwd / "lucidshark"

        if local_binary.exists() and local_binary.is_file():
            # For local binary, always return relative path
            return "./lucidshark.exe" if sys.platform == "win32" else "./lucidshark"

        # Then try PATH (only if not looking for portable path)
        if not portable:
            lucidshark_path = shutil.which("lucidshark")
            if lucidshark_path:
                return lucidshark_path

        # Try to find in the same directory as the Python interpreter
        # This handles venv installations where lucidshark isn't in global PATH
        python_dir = Path(sys.executable).parent

        if sys.platform == "win32":
            # On Windows, check both Scripts and the python directory
            candidates = [
                python_dir / "lucidshark.exe",
                python_dir / "Scripts" / "lucidshark.exe",
            ]
        else:
            # On Unix-like systems
            candidates = [
                python_dir / "lucidshark",
            ]

        for candidate in candidates:
            if candidate.exists():
                if portable:
                    # Try to make it relative to cwd for version control
                    try:
                        relative = candidate.relative_to(cwd)
                        return str(relative)
                    except ValueError:
                        # Not relative to cwd, can't use portable path
                        pass
                else:
                    return str(candidate)

        # For portable, fall back to just "lucidshark"
        if portable:
            return None

        return None

    def _build_mcp_config(self, lucidshark_path: Optional[str]) -> dict:
        """Build MCP server configuration.

        Args:
            lucidshark_path: Full path to lucidshark executable, or None.

        Returns:
            MCP server configuration dict.
        """
        command = lucidshark_path if lucidshark_path else "lucidshark"
        return {
            "command": command,
            "args": LUCIDSHARK_MCP_ARGS.copy(),
        }

    def _configure_mcp_tool(
        self,
        tool_name: str,
        config_path: Path,
        config_key: str,
        dry_run: bool = False,
        force: bool = False,
        remove: bool = False,
        use_portable_path: bool = False,
    ) -> bool:
        """Configure an MCP-compatible tool.

        Args:
            tool_name: Name of the tool for display.
            config_path: Path to the config file.
            config_key: Key in the config for MCP servers.
            dry_run: If True, only show what would be done.
            force: If True, overwrite existing config.
            remove: If True, remove LucidShark from config.
            use_portable_path: If True, use relative path for version control.

        Returns:
            True if successful.
        """
        # Find lucidshark executable
        lucidshark_path = self._find_lucidshark_path(portable=use_portable_path)
        if lucidshark_path:
            print(f"  Using lucidshark command: {lucidshark_path}")
        elif not dry_run:
            print("  Warning: 'lucidshark' command not found in PATH or venv.")
            print("  Using 'lucidshark' as command (must be in PATH at runtime).")

        # Read existing config
        config, error = self._read_json_config(config_path)
        if error and not remove:
            # For new config, start fresh
            config = {}

        # Get or create the MCP servers section
        mcp_servers = config.get(config_key, {})

        if remove:
            # Remove LucidShark from config
            if "lucidshark" in mcp_servers:
                if dry_run:
                    print(f"  Would remove lucidshark from {config_path}")
                else:
                    del mcp_servers["lucidshark"]
                    config[config_key] = mcp_servers
                    if not mcp_servers:
                        del config[config_key]
                    self._write_json_config(config_path, config)
                    print(f"  Removed lucidshark from {config_path}")
            else:
                print(f"  lucidshark not found in {config_path}")
            return True

        # Check if LucidShark is already configured
        if "lucidshark" in mcp_servers and not force:
            print(f"  LucidShark already configured in {config_path}")
            print("  Use --force to overwrite.")
            return True

        # Add LucidShark config with found path
        mcp_config = self._build_mcp_config(lucidshark_path)
        mcp_servers["lucidshark"] = mcp_config
        config[config_key] = mcp_servers

        if dry_run:
            print(f"  Would write to {config_path}:")
            print(f"    {json.dumps(config, indent=2)}")
            return True

        # Ensure parent directory exists
        config_path.parent.mkdir(parents=True, exist_ok=True)

        # Write config
        success = self._write_json_config(config_path, config)
        if success:
            print(f"  Added lucidshark to {config_path}")
            self._print_available_tools()
        return success

    def _configure_claude_skill(
        self,
        dry_run: bool = False,
        force: bool = False,
        remove: bool = False,
    ) -> bool:
        """Configure Claude skill for lucidshark.

        Creates a skill file at .claude/skills/lucidshark/SKILL.md

        Args:
            dry_run: If True, only show what would be done.
            force: If True, overwrite existing skill.
            remove: If True, remove lucidshark skill.

        Returns:
            True if successful.
        """
        skill_dir = Path.cwd() / ".claude" / "skills" / "lucidshark"
        skill_file = skill_dir / "SKILL.md"

        print("Configuring Claude skill...")

        if remove:
            if skill_file.exists():
                if dry_run:
                    print(f"  Would remove {skill_file}")
                else:
                    try:
                        skill_file.unlink()
                        # Remove directory if empty
                        if skill_dir.exists() and not any(skill_dir.iterdir()):
                            skill_dir.rmdir()
                        print("  Removed lucidshark skill")
                    except Exception as e:
                        print(f"  Error removing skill: {e}")
                        return False
            else:
                print("  Lucidshark skill not found")
            return True

        if skill_file.exists() and not force:
            print(f"  Lucidshark skill already exists at {skill_file}")
            print("  Use --force to overwrite.")
            return True

        if dry_run:
            print(f"  Would create skill at {skill_file}")
            return True

        # Ensure directory exists
        skill_dir.mkdir(parents=True, exist_ok=True)

        try:
            skill_file.write_text(LUCIDSHARK_SKILL_CONTENT.lstrip(), encoding="utf-8")
            print(f"  Created lucidshark skill at {skill_file}")
            return True
        except Exception as e:
            print(f"  Error creating skill: {e}")
            return False

    def _configure_claude_md(
        self,
        dry_run: bool = False,
        force: bool = False,
        remove: bool = False,
    ) -> bool:
        """Configure CLAUDE.md with LucidShark proactive scanning instructions.

        CLAUDE.md is loaded into Claude's system prompt for every conversation,
        making it the most reliable way to ensure proactive scanning behavior.
        Uses HTML comment markers to manage the LucidShark section so it can
        be updated or removed without affecting user content.

        Args:
            dry_run: If True, only show what would be done.
            force: If True, overwrite existing LucidShark section.
            remove: If True, remove LucidShark section from CLAUDE.md.

        Returns:
            True if successful.
        """
        claude_md_path = Path.cwd() / ".claude" / "CLAUDE.md"
        start_marker = "<!-- lucidshark:start"
        end_marker = "<!-- lucidshark:end -->"

        print("Configuring .claude/CLAUDE.md...")

        # Read existing content
        existing_content = ""
        if claude_md_path.exists():
            try:
                existing_content = claude_md_path.read_text(encoding="utf-8")
            except Exception as e:
                print(f"  Error reading {claude_md_path}: {e}")
                return False

        has_section = start_marker in existing_content and end_marker in existing_content

        if remove:
            if has_section:
                if dry_run:
                    print(f"  Would remove LucidShark section from {claude_md_path}")
                else:
                    new_content = self._remove_managed_section(
                        existing_content, start_marker, end_marker
                    )
                    try:
                        # If only whitespace remains, remove the file
                        if new_content.strip():
                            claude_md_path.write_text(new_content, encoding="utf-8")
                            print(f"  Removed LucidShark section from {claude_md_path}")
                        else:
                            claude_md_path.unlink()
                            print(f"  Removed {claude_md_path} (was empty after removal)")
                    except Exception as e:
                        print(f"  Error updating {claude_md_path}: {e}")
                        return False
            else:
                print(f"  LucidShark section not found in {claude_md_path}")
            return True

        if has_section and not force:
            print(f"  LucidShark section already exists in {claude_md_path}")
            print("  Use --force to overwrite.")
            return True

        if dry_run:
            action = "update" if has_section else "create"
            print(f"  Would {action} LucidShark section in {claude_md_path}")
            return True

        # Build new content
        if has_section:
            # Replace existing section
            new_content = self._replace_managed_section(
                existing_content,
                start_marker,
                end_marker,
                LUCIDSHARK_CLAUDE_MD_SECTION,
            )
        else:
            # Append to existing content (or create new file)
            new_content = existing_content.rstrip() + "\n" + LUCIDSHARK_CLAUDE_MD_SECTION

        try:
            claude_md_path.parent.mkdir(parents=True, exist_ok=True)
            claude_md_path.write_text(new_content, encoding="utf-8")
            action = "Updated" if has_section else "Added"
            print(f"  {action} LucidShark section in {claude_md_path}")
            return True
        except Exception as e:
            print(f"  Error writing {claude_md_path}: {e}")
            return False

    @staticmethod
    def _process_managed_section(
        content: str,
        start_marker: str,
        end_marker: str,
        replacement: Optional[str] = None,
    ) -> str:
        """Process a managed section delimited by markers.

        Args:
            content: The full file content.
            start_marker: Start of the managed section (prefix match).
            end_marker: End of the managed section (exact line match).
            replacement: If provided, replaces section with this content.
                         If None, section is removed.

        Returns:
            Content with the managed section processed.
        """
        lines = content.split("\n")
        result: List[str] = []
        in_section = False
        replaced = False
        for line in lines:
            if not in_section and start_marker in line:
                in_section = True
                if replacement is not None and not replaced:
                    result.append(replacement.rstrip())
                    replaced = True
            elif in_section and end_marker in line:
                in_section = False
            elif not in_section:
                result.append(line)
        return "\n".join(result)

    @staticmethod
    def _remove_managed_section(content: str, start_marker: str, end_marker: str) -> str:
        """Remove a managed section delimited by markers from content."""
        return InitCommand._process_managed_section(content, start_marker, end_marker)

    @staticmethod
    def _replace_managed_section(
        content: str, start_marker: str, end_marker: str, new_section: str
    ) -> str:
        """Replace a managed section with new content."""
        return InitCommand._process_managed_section(
            content, start_marker, end_marker, new_section
        )

    def _get_claude_code_config_path(self) -> Optional[Path]:
        """Get the Claude Code MCP config file path.

        Returns:
            Path to .mcp.json at project root.
        """
        # Claude Code project-scoped MCP servers in .mcp.json
        return Path.cwd() / ".mcp.json"

    def _read_json_config(self, path: Path) -> Tuple[Dict[str, Any], Optional[str]]:
        """Read a JSON config file.

        Args:
            path: Path to the config file.

        Returns:
            Tuple of (config dict, error message or None).
        """
        if not path.exists():
            return {}, f"Config file does not exist: {path}"

        try:
            with open(path, "r") as f:
                content = f.read().strip()
                if not content:
                    return {}, None
                return json.loads(content), None
        except json.JSONDecodeError as e:
            return {}, f"Invalid JSON in {path}: {e}"
        except Exception as e:
            return {}, f"Error reading {path}: {e}"

    def _write_json_config(self, path: Path, config: Dict[str, Any]) -> bool:
        """Write a JSON config file.

        Args:
            path: Path to the config file.
            config: Configuration dictionary.

        Returns:
            True if successful.
        """
        try:
            with open(path, "w") as f:
                json.dump(config, f, indent=2)
                f.write("\n")
            return True
        except Exception as e:
            print(f"  Error writing {path}: {e}")
            return False

    def _print_available_tools(self) -> None:
        """Print available CLI commands."""
        print("\n  Available commands:")
        print("    lucidshark scan --format ai     # Run quality checks")
        print("    lucidshark scan --fix           # Auto-fix linting issues")
        print("    lucidshark scan --all           # Full scan (all domains)")
        print("    lucidshark status               # Show configuration")
        print("    lucidshark validate             # Validate lucidshark.yml")
        print("    lucidshark help                 # Show documentation")
        print("\n  MCP server:")
        print("    lucidshark serve --mcp          # Run as MCP server")
