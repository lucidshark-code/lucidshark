# LucidScan Reference Documentation

LucidScan is a unified code quality tool that combines linting, type checking, security scanning, testing, and coverage analysis into a single pipeline.

## Quick Start

### Installation

```bash
pip install lucidscan
```

### Recommended Setup (AI-Assisted)

```bash
# 1. Set up your AI tools
lucidscan init --all

# 2. Restart Claude Code or Cursor, then ask:
#    "Autoconfigure LucidScan for this project"
```

Your AI assistant will analyze your codebase, ask a few questions, and generate `lucidscan.yml`.

### Alternative: CLI Configuration

```bash
# Auto-detect languages and generate lucidscan.yml
lucidscan autoconfigure

# With CI configuration
lucidscan autoconfigure --ci github

# Non-interactive mode
lucidscan autoconfigure -y
```

### Run Scans

```bash
# Default: scan only changed files (uncommitted changes)
lucidscan scan --lint --type-check

# Full project scan (all domains, all files)
lucidscan scan --all --all-files

# Run specific checks (on changed files by default)
lucidscan scan --lint           # Linting only
lucidscan scan --type-check     # Type checking only
lucidscan scan --sca            # Dependency vulnerabilities (always project-wide)
lucidscan scan --sast           # Code security analysis

# Auto-fix linting issues (on changed files)
lucidscan scan --lint --fix
```

---

## CLI Commands

### `lucidscan init`

Configure AI tools (Claude Code, Cursor) to use LucidScan via MCP.

| Option | Description |
|--------|-------------|
| `--claude-code` | Configure Claude Code MCP settings |
| `--cursor` | Configure Cursor MCP settings |
| `--all` | Configure all supported AI tools |
| `--dry-run` | Show changes without applying |
| `--force` | Overwrite existing configuration |
| `--remove` | Remove LucidScan from tool configuration |

**Examples:**
```bash
lucidscan init --claude-code
lucidscan init --cursor
lucidscan init --all
lucidscan init --claude-code --remove
```

### `lucidscan autoconfigure`

Auto-configure LucidScan for a project. Detects languages, frameworks, and generates `lucidscan.yml`.

| Option | Description |
|--------|-------------|
| `--ci {github,gitlab,bitbucket}` | Generate CI configuration for platform |
| `--non-interactive`, `-y` | Use defaults without prompting |
| `--force`, `-f` | Overwrite existing configuration |
| `path` | Project directory (default: `.`) |

**Examples:**
```bash
lucidscan autoconfigure
lucidscan autoconfigure --ci github --non-interactive
lucidscan autoconfigure /path/to/project -f
```

### `lucidscan scan`

Run the quality/security pipeline. By default, scans only changed files (uncommitted changes).

#### Scan Domains

| Flag | Domain | Description |
|------|--------|-------------|
| `--lint` | Linting | Code style and linting (Ruff, ESLint, Biome, Checkstyle) |
| `--type-check` | Type Checking | Static type analysis (mypy, pyright, TypeScript) |
| `--sca` | SCA | Dependency vulnerability scanning (Trivy) |
| `--sast` | SAST | Code security patterns (OpenGrep) |
| `--iac` | IaC | Infrastructure-as-Code scanning (Checkov) |
| `--container` | Container | Container image scanning (Trivy) |
| `--test` | Testing | Run test suite (pytest, Jest) |
| `--coverage` | Coverage | Coverage analysis (coverage.py, Istanbul) |
| `--all` | All | Enable all domains |

#### Target Options

| Option | Description |
|--------|-------------|
| `--files FILE [FILE ...]` | Specific files to scan (overrides default changed-files behavior) |
| `--all-files` | Scan entire project instead of just changed files |

#### Output Options

| Option | Description |
|--------|-------------|
| `--format {json,table,sarif,summary}` | Output format |

#### Configuration Options

| Option | Description |
|--------|-------------|
| `--fail-on {critical,high,medium,low}` | Failure threshold for security issues |
| `--coverage-threshold PERCENT` | Coverage threshold (default: 80) |
| `--config PATH` | Path to config file |

#### Execution Options

| Option | Description |
|--------|-------------|
| `--sequential` | Disable parallel execution |
| `--fix` | Apply auto-fixes (linting only) |
| `--stream` | Stream tool output in real-time as scans run |
| `--image IMAGE` | Container image to scan (with `--container`) |

**Examples:**
```bash
# Default: scan only changed files (uncommitted changes)
lucidscan scan --lint --type-check

# Full project scan
lucidscan scan --all --all-files

# Scan specific files
lucidscan scan --lint --files src/main.py src/utils.py

# Lint with auto-fix (on changed files)
lucidscan scan --lint --fix

# Full security scan
lucidscan scan --sca --sast --all-files --fail-on high

# Full scan before commit
lucidscan scan --all --all-files --format sarif > results.sarif

# Container scanning
lucidscan scan --container --image myapp:latest

# Stream output during scan
lucidscan scan --all --stream
```

### `lucidscan status`

Show configuration and tool status.

| Option | Description |
|--------|-------------|
| `--tools` | Show installed tool versions |
| `--config` | Show effective configuration |

**Examples:**
```bash
lucidscan status
lucidscan status --tools
```

### `lucidscan serve`

Run LucidScan as a server for AI tool integration.

| Option | Description |
|--------|-------------|
| `--mcp` | Run as MCP server (for Claude Code, Cursor) |
| `--watch` | Watch files and run incremental checks |
| `--port PORT` | HTTP port for status endpoint (default: 7432) |
| `--debounce MS` | File watcher debounce delay (default: 1000) |

**Examples:**
```bash
lucidscan serve --mcp
lucidscan serve --watch
lucidscan serve --watch --debounce 500
```


### `lucidscan help`

Display this documentation.

```bash
lucidscan help
```

### `lucidscan validate`

Validate a `lucidscan.yml` configuration file and report errors/warnings.

| Option | Description |
|--------|-------------|
| `--config PATH` | Path to config file (default: find in current directory) |

**Exit codes:**
- 0: Configuration is valid (may have warnings)
- 1: Configuration has errors
- 3: Configuration file not found

**Examples:**
```bash
lucidscan validate
lucidscan validate --config custom-config.yml
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed |
| 1 | Issues found above threshold |
| 2 | Tool/scanner execution error |
| 3 | Configuration error |
| 4 | Bootstrap/download failure |

---

## MCP Tools Reference

LucidScan exposes these tools via MCP (Model Context Protocol) for AI agent integration:

### `scan`

Run quality checks on the codebase or specific files. Supports partial scanning via the `files` parameter for faster feedback on changed files.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `domains` | array of strings | `["all"]` | Domains to check |
| `files` | array of strings | (none) | Specific files to check (relative paths). When provided, only these files are scanned. |
| `all_files` | boolean | `false` | Scan entire project instead of just changed files. By default, only uncommitted changes are scanned. |
| `fix` | boolean | `false` | Apply auto-fixes for linting issues |

**Valid domains:** `linting`, `type_checking`, `security`, `sca`, `sast`, `iac`, `container`, `testing`, `coverage`, `all`

**Default Behavior:** Partial scanning (changed files only) is the default. Use `all_files=true` for full project scans.

**Partial Scanning Support by Domain:**

| Domain | Partial Scan Support | Behavior |
|--------|---------------------|----------|
| `linting` | ✅ Full support | Only lints specified/changed files |
| `type_checking` | ✅ Partial support | mypy/pyright support file args; TypeScript (tsc) scans full project |
| `sast` | ✅ Full support | OpenGrep scans only specified/changed files |
| `sca` | ❌ Project-wide only | Trivy dependency scan is inherently project-wide |
| `iac` | ❌ Project-wide only | Checkov scans entire project |
| `testing` | ✅ Full support | Can run specific test files (but full suite recommended for coverage) |
| `coverage` | ⚠️ Run full, filter output | Tests run fully, but coverage can be filtered to changed files |

**Response format:**
```json
{
  "total_issues": 5,
  "blocking": true,
  "summary": "5 issues found: 1 critical, 2 high, 2 medium",
  "severity_counts": {"critical": 1, "high": 2, "medium": 2},
  "instructions": [
    {
      "priority": 1,
      "action": "FIX_SECURITY_VULNERABILITY",
      "summary": "Hardcoded password in config.py:23",
      "file": "config.py",
      "line": 23,
      "problem": "Hardcoded credentials detected",
      "fix_steps": ["Remove hardcoded password", "Use environment variable"],
      "issue_id": "security-123"
    }
  ]
}
```

**Examples:**
```
# Default: scan only changed files (uncommitted changes)
scan(domains=["linting", "type_checking"])

# Explicit full project scan
scan(domains=["all"], all_files=true)

# Scan specific files only
scan(domains=["linting", "type_checking"], files=["src/main.py", "src/utils.py"])

# Lint with auto-fix (on changed files by default)
scan(domains=["linting"], fix=true)

# Security scan - SAST scans changed files, SCA always project-wide
scan(domains=["sca", "sast"])
```

### `check_file`

Check a specific file and return issues with fix instructions. This is a convenience wrapper for partial scanning that automatically detects the file type and runs appropriate checks (linting, type checking) for that single file.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `file_path` | string | Yes | Path to file (relative to project root) |

**When to use:**
- Quick feedback on a single file you just modified
- Checking a specific file before committing
- Faster than `scan()` when you only need to check one file

**Example:**
```
check_file(file_path="src/main.py")
```

**Note:** For checking multiple files, use `scan(files=["file1.py", "file2.py"])` instead.

### `get_fix_instructions`

Get detailed fix instructions for a specific issue. Use the `issue_id` from scan results.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `issue_id` | string | Yes | Issue identifier from scan result |

**Example:**
```
get_fix_instructions(issue_id="security-123")
```

### `apply_fix`

Apply auto-fix for a fixable issue. Currently only supports linting issues.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `issue_id` | string | Yes | Issue identifier to fix |

**Example:**
```
apply_fix(issue_id="linting-456")
```

### `get_status`

Get current LucidScan status and configuration.

**Parameters:** None

**Response format:**
```json
{
  "project_root": "/path/to/project",
  "available_tools": {
    "scanners": ["trivy", "opengrep", "checkov"],
    "linters": ["ruff", "eslint", "biome"],
    "type_checkers": ["mypy", "pyright", "typescript"]
  },
  "enabled_domains": ["sca", "sast", "linting"],
  "cached_issues": 5
}
```

### `get_help`

Get this documentation.

**Parameters:** None

**Response format:**
```json
{
  "documentation": "# LucidScan Reference Documentation...",
  "format": "markdown"
}
```

### `autoconfigure`

Get instructions for auto-configuring LucidScan for the project. Returns guidance on what files to analyze and how to generate `lucidscan.yml`. The AI should then read the codebase, read the help docs via `get_help()`, and create the configuration file.

**Parameters:** None

**Response format:**
```json
{
  "instructions": "To configure LucidScan for this project, follow these steps...",
  "analysis_steps": [
    {
      "step": 1,
      "action": "Detect languages and package managers",
      "files_to_check": ["package.json", "pyproject.toml", "Cargo.toml", "go.mod"],
      "what_to_look_for": "Presence of these files indicates the primary language(s)"
    },
    {
      "step": 2,
      "action": "Detect existing tools",
      "files_to_check": [".eslintrc*", "ruff.toml", "tsconfig.json", "mypy.ini"],
      "what_to_look_for": "Existing tool configurations to preserve"
    }
  ],
  "tool_recommendations": {
    "python": {
      "linter": "ruff (recommended)",
      "type_checker": "mypy (recommended)",
      "test_runner": "pytest"
    },
    "javascript_typescript": {
      "linter": "eslint or biome",
      "type_checker": "typescript (tsc)",
      "test_runner": "jest or playwright"
    }
  },
  "security_tools": {
    "always_recommended": ["trivy (SCA)", "opengrep (SAST)"]
  },
  "example_config": {
    "minimal_python": "version: 1\nproject:\n  name: my-project..."
  },
  "post_config_steps": [
    "Run 'lucidscan init --claude-code' to set up AI tool integration",
    "Run 'lucidscan scan --all' to test the configuration"
  ]
}
```

**Usage:**
```
autoconfigure()
```

After calling this tool, the AI should:
1. Check for files mentioned in `analysis_steps` to detect the project type
2. Call `get_help()` to read the full configuration documentation
3. Generate an appropriate `lucidscan.yml` based on detected project characteristics
4. Write the configuration file to the project root
5. Call `validate_config()` to verify the configuration is valid
6. Fix any validation errors before informing the user
7. Inform the user about any tools that need to be installed

### `validate_config`

Validate a `lucidscan.yml` configuration file. Returns validation results with errors and warnings. Use after generating or modifying configuration to ensure it's valid.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config_path` | string | No | Path to config file (relative to project root). Default: find `lucidscan.yml` |

**Response format:**
```json
{
  "valid": true,
  "config_path": "lucidscan.yml",
  "errors": [],
  "warnings": [
    {
      "message": "Unknown key 'output.formatt'",
      "key": "output.formatt",
      "suggestion": "format"
    }
  ]
}
```

**Examples:**
```
validate_config()
validate_config(config_path="lucidscan.yml")
validate_config(config_path="configs/custom.yml")
```

**Validation includes:**
- YAML syntax errors
- Unknown configuration keys (with typo suggestions)
- Type errors (e.g., string where boolean expected)
- Invalid values (e.g., unknown severity level)

**Best practice:** Always call `validate_config()` after generating or modifying `lucidscan.yml` to catch configuration errors early.

---

## Configuration Reference (`lucidscan.yml`)

LucidScan auto-detects your project, but you can customize behavior with `lucidscan.yml` in your project root.

### Complete Configuration Example

```yaml
version: 1

# Project metadata
project:
  name: my-project
  languages:
    - python
    - typescript

# Pipeline configuration
pipeline:
  max_workers: 4  # Parallel execution workers

  linting:
    enabled: true
    tools:
      - name: ruff
        config: ruff.toml  # Optional custom config path
      - name: eslint
      - name: biome
      - name: checkstyle  # For Java projects

  type_checking:
    enabled: true
    tools:
      - name: mypy
        strict: true
      - name: pyright
      - name: typescript

  security:
    enabled: true
    tools:
      - name: trivy
        domains: [sca, container]
      - name: opengrep
        domains: [sast]
      - name: checkov
        domains: [iac]

  testing:
    enabled: true
    tools:
      - name: pytest      # Python unit tests
      - name: jest        # JavaScript/TypeScript tests
      - name: karma       # Angular unit tests (Jasmine)
      - name: playwright  # E2E tests

  coverage:
    enabled: true
    tools: [coverage_py]  # Required: coverage_py for Python, istanbul for JS/TS
    threshold: 80  # Fail if coverage below this

# Failure thresholds (per-domain)
fail_on:
  linting: error      # error, none
  type_checking: error
  security: high      # critical, high, medium, low, info, none
  testing: any        # any, none
  coverage: any       # any, none

# Alternative: single threshold for all security
# fail_on: high

# Files/directories to ignore
ignore:
  - "**/node_modules/**"
  - "**/.venv/**"
  - "**/dist/**"
  - "**/build/**"
  - "**/__pycache__/**"

# Output format
output:
  format: json  # json, table, sarif, summary
```

### Configuration Sections

#### `project`

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Project name |
| `languages` | array | Detected/specified languages |

#### `pipeline`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_workers` | int | 4 | Maximum parallel workers |
| `linting.enabled` | bool | true | Enable linting |
| `linting.tools` | array | (auto) | List of linting tools |
| `type_checking.enabled` | bool | true | Enable type checking |
| `type_checking.tools` | array | (auto) | List of type checkers |
| `security.enabled` | bool | true | Enable security scanning |
| `security.tools` | array | (auto) | Security tools with domains |
| `testing.enabled` | bool | false | Enable test execution |
| `testing.tools` | array | (auto) | Test frameworks |
| `coverage.enabled` | bool | false | Enable coverage analysis |
| `coverage.tools` | array | **required** | Coverage tools (coverage_py, istanbul) |
| `coverage.threshold` | int | 80 | Coverage percentage threshold |

#### Tool Configuration

Each tool in a pipeline section can have:

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Tool identifier (ruff, mypy, trivy, etc.) |
| `config` | string | Path to tool-specific config file |
| `strict` | bool | Enable strict mode (type checkers) |
| `domains` | array | Security domains for scanner (sca, sast, iac, container) |
| `options` | object | Tool-specific options (passed through) |

#### `fail_on`

Per-domain failure thresholds:

| Domain | Valid Values |
|--------|--------------|
| `linting` | `error`, `none` |
| `type_checking` | `error`, `none` |
| `security` | `critical`, `high`, `medium`, `low`, `info`, `none` |
| `testing` | `any`, `none` |
| `coverage` | `any`, `none` |

#### `ignore`

Array of glob patterns for files/directories to skip:

```yaml
ignore:
  - "**/node_modules/**"
  - "**/.venv/**"
  - "**/test_*.py"
```

### Config File Locations

LucidScan searches for configuration in this order:

1. CLI `--config PATH` flag
2. Project root: `.lucidscan.yml`, `.lucidscan.yaml`, `lucidscan.yml`, `lucidscan.yaml`
3. Global: `~/.lucidscan/config/config.yml`
4. Built-in defaults

### Environment Variable Expansion

Use `${VAR}` or `${VAR:-default}` syntax in configuration:

```yaml
project:
  name: ${PROJECT_NAME:-my-project}
```

---

## AI Tool Setup

### Claude Code

```bash
lucidscan init --claude-code
```

This creates:
- `.mcp.json` - MCP server configuration
- `.claude/CLAUDE.md` - Instructions for Claude

Or manually create `.mcp.json`:
```json
{
  "mcpServers": {
    "lucidscan": {
      "command": ".venv/bin/lucidscan",
      "args": ["serve", "--mcp"]
    }
  }
}
```

### Cursor

```bash
lucidscan init --cursor
```

This creates:
- `~/.cursor/mcp.json` - MCP server configuration
- `.cursor/rules/lucidscan.mdc` - Cursor rules

Or manually add to `~/.cursor/mcp.json`:
```json
{
  "mcpServers": {
    "lucidscan": {
      "command": "lucidscan",
      "args": ["serve", "--mcp"]
    }
  }
}
```

---

## Best Practices for AI Agents

### Recommended Workflow

1. **After code changes**: Run scan (automatically checks only changed files)
   ```
   scan(domains=["linting", "type_checking"])
   ```

2. **Before commit**: Run full scan (comprehensive)
   ```
   scan(domains=["all"], all_files=true)
   ```

3. **To fix issues**: Use auto-fix (on changed files by default)
   ```
   scan(domains=["linting"], fix=true)
   ```

4. **For detailed guidance**: Get fix instructions
   ```
   get_fix_instructions(issue_id="...")
   ```

### Default Partial Scanning

LucidScan scans only changed files (uncommitted changes) by default. This is the recommended workflow:

| Scenario | Approach | Example |
|----------|----------|---------|
| After editing files | Default scan | `scan(domains=["linting", "type_checking"])` — scans changed files automatically |
| Quick single-file check | Use check_file | `check_file(file_path="src/main.py")` |
| Scan specific files | Use files param | `scan(domains=["linting"], files=["src/a.py", "src/b.py"])` |
| Before commit | Full scan | `scan(domains=["all"], all_files=true)` |
| Security audit | Full scan | `scan(domains=["sca", "sast", "iac"], all_files=true)` |

**Note:** SCA (dependency scanning) always runs project-wide. SAST (OpenGrep) and most other tools scan only changed files by default.

### Domain Selection Guidelines

| Scenario | Recommended Domains |
|----------|---------------------|
| Quick style check | `["linting"]` (scans changed files by default) |
| After editing Python | `["linting", "type_checking"]` |
| After editing TypeScript | `["linting", "type_checking"]` |
| Before commit | `["all"]` with `all_files=true` |
| Security audit | `["sca", "sast", "iac"]` with `all_files=true` |
| Pre-release | `["all"]` with `all_files=true` and `fix=true` for linting |

### Handling Issues

1. **Priority order**: Fix high-priority issues first (priority 1-2)
2. **Auto-fixable**: Use `apply_fix()` for linting issues
3. **Manual fixes**: Follow `fix_steps` from instructions
4. **Re-scan**: Always re-scan after fixes to verify

### Performance Tips

- **Default is fast**: Just call `scan()` — it automatically scans only changed files
- **Use `check_file()`**: For single-file checks, this is the fastest option
- **Reserve full scans for commits**: Use `all_files=true` only before committing
- **SCA is always full**: Dependency scanning requires full project context
- **Auto-fix is smart**: `scan(domains=["linting"], fix=true)` fixes only changed files

---

## Supported Tools

### Linting

| Tool | Languages | Partial Scan |
|------|-----------|--------------|
| Ruff | Python | ✅ Yes |
| ESLint | JavaScript, TypeScript | ✅ Yes |
| Biome | JavaScript, TypeScript, JSON | ✅ Yes |
| Checkstyle | Java | ✅ Yes |

All linting tools support the `files` parameter for partial scanning.

### Type Checking

| Tool | Languages | Partial Scan |
|------|-----------|--------------|
| mypy | Python | ✅ Yes |
| pyright | Python | ✅ Yes |
| TypeScript (tsc) | TypeScript | ❌ No (project-wide only) |

**Note:** TypeScript (tsc) does not support file-level scanning — it always analyzes the full project based on `tsconfig.json`.

### Security Scanning

| Tool | Domains | Partial Scan |
|------|---------|--------------|
| Trivy | SCA (dependencies), Container images | ❌ No (project-wide) |
| OpenGrep | SAST (code patterns) | ✅ Yes |
| Checkov | IaC (Terraform, K8s, CloudFormation) | ❌ No (project-wide) |

**Note:** OpenGrep (SAST) supports partial scanning and will scan only changed files by default. Trivy (SCA) and Checkov (IaC) always scan the entire project — dependency analysis requires full project context.

### Testing

| Tool | Languages | Partial Scan |
|------|-----------|--------------|
| pytest | Python | ✅ Yes |
| Jest | JavaScript, TypeScript | ✅ Yes |
| Karma | JavaScript, TypeScript (Angular) | ❌ No (config-based) |
| Playwright | JavaScript, TypeScript (E2E) | ✅ Yes |

**Note:** While test runners support running specific test files, it's recommended to run the full test suite before commits to catch regressions.

### Coverage

| Tool | Languages | Partial Scan |
|------|-----------|--------------|
| coverage.py | Python | ⚠️ Partial (filter output) |
| Istanbul/nyc | JavaScript, TypeScript | ⚠️ Partial (filter output) |

**Note:** Coverage tools run the full test suite but can filter the coverage report to show only changed files.
