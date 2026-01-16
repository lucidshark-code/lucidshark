# LucidScan Roadmap

> **Vision**: The trust layer for AI-assisted development

LucidScan unifies code quality tools (linting, type checking, security, testing, coverage) into a single pipeline that auto-configures for any project and integrates with AI coding tools like Claude Code and Cursor.

---

## Roadmap Overview

```
    v0.1-v0.5        NEXT UP           v0.6-v0.8           v0.9              v1.0
        |               |                  |                 |                 |
   ─────●───────────────●──────────────────●─────────────────●─────────────────●─────
        |               |                  |                 |                 |
    COMPLETE        Partial            Language           CI/CD           Production
                     Scans            Expansion        Integration           Ready

  ┌─────────────┐ ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
  │ Core        │ │ Git-aware   │  │ 5 Languages │  │ GitHub      │  │ Docs        │
  │ Security    │ │ Default to  │  │ 2 tools per │  │ Actions     │  │ Performance │
  │ MCP Server  │ │ changed     │  │ domain      │  │ GitLab CI   │  │ Stability   │
  │ AI Tools    │ │ files only  │  │ Go, C#      │  │ Pre-commit  │  │             │
  └─────────────┘ └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘
```

---

## Completed (v0.1 - v0.5)

All foundational work is complete. LucidScan is a fully functional code quality platform with AI integration.

### What's Built

| Component | Details |
|-----------|---------|
| **Core Framework** | CLI with subcommands, plugin system, pipeline orchestrator, configuration system |
| **Security Scanning** | Trivy (SCA, Container), OpenGrep (SAST), Checkov (IaC) |
| **Linting** | Ruff (Python), ESLint (JS/TS), Biome (JS/TS), Checkstyle (Java) |
| **Type Checking** | mypy (Python), pyright (Python), TypeScript (tsc) |
| **Testing** | pytest (Python), Jest (JS/TS), Karma (Angular), Playwright (E2E) |
| **Coverage** | coverage.py (Python), Istanbul (JS/TS) |
| **AI Integration** | MCP server, file watcher, structured AI instructions |
| **Output** | JSON, Table, SARIF, Summary reporters |

### Current Language Support

| Language | Linting | Type Checking | Testing | Coverage |
|----------|---------|---------------|---------|----------|
| Python | Ruff | mypy, pyright | pytest | coverage.py |
| JavaScript/TypeScript | ESLint, Biome | TypeScript | Jest | Istanbul |
| Java | Checkstyle | — | — | — |

### Commands Available Today

```bash
lucidscan init --claude-code         # Configure Claude Code
lucidscan init --cursor              # Configure Cursor
lucidscan autoconfigure              # Generate lucidscan.yml
lucidscan scan --all                 # Run complete pipeline
lucidscan scan --lint --fix          # Lint with auto-fix
lucidscan scan --type-check          # Type checking
lucidscan scan --test --coverage     # Tests with coverage
lucidscan serve --mcp                # MCP server for AI tools
lucidscan status                     # Show tool status
```

---

## Next Priority — Partial Scans (Git-Aware Scanning)

**Goal**: Make scanning smarter by defaulting to only changed files

### Problem

Currently, LucidScan scans the entire project by default. For large codebases, this is slow and produces noise from files the developer hasn't touched. AI coding assistants (Claude Code, Cursor) primarily care about the code they just modified.

### Solution

Change the default behavior:
1. **Git projects**: Scan only uncommitted changes (staged + unstaged files)
2. **Non-git projects**: Fall back to full project scan
3. **Explicit full scan**: Add `--all-files` flag when full scan is needed

### Implementation

| Component | Change |
|-----------|--------|
| **CLI** | `lucidscan scan` defaults to changed files; add `--all-files` flag for full scan |
| **MCP Server** | `scan()` defaults to changed files; add `all_files` parameter |
| **Git Integration** | Detect git repo, get list of uncommitted files (staged + modified + untracked) |
| **Fallback** | If not a git repo or git unavailable, scan entire project |

### User Experience

```bash
# Default: scan only changed files (git diff + untracked)
lucidscan scan --lint --type-check

# Explicit full project scan
lucidscan scan --lint --type-check --all-files

# Still works: explicit file list
lucidscan scan --lint --files src/foo.py src/bar.py
```

### MCP Server

```python
# Default: scan changed files only
scan(domains=["linting", "type_checking"])

# Full project scan
scan(domains=["linting", "type_checking"], all_files=True)

# Explicit file list (unchanged)
scan(domains=["linting"], files=["src/foo.py"])
```

### Key Behaviors

| Scenario | Behavior |
|----------|----------|
| Git repo with uncommitted changes | Scan only changed files |
| Git repo with no changes | Report "no files to scan" (or scan all if `--all-files`) |
| Not a git repo | Scan entire project |
| Explicit `--files` provided | Scan specified files (ignore git status) |
| Explicit `--all-files` flag | Scan entire project |

### Domain-Specific Behavior

Not all domains can be partial — some must run in full to be meaningful:

| Domain | Partial Scan Behavior |
|--------|----------------------|
| **Linting** | Only lint changed files |
| **Type Checking** | Only type-check changed files |
| **Security (SAST)** | Only scan changed files |
| **Security (SCA)** | Always full scan (dependency analysis) |
| **Security (IaC)** | Only scan changed IaC files |
| **Testing** | **Always run full test suite** (to catch regressions) |
| **Coverage** | Run full tests, but **only report coverage for changed files** |

The key insight: tests must run in full because a change in `foo.py` might break tests in `test_bar.py`. But coverage reporting focuses on the changed files — developers care about coverage of code they just wrote, not the entire codebase.

### Tool-Level Partial Scan Support

Not all tools support file-level scanning. Here's the detailed breakdown:

#### Linting Tools

| Tool | Supports File Args | Implementation | Notes |
|------|-------------------|----------------|-------|
| **Ruff** | ✅ Yes | `ruff check [files...]` | Full support, files passed directly to CLI |
| **ESLint** | ✅ Yes | `eslint [files...]` | Full support, files passed directly to CLI |
| **Biome** | ✅ Yes | `biome lint [files...]` | Full support, files passed directly to CLI |
| **Checkstyle** | ✅ Yes | `java -jar checkstyle.jar [files...]` | Auto-discovers .java files in specified dirs |

#### Type Checking Tools

| Tool | Supports File Args | Implementation | Notes |
|------|-------------------|----------------|-------|
| **mypy** | ✅ Yes | `mypy [files...]` | Full support, supports `--exclude` patterns |
| **Pyright** | ✅ Yes | `pyright [files...]` | Full support, config via pyrightconfig.json |
| **TypeScript (tsc)** | ❌ No | `tsc --noEmit` | **No CLI file args** — uses tsconfig.json only |

#### Security Tools

| Tool | Supports File Args | Implementation | Notes |
|------|-------------------|----------------|-------|
| **OpenGrep** (SAST) | ❌ No | `opengrep scan <project_root>` | Project-wide only, ignores file list |
| **Trivy** (SCA) | ❌ No | `trivy fs <project_root>` | Dependency scan is inherently project-wide |
| **Trivy** (Container) | N/A | `trivy image <image>` | Scans container images, not files |
| **Checkov** (IaC) | ❌ No | `checkov --directory <project_root>` | Project-wide only, ignores file list |

#### Testing Tools

| Tool | Supports File Args | Implementation | Notes |
|------|-------------------|----------------|-------|
| **pytest** | ✅ Yes | `pytest [files...]` | Full support (but tests should run in full) |
| **Jest** | ✅ Yes | `jest [files...]` | Full support (but tests should run in full) |
| **Playwright** | ✅ Yes | `playwright test [files...]` | Full support (but E2E tests should run in full) |
| **Karma** | ❌ No | `karma start` | Uses karma.conf.js only, no CLI file args |

#### Coverage Tools

| Tool | Supports File Args | Implementation | Notes |
|------|-------------------|----------------|-------|
| **coverage.py** | ⚠️ Partial | `coverage run -m pytest [tests...]` | Can run specific tests, but measures all executed code |
| **Istanbul/NYC** | ❌ No | `nyc jest` | Project-wide measurement only |

### Partial Scan Strategy by Tool

Given tool limitations, here's how partial scans will work:

| Tool | Partial Scan Strategy |
|------|----------------------|
| **Ruff, ESLint, Biome, Checkstyle** | Pass changed files directly ✅ |
| **mypy, Pyright** | Pass changed files directly ✅ |
| **TypeScript (tsc)** | Must run full project (tool limitation) |
| **OpenGrep, Trivy, Checkov** | Must run full project (tool limitation) |
| **pytest, Jest, Playwright** | Run full suite, filter coverage output |
| **Karma** | Must run full project (tool limitation) |
| **coverage.py** | Run full tests, filter report to changed files |
| **Istanbul/NYC** | Run full tests, filter report to changed files |

### Summary

| Category | Partial Scan Support |
|----------|---------------------|
| **Linting** | ✅ All tools support file args |
| **Type Checking** | ⚠️ mypy/Pyright yes, tsc no |
| **Security** | ❌ No tools support file args (by design) |
| **Testing** | ⚠️ Most support file args, but should run full anyway |
| **Coverage** | ⚠️ Run full, filter output to changed files |

### Benefits

- **Faster scans**: Only check what changed
- **Less noise**: No issues from untouched legacy code
- **AI-friendly**: Perfect for AI coding assistants that modify specific files
- **Backwards compatible**: `--all-files` restores old behavior

---

## v0.6 - v0.8 — Language Expansion

**Goal**: Support 5 popular languages with 2 tools per domain each

### Target Language Matrix

| Language | Linting | Type Checking | Testing | Coverage |
|----------|---------|---------------|---------|----------|
| **Python** | Ruff, Flake8 | mypy, pyright | pytest, unittest | coverage.py |
| **JS/TS** | ESLint, Biome | TypeScript (tsc) | Jest, Vitest | Istanbul, c8 |
| **Java** | Checkstyle, SpotBugs | (compiler) | JUnit, TestNG | JaCoCo, Cobertura |
| **Go** | golangci-lint, staticcheck | (compiler) | go test, testify | go cover |
| **C#** | StyleCop, Roslyn | (compiler) | xUnit, NUnit | Coverlet, dotCover |

### Implementation by Version

#### v0.6 — Complete Python & JS/TS

| Task | Status |
|------|--------|
| Flake8 linter plugin | Planned |
| unittest test runner plugin | Planned |
| Vitest test runner plugin | Planned |
| c8 coverage plugin | Planned |

#### v0.7 — Complete Java & Add Go

| Task | Status |
|------|--------|
| SpotBugs linter plugin | Planned |
| JUnit test runner plugin | Planned |
| TestNG test runner plugin | Planned |
| JaCoCo coverage plugin | Planned |
| Cobertura coverage plugin | Planned |
| Go language detection | Planned |
| golangci-lint plugin | Planned |
| staticcheck plugin | Planned |
| go test integration | Planned |
| go cover integration | Planned |

#### v0.8 — Add C#

| Task | Status |
|------|--------|
| C# language detection | Planned |
| StyleCop linter plugin | Planned |
| Roslyn analyzer plugin | Planned |
| xUnit test runner plugin | Planned |
| NUnit test runner plugin | Planned |
| Coverlet coverage plugin | Planned |
| dotCover coverage plugin | Planned |

### Security Domains (Unchanged)

Security scanning remains the same across all languages:
- **SCA**: Trivy (dependency vulnerabilities)
- **SAST**: OpenGrep (code patterns)
- **IaC**: Checkov (infrastructure as code)
- **Container**: Trivy (image scanning)

---

## v0.9 — CI Integration

**Goal**: Native CI/CD pipeline support for automated quality gates

### Key Deliverables

| Feature | Description |
|---------|-------------|
| **GitHub Actions** | Generate `.github/workflows/lucidscan.yml` |
| **GitLab CI** | Generate `.gitlab-ci.yml` with LucidScan job |
| **Pre-commit hooks** | Integration with pre-commit framework |
| **SARIF upload** | Automatic upload to GitHub Security tab |
| **CI output mode** | Optimized output for CI environments |
| **Exit codes** | Clear pass/fail for pipeline gating |

### User Experience

```bash
# Generate CI configuration
lucidscan init --github-actions      # Create GitHub workflow
lucidscan init --gitlab-ci           # Create GitLab CI config
lucidscan init --pre-commit          # Add to .pre-commit-config.yaml

# CI-optimized scanning
lucidscan scan --all --ci            # CI mode with proper exit codes
lucidscan scan --all --sarif-upload  # Upload results to GitHub
```

### Generated GitHub Actions Workflow

```yaml
# .github/workflows/lucidscan.yml
name: LucidScan
on: [push, pull_request]

jobs:
  quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install LucidScan
        run: pip install lucidscan
      - name: Run quality checks
        run: lucidscan scan --all --format sarif --output results.sarif
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

---

## v1.0 — Production Ready

**Goal**: Polish, stability, and comprehensive documentation

### Key Deliverables

| Feature | Description |
|---------|-------------|
| **Documentation** | Complete user guide, API reference, plugin development guide |
| **Performance** | Incremental checking, result caching, parallel execution |
| **Stability** | Error handling, graceful degradation, clear error messages |
| **Distribution** | PyPI, Docker image, Homebrew formula |

### Success Criteria

- [ ] Complete documentation with examples
- [ ] Performance optimized for large codebases (10k+ files)
- [ ] Stable API (no breaking changes in 1.x)
- [ ] Production use validated by early adopters

---

## Future Considerations

Beyond v1.0, potential directions include:

| Direction | Description |
|-----------|-------------|
| **More languages** | Rust, PHP, Kotlin, Swift |
| **VS Code extension** | Native IDE integration beyond MCP |
| **Team features** | Shared configs, policy enforcement, dashboards |
| **Custom rules** | User-defined linting and security rules |
| **Cloud service** | Optional SaaS for team management |

These are not committed — they depend on user feedback and adoption.

---

## Changelog

| Version | Status | Highlights |
|---------|--------|------------|
| v0.1-v0.5 | Complete | Core framework, security scanning, linting, type checking, testing, coverage, MCP server, AI integration |
| **Next** | **Priority** | **Partial scans: default to git changed files only (CLI + MCP)** |
| v0.6 | Planned | Complete Python (Flake8, unittest) and JS/TS (Vitest, c8) tool coverage |
| v0.7 | Planned | Complete Java (SpotBugs, JUnit, TestNG, JaCoCo, Cobertura) and add Go support |
| v0.8 | Planned | Add C# support (StyleCop, Roslyn, xUnit, NUnit, Coverlet, dotCover) |
| v0.9 | Planned | CI integration (GitHub Actions, GitLab CI, pre-commit) |
| v1.0 | Planned | Production ready (docs, performance, stability) |

---

## Contributing

See the [full specification](main.md) for detailed technical requirements.

To contribute:
1. Pick an item from the current milestone
2. Open an issue to discuss approach
3. Submit a PR

We welcome contributions for:
- New tool plugins (especially Go and C#)
- CI integration templates
- Documentation improvements
- Bug fixes and testing
