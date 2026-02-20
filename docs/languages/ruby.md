# Ruby

**Support tier: Basic**

Ruby projects are detected and benefit from security scanning and duplication detection.

## Detection

| Method | Indicators |
|--------|-----------|
| **File extensions** | `.rb` |
| **Marker files** | `Gemfile` |

## Tools by Domain

| Domain | Tool | Notes |
|--------|------|-------|
| **Security (SAST)** | OpenGrep | Ruby-specific vulnerability rules |
| **Security (SCA)** | Trivy | Scans `Gemfile.lock` |
| **Duplication** | Duplo | Scans `.rb` files |

## Security

Security tools (OpenGrep, Trivy, Checkov) are language-agnostic. See the domain-specific sections in the [main documentation](../main.md) for details.

Trivy SCA scans Ruby manifests: `Gemfile.lock`.

## Duplication

Duplo scans `.rb` files for duplicate code blocks.

```yaml
pipeline:
  duplication:
    enabled: true
    threshold: 5.0
```

## Not Yet Supported

The following domains do not yet have Ruby-specific tools:

- **Linting** -- no dedicated Ruby linter (e.g., RuboCop) integrated yet
- **Type Checking** -- no Ruby type checker (e.g., Sorbet) integrated yet
- **Testing** -- no Ruby test runner (e.g., RSpec, Minitest) integrated yet
- **Coverage** -- no Ruby coverage tool integrated yet

## Example Configuration

```yaml
version: 1
project:
  languages: [ruby]
pipeline:
  security:
    enabled: true
    tools: [{ name: trivy }, { name: opengrep }]
  duplication:
    enabled: true
    threshold: 5.0
```

## See Also

- [Supported Languages Overview](README.md)
