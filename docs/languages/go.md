# Go

**Support tier: Basic**

Go projects are detected and benefit from security scanning and duplication detection.

## Detection

| Method | Indicators |
|--------|-----------|
| **File extensions** | `.go` |
| **Marker files** | `go.mod` |
| **Version detection** | `go` directive from `go.mod` |

## Tools by Domain

| Domain | Tool | Notes |
|--------|------|-------|
| **Security (SAST)** | OpenGrep | Go-specific vulnerability rules |
| **Security (SCA)** | Trivy | Scans `go.sum`, `go.mod` |
| **Duplication** | Duplo | Scans `.go` files |

## Security

Security tools (OpenGrep, Trivy, Checkov) are language-agnostic. See the domain-specific sections in the [main documentation](../main.md) for details.

Trivy SCA scans these Go manifests: `go.sum`, `go.mod`.

## Duplication

Duplo scans `.go` files for duplicate code blocks.

```yaml
pipeline:
  duplication:
    enabled: true
    threshold: 5.0
```

## Not Yet Supported

The following domains do not yet have Go-specific tools:

- **Linting** -- no dedicated Go linter (e.g., golangci-lint) integrated yet
- **Type Checking** -- Go's compiler handles type safety; no separate tool integrated
- **Testing** -- no `go test` runner integrated yet
- **Coverage** -- no Go coverage tool integrated yet

## Example Configuration

```yaml
version: 1
project:
  languages: [go]
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
