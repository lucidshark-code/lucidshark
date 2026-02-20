# Rust

**Support tier: Basic**

Rust projects are detected and benefit from security scanning and duplication detection.

## Detection

| Method | Indicators |
|--------|-----------|
| **File extensions** | `.rs` |
| **Marker files** | `Cargo.toml` |
| **Version detection** | `edition` from `Cargo.toml` |

## Tools by Domain

| Domain | Tool | Notes |
|--------|------|-------|
| **Security (SAST)** | OpenGrep | Rust-specific vulnerability rules |
| **Security (SCA)** | Trivy | Scans `Cargo.lock` |
| **Duplication** | Duplo | Scans `.rs` files |

## Security

Security tools (OpenGrep, Trivy, Checkov) are language-agnostic. See the domain-specific sections in the [main documentation](../main.md) for details.

Trivy SCA scans Rust manifests: `Cargo.lock`.

## Duplication

Duplo scans `.rs` files for duplicate code blocks.

```yaml
pipeline:
  duplication:
    enabled: true
    threshold: 5.0
```

## Not Yet Supported

The following domains do not yet have Rust-specific tools:

- **Linting** -- no dedicated Rust linter (e.g., clippy) integrated yet
- **Type Checking** -- Rust's compiler handles type safety; no separate tool integrated
- **Testing** -- no `cargo test` runner integrated yet
- **Coverage** -- no Rust coverage tool integrated yet

## Example Configuration

```yaml
version: 1
project:
  languages: [rust]
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
