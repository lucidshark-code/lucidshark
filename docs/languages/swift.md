# Swift

**Support tier: Minimal**

Swift projects are detected and benefit from security scanning.

## Detection

| Method | Indicators |
|--------|-----------|
| **File extensions** | `.swift` |

## Tools by Domain

| Domain | Tool | Notes |
|--------|------|-------|
| **Security (SAST)** | OpenGrep | Swift-specific vulnerability rules |

## Security

OpenGrep includes SAST rules for Swift code.

## Not Yet Supported

The following domains do not yet have Swift-specific tools:

- **Linting** -- no dedicated Swift linter (e.g., SwiftLint) integrated yet
- **Type Checking** -- Swift's compiler handles type safety; no separate tool integrated
- **Testing** -- no Swift test runner (e.g., XCTest) integrated yet
- **Coverage** -- no Swift coverage tool integrated yet
- **Duplication** -- Duplo does not currently support Swift files
- **Security (SCA)** -- no Swift dependency scanner integrated yet

## Example Configuration

```yaml
version: 1
project:
  languages: [swift]
pipeline:
  security:
    enabled: true
    tools: [{ name: opengrep }]
```

## See Also

- [Supported Languages Overview](README.md)
