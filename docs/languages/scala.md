# Scala

**Support tier: Minimal**

Scala projects are detected and benefit from security scanning.

## Detection

| Method | Indicators |
|--------|-----------|
| **File extensions** | `.scala` |

## Tools by Domain

| Domain | Tool | Notes |
|--------|------|-------|
| **Security (SAST)** | OpenGrep | Scala-specific vulnerability rules |

## Security

OpenGrep includes SAST rules for Scala code.

## Not Yet Supported

The following domains do not yet have Scala-specific tools:

- **Linting** -- no dedicated Scala linter (e.g., Scalastyle, Scalafix) integrated yet
- **Type Checking** -- Scala's compiler handles type safety; no separate tool integrated
- **Testing** -- no Scala test runner (e.g., ScalaTest, specs2) integrated yet
- **Coverage** -- no Scala coverage tool integrated yet
- **Duplication** -- Duplo does not currently support Scala files
- **Security (SCA)** -- no Scala dependency scanner integrated yet

## Example Configuration

```yaml
version: 1
project:
  languages: [scala]
pipeline:
  security:
    enabled: true
    tools: [{ name: opengrep }]
```

## See Also

- [Java](java.md) -- related JVM language with full support
- [Supported Languages Overview](README.md)
