# C#

**Support tier: Basic**

C# projects are detected and benefit from security scanning and duplication detection.

## Detection

| Method | Indicators |
|--------|-----------|
| **File extensions** | `.cs` |

## Tools by Domain

| Domain | Tool | Notes |
|--------|------|-------|
| **Security (SAST)** | OpenGrep | C#-specific vulnerability rules |
| **Duplication** | Duplo | Scans `.cs` files |

## Security

OpenGrep includes SAST rules for C# code, covering common .NET vulnerability patterns.

## Duplication

Duplo scans `.cs` files for duplicate code blocks.

```yaml
pipeline:
  duplication:
    enabled: true
    threshold: 5.0
```

## Not Yet Supported

The following domains do not yet have C#-specific tools:

- **Linting** -- no dedicated C# linter integrated yet
- **Type Checking** -- no C# static analyzer integrated yet
- **Testing** -- no .NET test runner integrated yet
- **Coverage** -- no C# coverage tool integrated yet
- **Security (SCA)** -- no NuGet dependency scanner integrated yet

## Example Configuration

```yaml
version: 1
project:
  languages: [csharp]
pipeline:
  security:
    enabled: true
    tools: [{ name: opengrep }]
  duplication:
    enabled: true
    threshold: 5.0
```

## See Also

- [Supported Languages Overview](README.md)
