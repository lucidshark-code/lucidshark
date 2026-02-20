# C++

**Support tier: Basic**

C++ projects are detected and benefit from security scanning and duplication detection.

## Detection

| Method | Indicators |
|--------|-----------|
| **File extensions** | `.cpp`, `.cc`, `.cxx`, `.hpp` |

## Tools by Domain

| Domain | Tool | Notes |
|--------|------|-------|
| **Security (SAST)** | OpenGrep | C++-specific vulnerability rules |
| **Duplication** | Duplo | Scans `.cpp`, `.cc`, `.cxx`, `.hpp` files |

## Security

OpenGrep includes SAST rules for C++ code.

## Duplication

Duplo scans C++ source and header files for duplicate code blocks.

```yaml
pipeline:
  duplication:
    enabled: true
    threshold: 5.0
```

## Not Yet Supported

The following domains do not yet have C++-specific tools:

- **Linting** -- no dedicated C++ linter integrated yet
- **Type Checking** -- no C++ static analyzer integrated yet
- **Testing** -- no C++ test runner integrated yet
- **Coverage** -- no C++ coverage tool integrated yet
- **Security (SCA)** -- no C++ dependency scanner integrated yet

## Example Configuration

```yaml
version: 1
project:
  languages: [c++]
pipeline:
  security:
    enabled: true
    tools: [{ name: opengrep }]
  duplication:
    enabled: true
    threshold: 5.0
```

## See Also

- [C](c.md) -- related language with similar support
- [Supported Languages Overview](README.md)
