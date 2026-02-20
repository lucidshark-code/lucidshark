# PHP

**Support tier: Minimal**

PHP projects are detected and benefit from security scanning.

## Detection

| Method | Indicators |
|--------|-----------|
| **File extensions** | `.php` |
| **Marker files** | `composer.json` |

## Tools by Domain

| Domain | Tool | Notes |
|--------|------|-------|
| **Security (SAST)** | OpenGrep | PHP-specific vulnerability rules |
| **Security (SCA)** | Trivy | Scans `composer.lock` |

## Security

OpenGrep includes SAST rules for PHP code, covering common web vulnerability patterns like SQL injection, XSS, and file inclusion.

Trivy SCA scans PHP manifests: `composer.lock`.

## Not Yet Supported

The following domains do not yet have PHP-specific tools:

- **Linting** -- no dedicated PHP linter (e.g., PHP_CodeSniffer, PHPStan) integrated yet
- **Type Checking** -- no PHP static analyzer (e.g., Psalm) integrated yet
- **Testing** -- no PHP test runner (e.g., PHPUnit) integrated yet
- **Coverage** -- no PHP coverage tool integrated yet
- **Duplication** -- Duplo does not currently support PHP files

## Example Configuration

```yaml
version: 1
project:
  languages: [php]
pipeline:
  security:
    enabled: true
    tools: [{ name: trivy }, { name: opengrep }]
```

## See Also

- [Supported Languages Overview](README.md)
