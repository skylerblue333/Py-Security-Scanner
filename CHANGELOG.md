# Changelog

## Unreleased

### Added
- Bounded offline source scanning with explicit defensive rules.
- Finding rule IDs, severity, line, and column metadata.
- Source-size and finding-count limits.
- CLI JSON reporting and exit-code contract.
- Tests for credential-value redaction, rule detection, clean input, and bounds.
- Ruff, pytest, dependency-audit, container-build, and non-root CI gates.
- Security and SKYCOIN4444 integration documentation.

### Changed
- Removed fabricated web-header/endpoint findings from the original demo.
- Reports no longer contain matched source excerpts that could re-expose secrets.
- Reduced runtime dependencies to the Python standard library.

### Known limitations
- Heuristic Python-oriented patterns only.
- No AST/data-flow analysis, dependency scanning, network scanning, exploitation, or security certification.
