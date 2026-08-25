# Security Policy

## Scope

Sky Security Audit is a defensive, offline heuristic source scanner. It reads local UTF-8 files supplied by the operator. It does not perform network scanning, exploitation, credential testing, endpoint enumeration, or remote code execution.

## Handling sensitive findings

Reports intentionally omit matched source excerpts so a detected password, key, or secret is not copied into CI logs or generated reports. Operators should still treat source files and findings as sensitive development data.

## Limitations

Pattern matching is incomplete and may report false positives or miss real vulnerabilities. A zero-finding result is not a security certification. Use language-aware SAST, dedicated secret scanning, dependency analysis, review, and authorized testing as appropriate for the system being evaluated.

## Reporting vulnerabilities

Use GitHub private vulnerability reporting when enabled. Do not publish credentials, private keys, or other sensitive values in issues.
