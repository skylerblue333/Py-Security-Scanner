# Sky Security Audit

A bounded **offline** Python source-code security auditor for a small set of explicit heuristic rules. It analyzes caller-supplied UTF-8 source files and emits structured findings without making network requests or probing external systems.

## Implemented checks

Current rules flag:
- likely hardcoded password assignments;
- likely hardcoded secret assignments;
- likely hardcoded API-key assignments;
- private-key material markers;
- Python `eval()` usage;
- Python `exec()` usage;
- common subprocess calls using `shell=True`.

Findings contain only severity, rule description/ID, line, and column. The scanner intentionally does **not** copy the matched source text into reports, reducing the chance that a detected credential is leaked again through logs or artifacts.

Source input is bounded to 1,000,000 characters and each scan returns at most 500 findings.

## Usage

```bash
python main.py app.py another_module.py
```

Output is JSON. Exit status is:
- `0` when no findings are produced;
- `1` when one or more findings are produced;
- `2` for file/input errors.

Container usage:

```bash
docker build -t sky-security-audit .
docker run --rm -v "$PWD:/workspace:ro" sky-security-audit /workspace/app.py
```

## Verification

```bash
python -m compileall -q main.py src tests
ruff check main.py src tests
pytest -q
pip-audit -r requirements.txt
```

CI additionally builds the image and verifies non-root execution.

## Security and product boundary

This is a defensive static-analysis helper. It does not crawl websites, enumerate endpoints, send payloads, exploit vulnerabilities, execute target code, or perform network reconnaissance. The old repository demo fabricated web findings such as exposed files; that behavior is removed.

Heuristic pattern matches can produce false positives and false negatives. A clean result is **not** proof that code is secure. The tool is not a replacement for language-aware SAST, secret scanners, dependency scanners, code review, penetration testing, or a security assessment.

## SKYCOIN4444 integration

Sky Security Audit can be used as one lightweight pre-commit/CI signal for Python repositories. Integrations should treat its findings as advisory inputs alongside stronger scanners and review processes rather than as an authorization or release decision by itself.

## Status

**Status: Engineering Beta.** Local implementation and automated verification are being hardened; no production deployment or security certification is claimed.

See `SECURITY.md` and `CHANGELOG.md` for operating boundaries and productization history.
