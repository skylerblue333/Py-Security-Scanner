import pytest

from src.scanner import MAX_SOURCE_CHARS, scan_code


def test_detects_hardcoded_password_without_leaking_value():
    secret = "hunter2-secret"
    findings = scan_code(f'password = "{secret}"')
    assert any(f.rule == "Hardcoded password" for f in findings)
    assert secret not in repr(findings)


def test_detects_eval_exec_and_shell_true():
    code = "result = eval(user_input)\nexec(source)\nsubprocess.run(command, shell=True)"
    rule_ids = {finding.rule_id for finding in scan_code(code)}
    assert {"PY101", "PY102", "PY103"}.issubset(rule_ids)


def test_detects_multiline_shell_true():
    code = "subprocess.run(\n    command,\n    shell=True,\n)\n"
    findings = [finding for finding in scan_code(code) if finding.rule_id == "PY103"]
    assert len(findings) == 1
    assert findings[0].line == 1
    assert findings[0].column == 1


def test_detects_subprocess_aliases():
    code = "import subprocess as sp\nsp.run(command, shell=True)\n"
    findings = [finding for finding in scan_code(code) if finding.rule_id == "PY103"]
    assert len(findings) == 1
    assert findings[0].line == 2
    assert findings[0].column == 1


def test_preserves_shell_detection_when_ast_parse_fails():
    code = "subprocess.run(command, shell=True)\nif (\n"
    findings = [finding for finding in scan_code(code) if finding.rule_id == "PY103"]
    assert len(findings) == 1
    assert findings[0].line == 1
    assert findings[0].column == 1


def test_reports_unicode_columns_as_character_positions():
    code = 'é = "x"; subprocess.run(command, shell=True)\n'
    findings = [finding for finding in scan_code(code) if finding.rule_id == "PY103"]
    assert len(findings) == 1
    assert findings[0].column == 10


def test_detects_private_key_marker():
    findings = scan_code("-----BEGIN PRIVATE KEY-----")
    assert findings[0].severity == "HIGH"
    assert findings[0].rule_id == "PY004"


def test_clean_code_has_no_findings():
    assert scan_code("x = 1 + 2") == []


def test_findings_include_position_but_not_source_excerpt():
    finding = scan_code('api_key = "abcd1234"')[0]
    assert finding.line == 1
    assert finding.column == 1
    assert set(finding.to_dict()) == {"severity", "rule", "rule_id", "line", "column"}


def test_rejects_oversized_source():
    with pytest.raises(ValueError, match="character limit"):
        scan_code("x" * (MAX_SOURCE_CHARS + 1))
