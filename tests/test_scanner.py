import pytest

from src.scanner import MAX_SOURCE_CHARS, scan_code


def test_detects_hardcoded_password_without_leaking_value():
    secret = "hunter2-secret"
    findings = scan_code(f'password = "{secret}"')
    assert any(f.rule == "Hardcoded password" for f in findings)
    assert secret not in repr(findings)


def test_detects_eval_exec_and_shell_true():
    code = "\n".join([
        "result = eval(user_input)",
        "exec(source)",
        "subprocess.run(command, shell=True)",
    ])
    rule_ids = {finding.rule_id for finding in scan_code(code)}
    assert {"PY101", "PY102", "PY103"}.issubset(rule_ids)


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
