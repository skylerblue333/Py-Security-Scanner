from src.scanner import scan_code

def test_detects_hardcoded_password():
    code = 'password = "hunter2"'
    findings = scan_code(code)
    assert any(f.rule == "Hardcoded password" for f in findings)

def test_detects_eval():
    code = "result = eval(user_input)"
    findings = scan_code(code)
    assert any("eval" in f.rule for f in findings)

def test_clean_code():
    code = "x = 1 + 2"
    findings = scan_code(code)
    assert len(findings) == 0

def test_severity_high():
    code = 'api_key = "sk-abc123"'
    findings = scan_code(code)
    assert findings[0].severity == "HIGH"
