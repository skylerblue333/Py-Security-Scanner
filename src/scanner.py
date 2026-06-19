import re
from dataclasses import dataclass, field
from typing import List

@dataclass
class Finding:
    severity: str
    rule: str
    line: int
    match: str

RULES = [
    ("HIGH",   r"password\s*=\s*['\"][^'\"]+['\"]",   "Hardcoded password"),
    ("HIGH",   r"secret\s*=\s*['\"][^'\"]+['\"]",     "Hardcoded secret"),
    ("HIGH",   r"api_key\s*=\s*['\"][^'\"]+['\"]",    "Hardcoded API key"),
    ("MEDIUM", r"eval\s*\(",                                  "Use of eval()"),
    ("MEDIUM", r"exec\s*\(",                                  "Use of exec()"),
    ("LOW",    r"TODO|FIXME|HACK",                              "Code smell"),
]

def scan_code(code: str) -> List[Finding]:
    findings = []
    for i, line in enumerate(code.splitlines(), start=1):
        for severity, pattern, rule in RULES:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(Finding(
                    severity=severity,
                    rule=rule,
                    line=i,
                    match=line.strip()[:80]
                ))
    return findings
