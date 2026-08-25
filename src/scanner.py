from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Final

MAX_SOURCE_CHARS: Final = 1_000_000
MAX_FINDINGS: Final = 500


@dataclass(frozen=True)
class Finding:
    severity: str
    rule: str
    rule_id: str
    line: int
    column: int

    def to_dict(self) -> dict[str, str | int]:
        return asdict(self)


@dataclass(frozen=True)
class Rule:
    rule_id: str
    severity: str
    description: str
    pattern: re.Pattern[str]


RULES: Final[tuple[Rule, ...]] = (
    Rule(
        "PY001",
        "HIGH",
        "Hardcoded password",
        re.compile(r"\bpassword\s*=\s*['\"][^'\"\n]{4,}['\"]", re.IGNORECASE),
    ),
    Rule(
        "PY002",
        "HIGH",
        "Hardcoded secret",
        re.compile(r"\bsecret\s*=\s*['\"][^'\"\n]{4,}['\"]", re.IGNORECASE),
    ),
    Rule(
        "PY003",
        "HIGH",
        "Hardcoded API key",
        re.compile(r"\bapi[_-]?key\s*=\s*['\"][^'\"\n]{4,}['\"]", re.IGNORECASE),
    ),
    Rule(
        "PY004",
        "HIGH",
        "Private key material marker",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
    Rule("PY101", "MEDIUM", "Use of eval()", re.compile(r"\beval\s*\(")),
    Rule("PY102", "MEDIUM", "Use of exec()", re.compile(r"\bexec\s*\(")),
    Rule(
        "PY103",
        "MEDIUM",
        "Shell execution with shell=True",
        re.compile(
            r"\b(?:subprocess\.(?:run|Popen|call)|run|Popen|call)"
            r"\s*\([^\n]*\bshell\s*=\s*True",
            re.IGNORECASE,
        ),
    ),
)


def scan_code(code: str) -> list[Finding]:
    if not isinstance(code, str):
        raise TypeError("code must be a string")
    if len(code) > MAX_SOURCE_CHARS:
        raise ValueError(f"source exceeds {MAX_SOURCE_CHARS} character limit")

    findings: list[Finding] = []
    for line_number, line in enumerate(code.splitlines(), start=1):
        for rule in RULES:
            match = rule.pattern.search(line)
            if match is None:
                continue
            findings.append(
                Finding(
                    severity=rule.severity,
                    rule=rule.description,
                    rule_id=rule.rule_id,
                    line=line_number,
                    column=match.start() + 1,
                )
            )
            if len(findings) >= MAX_FINDINGS:
                return findings
    return findings
