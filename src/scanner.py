from __future__ import annotations

import ast
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
)

_SUBPROCESS_CALLS: Final = {"run", "Popen", "call"}


def _shell_true_findings(code: str) -> list[Finding]:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []

    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name: str | None = None
        if isinstance(node.func, ast.Name):
            name = node.func.id
        elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.value.id == "subprocess":
                name = node.func.attr
        if name not in _SUBPROCESS_CALLS:
            continue
        if not any(
            keyword.arg == "shell"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        ):
            continue
        findings.append(
            Finding(
                severity="MEDIUM",
                rule="Shell execution with shell=True",
                rule_id="PY103",
                line=node.lineno,
                column=node.col_offset + 1,
            )
        )
    return findings


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

    for finding in _shell_true_findings(code):
        findings.append(finding)
        if len(findings) >= MAX_FINDINGS:
            return findings
    return findings
