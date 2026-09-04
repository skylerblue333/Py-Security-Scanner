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
_LEGACY_SHELL_CALL: Final = re.compile(
    r"\b(?:subprocess\.(?:run|Popen|call)|run|Popen|call)"
    r"\s*\([^\n]*\bshell\s*=\s*True",
    re.IGNORECASE,
)


def _finding(line: int, column: int) -> Finding:
    return Finding(
        severity="MEDIUM",
        rule="Shell execution with shell=True",
        rule_id="PY103",
        line=line,
        column=column,
    )


def _fallback_shell_true_findings(code: str) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, line in enumerate(code.splitlines(), start=1):
        match = _LEGACY_SHELL_CALL.search(line)
        if match is not None:
            findings.append(_finding(line_number, match.start() + 1))
    return findings


def _subprocess_names(tree: ast.AST) -> tuple[set[str], set[str]]:
    module_names = {"subprocess"}
    direct_calls = set(_SUBPROCESS_CALLS)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for imported in node.names:
                if imported.name == "subprocess":
                    module_names.add(imported.asname or imported.name)
        elif isinstance(node, ast.ImportFrom) and node.module == "subprocess":
            for imported in node.names:
                if imported.name in _SUBPROCESS_CALLS:
                    direct_calls.add(imported.asname or imported.name)

    return module_names, direct_calls


def _character_column(lines: list[str], node: ast.AST) -> int:
    line_number = getattr(node, "lineno", 1)
    byte_column = getattr(node, "col_offset", 0)
    if line_number < 1 or line_number > len(lines):
        return byte_column + 1
    prefix = lines[line_number - 1].encode("utf-8")[:byte_column]
    return len(prefix.decode("utf-8")) + 1


def _shell_true_findings(code: str) -> list[Finding]:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return _fallback_shell_true_findings(code)

    module_names, direct_calls = _subprocess_names(tree)
    lines = code.splitlines()
    findings: list[Finding] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        name: str | None = None
        if isinstance(node.func, ast.Name) and node.func.id in direct_calls:
            name = node.func.id
        elif (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in module_names
        ):
            name = node.func.attr

        if name not in _SUBPROCESS_CALLS and name not in direct_calls:
            continue
        if not any(
            keyword.arg == "shell"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        ):
            continue

        findings.append(_finding(node.lineno, _character_column(lines, node)))

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
