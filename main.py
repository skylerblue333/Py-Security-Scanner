from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.scanner import MAX_SOURCE_CHARS, scan_code

MAX_SOURCE_BYTES = MAX_SOURCE_CHARS * 4


def _read_bounded_utf8(path: Path) -> str:
    if not path.is_file():
        raise ValueError(f"not a regular file: {path}")
    with path.open("rb") as handle:
        data = handle.read(MAX_SOURCE_BYTES + 1)
    if len(data) > MAX_SOURCE_BYTES:
        raise ValueError(f"file is too large: {path}")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"file is not valid UTF-8: {path}") from error


def audit_file(path: Path) -> dict[str, object]:
    source = _read_bounded_utf8(path)
    findings = scan_code(source)
    return {
        "path": str(path),
        "findings": [finding.to_dict() for finding in findings],
        "finding_count": len(findings),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline bounded Python security source audit")
    parser.add_argument("paths", nargs="+", type=Path, help="UTF-8 source files to inspect")
    args = parser.parse_args()

    reports: list[dict[str, object]] = []
    try:
        for path in args.paths:
            reports.append(audit_file(path))
    except (OSError, ValueError) as error:
        print(json.dumps({"error": str(error)}))
        return 2

    finding_count = sum(int(report["finding_count"]) for report in reports)
    print(json.dumps({"reports": reports, "finding_count": finding_count}, sort_keys=True))
    return 1 if finding_count else 0


if __name__ == "__main__":
    raise SystemExit(main())
