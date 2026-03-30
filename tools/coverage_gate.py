#!/usr/bin/env python3
"""Fail CI when critical module coverage drops below defined thresholds.

Usage:
  python tools/coverage_gate.py coverage.json
  python tools/coverage_gate.py coverage.json netcontrol/app.py:49
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

DEFAULT_RULES = {
    "netcontrol/app.py": 49.0,
}


def _normalize_path(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def _parse_rules(args: list[str]) -> dict[str, float]:
    if not args:
        return dict(DEFAULT_RULES)

    parsed: dict[str, float] = {}
    for raw in args:
        if ":" not in raw:
            raise ValueError(f"Invalid rule '{raw}'. Expected format path:min_percent")
        path, minimum = raw.rsplit(":", 1)
        parsed[_normalize_path(path)] = float(minimum)
    return parsed


def _find_percent_covered(files: dict, wanted_path: str) -> float | None:
    wanted_norm = _normalize_path(wanted_path)

    for file_path, file_info in files.items():
        current_norm = _normalize_path(file_path)
        if current_norm == wanted_norm or current_norm.endswith("/" + wanted_norm):
            summary = file_info.get("summary", {})
            if "percent_covered" in summary:
                return float(summary["percent_covered"])
            if "percent_covered_display" in summary:
                return float(summary["percent_covered_display"])
    return None


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python tools/coverage_gate.py <coverage.json> [path:min_percent ...]")
        return 2

    coverage_path = Path(sys.argv[1])
    if not coverage_path.exists():
        print(f"Coverage report not found: {coverage_path}")
        return 2

    try:
        rules = _parse_rules(sys.argv[2:])
    except ValueError as exc:
        print(str(exc))
        return 2

    data = json.loads(coverage_path.read_text(encoding="utf-8"))
    files = data.get("files", {})

    failures: list[str] = []
    for target, minimum in rules.items():
        covered = _find_percent_covered(files, target)
        if covered is None:
            failures.append(f"- {target}: file missing from coverage report")
            continue
        if covered < minimum:
            failures.append(f"- {target}: {covered:.2f}% < required {minimum:.2f}%")
        else:
            print(f"PASS {target}: {covered:.2f}% >= {minimum:.2f}%")

    if failures:
        print("Critical module coverage gate failed:")
        for item in failures:
            print(item)
        return 1

    print("Critical module coverage gate passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
