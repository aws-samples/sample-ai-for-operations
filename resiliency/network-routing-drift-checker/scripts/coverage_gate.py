# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Per-module coverage gate for tool code (tasks.md 1.30, testing-standards).

Usage: .venv/bin/pytest tests --cov=src --cov-report=json:coverage.json && \
       .venv/bin/python scripts/coverage_gate.py coverage.json
Fails if the total, or ANY module under drift_core/collectors/ or drift_core/checks/, is below 80 %.
"""

from __future__ import annotations

import json
import sys

THRESHOLD = 80.0
TOOL_DIRS = ("src/drift_core/collectors/", "src/drift_core/checks/")


def main(path: str) -> int:
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    failures = []
    total = data["totals"]["percent_covered"]
    if total < THRESHOLD:
        failures.append(f"total {total:.1f} %")
    for name, info in sorted(data["files"].items()):
        if name.startswith(TOOL_DIRS) and info["summary"]["percent_covered"] < THRESHOLD:
            failures.append(f"{name} {info['summary']['percent_covered']:.1f} %")
    if failures:
        print("Coverage below 80 %: " + "; ".join(failures))
        return 1
    tools = [n for n in data["files"] if n.startswith(TOOL_DIRS)]
    print(f"Coverage gate passed: total {total:.1f} %, {len(tools)} tool modules each >= {THRESHOLD:.0f} %")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "coverage.json"))
