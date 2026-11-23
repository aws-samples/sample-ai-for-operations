# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Build the least-privilege IAM policies for read-only AWS discovery.

The policies are generated from MINIMUM_READ_ONLY_ACTIONS and
ENHANCED_READ_ONLY_ACTIONS in src/discovery.py, so the published JSON in
docs/iam/ can never drift from what the code asks for. Regenerate with:

    python -m src.iam_policies --write

Every action is a Describe, List, Get, or Simulate call (plus API Gateway's
read-only GET). Resource is "*" because most of these list operations do not
support resource-level permissions; none of them can change a resource.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from src.discovery import ENHANCED_READ_ONLY_ACTIONS, MINIMUM_READ_ONLY_ACTIONS

POLICY_DIR = Path(__file__).resolve().parent.parent / "docs" / "iam"
POLICY_FILES = {
    "discovery-minimum-policy.json": MINIMUM_READ_ONLY_ACTIONS,
    "discovery-enhanced-policy.json": ENHANCED_READ_ONLY_ACTIONS,
}
READ_ONLY_PREFIXES = ("Describe", "List", "Get", "Simulate", "GET")


def build_policy(actions: tuple[str, ...]) -> dict[str, Any]:
    """Return an IAM policy document allowing exactly `actions`, read-only."""

    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "SaasReadinessReadOnlyDiscovery",
                "Effect": "Allow",
                "Action": sorted(set(actions)),
                "Resource": "*",
            }
        ],
    }


def render(actions: tuple[str, ...]) -> str:
    return json.dumps(build_policy(actions), indent=2) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--write", action="store_true", help="write docs/iam/*.json")
    args = parser.parse_args()
    for name, actions in POLICY_FILES.items():
        text = render(actions)
        if args.write:
            POLICY_DIR.mkdir(parents=True, exist_ok=True)
            (POLICY_DIR / name).write_text(text, encoding="utf-8")
            print(f"wrote docs/iam/{name} ({len(set(actions))} actions)")
        else:
            print(f"--- {name}\n{text}")


if __name__ == "__main__":
    main()
