# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .. import __version__
from ..config import Config
from ..models import Finding, RunSummary
from ..serialization import to_plain
from .files import write_private
from .rows import actions_allowed, protect

SCHEMA_VERSION = 1


def finding_to_json(finding: Finding, config: Config) -> dict[str, Any]:
    data = to_plain(finding)
    if finding.credential is not None and not config.unmask:
        data["credential"]["key_id"] = finding.credential.id_masked
    data["bedrock_actions_allowed"] = list(actions_allowed(finding, config))
    data["granting_policies"] = list(finding.granting_policies)
    # Redaction keeps JSON valid: it only rewrites key-shaped tokens inside string values.
    return json.loads(protect(json.dumps(data), config))


def render_json(findings: Sequence[Finding], summary: RunSummary, config: Config) -> str:
    document = {
        "schema": SCHEMA_VERSION,
        "tool_version": __version__,
        "run": to_plain(summary),
        "limitations": summary.notices,
        "findings": [finding_to_json(f, config) for f in findings],
    }
    return json.dumps(document, indent=2) + "\n"


def write_json(
    path: Path, findings: Sequence[Finding], summary: RunSummary, config: Config
) -> None:
    write_private(path, render_json(findings, summary, config))
