# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Shared helpers for the agent's tools.

These are not tools themselves. They hold the input validation, assessment
call, session merge, and output-path guard that several tools share, so each
tool module stays a thin wrapper and the rules live in one place.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from src.assessment_core import Redactor, assess_payload, merge_aws_preflight, merge_session_answers
from src.config import load_limits, load_reports_dir
from src.session_store import SessionStore


def _parse_input_json(input_json: str) -> dict[str, Any]:
    """Parse a tool's input_json payload, rejecting oversized or non-object input.

    The size cap (MAX_INPUT_JSON_BYTES) bounds the work and token cost a
    single tool call can trigger (OWASP LLM04: model denial of service).
    """

    if not input_json.strip():
        return {}
    limit = load_limits().max_input_json_bytes
    size = len(input_json.encode("utf-8"))
    if size > limit:
        raise ValueError(
            f"input_json is {size} bytes, which exceeds the {limit}-byte limit "
            "(MAX_INPUT_JSON_BYTES). Send a smaller payload."
        )
    payload = json.loads(input_json)
    if not isinstance(payload, dict):
        raise ValueError("input_json must be a JSON object.")
    return payload


def _run_assessment(payload: Mapping[str, Any], discover_aws: bool, redactor: Redactor) -> Any:
    """Merge read-only AWS discovery if requested, then score with assess_payload()."""

    merged = dict(payload)
    if discover_aws:
        merged = merge_aws_preflight(merged)
    return assess_payload(merged, redactor=redactor)


def _merge_input_with_store(input_json: str, session_store: SessionStore) -> str:
    """Merge persisted answers into an input payload for every session-bound tool."""

    payload: dict[str, Any] = _parse_input_json(input_json)
    merged = merge_session_answers(payload, session_store)
    return json.dumps(merged)


def _resolve_within_cwd(output_path: str) -> Path | str:
    """Resolve output_path against Path.cwd() and reject anything outside it.

    Returns the resolved Path on success, or a "DENIED: ..." string on
    failure, so a model-supplied path can never escape the project directory.
    """

    resolved = (Path.cwd() / output_path).resolve()
    cwd = Path.cwd().resolve()
    if cwd not in resolved.parents and resolved != cwd:
        return f"DENIED: output_path must resolve within the working directory ({cwd})."
    return resolved


def _resolve_report_path(output_path: str, allowed_suffixes: frozenset[str]) -> Path | str:
    """Resolve a model-supplied report path, allowing only REPORTS_DIR and report suffixes.

    Stricter than _resolve_within_cwd(): a steered output_path cannot overwrite
    README.md, source files, or session data elsewhere in the working
    directory. The path is resolved (including symlinks) before the check, so
    a symlink inside REPORTS_DIR that points elsewhere is also denied.
    Returns the resolved Path, or a "DENIED: ..." string.
    """

    reports_dir = (Path.cwd() / load_reports_dir()).resolve()
    resolved = (Path.cwd() / output_path).resolve()
    if reports_dir not in resolved.parents:
        return f"DENIED: output_path must be a file inside the reports directory ({reports_dir})."
    if resolved.suffix.lower() not in allowed_suffixes:
        allowed = ", ".join(sorted(allowed_suffixes))
        return f"DENIED: output_path must end with one of: {allowed}."
    return resolved
