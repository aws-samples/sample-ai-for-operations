# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Precision tool: return the flattened, normalized findings list."""

from __future__ import annotations

from typing import Any

from strands import tool

from src.assessment_core import Redactor, build_findings_list
from src.session_store import SessionStore
from src.tools._common import _merge_input_with_store, _parse_input_json, _run_assessment


def _get_findings_summary(input_json: str = "", discover_aws: bool = False) -> list[dict[str, Any]]:
    payload: dict[str, Any] = _parse_input_json(input_json)
    redactor = Redactor()
    result = _run_assessment(payload, discover_aws, redactor)
    findings = build_findings_list(result)
    return [redactor.sanitize(item) for item in findings]


@tool
def get_findings_summary(input_json: str = "", discover_aws: bool = False) -> list[dict[str, Any]]:
    """Run the assessment and return the flattened, normalized findings list.

    Convenience tool for when the model (or the user) wants a flat list of
    every scored control - dimension, status, evidence_state, why_it_matters,
    evidence, recommended_next_step, source_refs - rather than the full
    nested assessment result. Delegates to build_findings_list(), the same
    function the CLI's --findings-json flag uses.
    """

    return _get_findings_summary(input_json=input_json, discover_aws=discover_aws)


def make_session_tool(session_store: SessionStore) -> Any:
    """Return a variant of this tool that merges answers saved in session_store."""

    @tool
    def get_findings_summary(
        input_json: str = "", discover_aws: bool = False
    ) -> list[dict[str, Any]]:
        """Precision tool: return findings derived from input and saved answers."""

        merged = _merge_input_with_store(input_json, session_store)
        return _get_findings_summary(merged, discover_aws)

    return get_findings_summary
