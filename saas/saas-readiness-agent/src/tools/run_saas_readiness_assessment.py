# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Precision tool: run the deterministic SaaS readiness assessment."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from strands import tool

from src.assessment_core import Redactor, to_plain
from src.session_store import SessionStore
from src.tools._common import _merge_input_with_store, _parse_input_json, _run_assessment


def _run_saas_readiness_assessment(
    input_json: str = "", discover_aws: bool = False
) -> dict[str, Any]:
    payload: dict[str, Any] = _parse_input_json(input_json)
    redactor = Redactor()
    result = _run_assessment(payload, discover_aws, redactor)
    sanitized = redactor.sanitize(to_plain(result))
    return dict(sanitized) if isinstance(sanitized, Mapping) else {}


@tool
def run_saas_readiness_assessment(
    input_json: str = "", discover_aws: bool = False
) -> dict[str, Any]:
    """Run the deterministic SaaS readiness assessment and return the full result.

    This is the only tool that produces scores, statuses, and confidence
    levels - and it produces them by calling the exact same assess_payload()
    function the CLI uses, not by asking the model to judge anything. The
    model should never attempt its own scoring; it should call this tool and
    then explain the result it gets back.

    Args:
        input_json: Optional JSON string shaped like samples/minimal_assessment.json
            (scope, business_context, facts, evidence). Pass "" to start from
            an empty payload (every control starts unknown) and rely on
            discover_aws instead.
        discover_aws: If true, runs the read-only AWS discovery pipeline
            (src/discovery.py) against the caller's current AWS credentials
            before scoring, exactly like the CLI's --discover-aws flag.
            Every discovery call is Describe/List/Get/Simulate only.

    Returns:
        The full assessment result as plain JSON-serializable data
        (dimensions, controls, scores, confidence, recommendations,
        evidence gaps, disclaimers), sanitized for common sensitive values.
    """

    return _run_saas_readiness_assessment(input_json=input_json, discover_aws=discover_aws)


def make_session_tool(session_store: SessionStore) -> Any:
    """Return a variant of this tool that merges answers saved in session_store."""

    @tool
    def run_saas_readiness_assessment(
        input_json: str = "", discover_aws: bool = False
    ) -> dict[str, Any]:
        """Precision tool: score input plus all answers saved for this assessment."""

        merged = _merge_input_with_store(input_json, session_store)
        return _run_saas_readiness_assessment(merged, discover_aws)

    return run_saas_readiness_assessment
