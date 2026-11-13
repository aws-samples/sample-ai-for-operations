# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT License
# See LICENSE file in the project root for full license information.
"""Precision tool: assemble the documented JSON response contract.

Pure code, no LLM. Produces the stable JSON shapes that provisioning automation
parses: fact-passthrough, readiness-investigation, and error.
"""

from typing import Optional

from strands import tool


def format_fact_response_impl(
    dataset: str,
    result: dict,
    source: Optional[str] = None,
    confidence: Optional[str] = None,
    region: Optional[str] = None,
) -> dict:
    """Assemble a fact-passthrough response."""
    resp = {"query_mode": "fact", "dataset": dataset, "result": result}
    if region is not None:
        resp["region"] = region
    if source is not None:
        resp["source"] = source
    if confidence is not None:
        resp["confidence"] = confidence
    return resp


def format_readiness_response_impl(
    region: str,
    verdict: str,
    blockers: list,
    facts: dict,
    confidence: str,
    target: Optional[dict] = None,
) -> dict:
    """Assemble a readiness-investigation response."""
    resp = {
        "query_mode": "readiness",
        "region": region,
        "verdict": verdict,
        "blockers": blockers,
        "facts": facts,
        "confidence": confidence,
    }
    if target:
        resp["target"] = target
    return resp


def format_error_response_impl(error_type: str, message: str) -> dict:
    """Assemble a structured error response."""
    return {"error": True, "error_type": error_type, "message": message}


@tool
def format_response(
    mode: str,
    payload: dict,
) -> dict:
    """Assemble the final structured JSON response.

    This is the only correct way to shape output for the caller. Pass mode and a
    payload dict:

    - mode="fact": payload = {"dataset", "result", "source"?, "confidence"?,
      "region"?}
    - mode="readiness": payload = {"region", "verdict", "blockers", "facts",
      "confidence", "target"?}
    - mode="error": payload = {"error_type", "message"}

    Args:
        mode: one of "fact", "readiness", "error".
        payload: the fields for that mode.

    Returns:
        The assembled response dict.
    """
    if mode == "fact":
        return format_fact_response_impl(
            dataset=payload.get("dataset", "unknown"),
            result=payload.get("result", {}),
            source=payload.get("source"),
            confidence=payload.get("confidence"),
            region=payload.get("region"),
        )
    if mode == "readiness":
        return format_readiness_response_impl(
            region=payload.get("region", ""),
            verdict=payload.get("verdict", ""),
            blockers=payload.get("blockers", []),
            facts=payload.get("facts", {}),
            confidence=payload.get("confidence", "low"),
            target=payload.get("target"),
        )
    if mode == "error":
        return format_error_response_impl(
            error_type=payload.get("error_type", "unknown_error"),
            message=payload.get("message", ""),
        )
    return format_error_response_impl(
        "invalid_mode", f"Unknown format mode '{mode}'."
    )
