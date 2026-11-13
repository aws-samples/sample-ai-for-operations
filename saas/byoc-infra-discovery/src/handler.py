# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT License
# See LICENSE file in the project root for full license information.
"""AWS Lambda handler for the BYOC Infrastructure Discovery Agent.

Contract: the invocation event carries a natural-language or structured query.
The handler validates the event, runs the agent to GATHER facts (Strands
structured output -> GatheredFacts), then deterministically assembles the final
JSON contract — the verdict and confidence are computed in code, never by the
model. It contains NO resolution logic. Any uncaught error is returned as the
structured error contract, never a stack trace.
"""

import json
import time

from agent import gather_facts
from assemble import assemble_contract
from logging_util import log_event
from tools.format_response import format_error_response_impl


def _extract_query(event: dict) -> str:
    """Pull the query string from a variety of invocation shapes."""
    if not isinstance(event, dict):
        raise ValueError("event must be a JSON object")

    # Direct invoke: {"query": "..."}
    if isinstance(event.get("query"), str) and event["query"].strip():
        return event["query"].strip()

    # API Gateway proxy: body is a JSON string
    body = event.get("body")
    if isinstance(body, str) and body.strip():
        try:
            parsed = json.loads(body)
        except ValueError as exc:
            raise ValueError(f"request body is not valid JSON: {exc}") from exc
        if isinstance(parsed, dict) and isinstance(parsed.get("query"), str):
            q = parsed["query"].strip()
            if q:
                return q

    raise ValueError("no 'query' field found in the event")


def handler(event: dict, context: object = None) -> dict:
    """Lambda entrypoint."""
    start = time.time()
    try:
        query = _extract_query(event)
    except ValueError as exc:
        log_event("bad_request", detail=str(exc))
        return format_error_response_impl("bad_request", str(exc))

    try:
        facts = gather_facts(query)
        output = assemble_contract(facts)
        log_event(
            "invocation_complete",
            duration_ms=int((time.time() - start) * 1000),
            query_mode=output.get("query_mode"),
            verdict=output.get("verdict"),
            confidence=output.get("confidence"),
        )
        return output
    except Exception as exc:  # noqa: BLE001 - handler must never leak a stack trace
        log_event("invocation_error", detail=type(exc).__name__)
        return format_error_response_impl(
            "internal_error",
            "The agent failed to process the query.",
        )
