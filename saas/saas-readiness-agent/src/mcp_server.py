# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Optional MCP wrapper for the SaaS readiness agent.

The MCP server deliberately delegates assessment work to src.assessment_core.
That keeps the Strands agent, tests, and MCP path on one scoring
implementation.
"""

from __future__ import annotations

from typing import Any

from src.assessment_core import AssessmentError, assess_payload, render_html_report, to_plain

try:
    from mcp.server.fastmcp import FastMCP
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    FastMCP = None  # type: ignore[assignment]


def assess(payload: dict[str, Any]) -> dict[str, Any]:
    """Run an assessment and return a single HTML report plus structured data."""

    try:
        result = assess_payload(payload)
        return {
            "assessment_id": result.assessment_id,
            "overall_score": result.overall_score,
            "overall_confidence": result.overall_confidence,
            "report_html": render_html_report(result),
            "result": to_plain(result),
        }
    except AssessmentError as exc:
        return exc.to_dict()


def build_server() -> Any:
    if FastMCP is None:
        raise RuntimeError("Optional dependency mcp is not installed. Install the mcp extra first.")

    server = FastMCP("saas-readiness-agent")

    @server.tool()
    def run_saas_readiness_assessment(payload: dict[str, Any]) -> dict[str, Any]:
        return assess(payload)

    return server


def main() -> None:
    server = build_server()
    server.run()


if __name__ == "__main__":
    main()
