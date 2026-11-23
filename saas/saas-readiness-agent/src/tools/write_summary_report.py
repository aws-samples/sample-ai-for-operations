# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Precision tool: write the Markdown summary report inside the reports directory."""

from __future__ import annotations

from typing import Any

from strands import tool

from src.assessment_core import Redactor, build_summary_markdown
from src.session_store import SessionStore
from src.tools._common import (
    _merge_input_with_store,
    _parse_input_json,
    _resolve_report_path,
    _run_assessment,
)

MARKDOWN_SUFFIXES = frozenset({".md"})


def _write_summary_report(
    input_json: str = "", discover_aws: bool = False, output_path: str = "reports/summary.md"
) -> str:
    # Check the destination first so a denied path never triggers discovery.
    resolved = _resolve_report_path(output_path, MARKDOWN_SUFFIXES)
    if isinstance(resolved, str):
        return resolved

    payload: dict[str, Any] = _parse_input_json(input_json)
    redactor = Redactor()
    result = _run_assessment(payload, discover_aws, redactor)
    markdown = build_summary_markdown(result)

    resolved.parent.mkdir(parents=True, exist_ok=True)
    resolved.write_text(markdown, encoding="utf-8")
    return f"Wrote summary report to {resolved}"


@tool
def write_summary_report(
    input_json: str = "", discover_aws: bool = False, output_path: str = "reports/summary.md"
) -> str:
    """Run the assessment and write the short customer-facing Markdown summary to disk.

    Uses build_summary_markdown() - the same function the CLI's --summary-md
    flag uses - with no LLM narrative attached. If a richer, model-generated
    executive summary is wanted, ask the model to read the assessment result
    (via run_saas_readiness_assessment) and write its own prose in the chat
    response instead; this tool intentionally stays deterministic-only so
    the written artifact never depends on a model call succeeding.

    output_path is relative to the current working directory and must be a
    .md file inside the reports directory (REPORTS_DIR, default ./reports),
    for example "reports/summary.md". Any other path is refused with a
    DENIED message.
    """

    return _write_summary_report(
        input_json=input_json, discover_aws=discover_aws, output_path=output_path
    )


def make_session_tool(session_store: SessionStore) -> Any:
    """Return a variant of this tool that merges answers saved in session_store."""

    @tool
    def write_summary_report(
        input_json: str = "",
        discover_aws: bool = False,
        output_path: str = "reports/summary.md",
    ) -> str:
        """Precision tool: write Markdown using input plus persisted answers."""

        merged = _merge_input_with_store(input_json, session_store)
        return _write_summary_report(merged, discover_aws, output_path)

    return write_summary_report
