# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Precision tool: write the HTML assessment report inside the reports directory."""

from __future__ import annotations

from typing import Any

from strands import tool

from src.assessment_core import Redactor, render_html_report
from src.session_store import SessionStore
from src.tools._common import (
    _merge_input_with_store,
    _parse_input_json,
    _resolve_report_path,
    _run_assessment,
)

HTML_SUFFIXES = frozenset({".html", ".htm"})


def _write_html_report(
    input_json: str = "", discover_aws: bool = False, output_path: str = "reports/assessment.html"
) -> str:
    # Check the destination first so a denied path never triggers discovery.
    resolved = _resolve_report_path(output_path, HTML_SUFFIXES)
    if isinstance(resolved, str):
        return resolved

    payload: dict[str, Any] = _parse_input_json(input_json)
    redactor = Redactor()
    result = _run_assessment(payload, discover_aws, redactor)
    html = render_html_report(result, redactor)

    resolved.parent.mkdir(parents=True, exist_ok=True)
    resolved.write_text(html, encoding="utf-8")
    return f"Wrote HTML report to {resolved}"


@tool
def write_html_report(
    input_json: str = "", discover_aws: bool = False, output_path: str = "reports/assessment.html"
) -> str:
    """Run the assessment and write the primary HTML report to disk.

    output_path is relative to the current working directory and must be an
    .html or .htm file inside the reports directory (REPORTS_DIR, default
    ./reports), for example "reports/assessment.html". Any other path is
    refused with a DENIED message, so a model-supplied path cannot overwrite
    source files, README.md, or session data.
    """

    return _write_html_report(
        input_json=input_json, discover_aws=discover_aws, output_path=output_path
    )


def make_session_tool(session_store: SessionStore) -> Any:
    """Return a variant of this tool that merges answers saved in session_store."""

    @tool
    def write_html_report(
        input_json: str = "",
        discover_aws: bool = False,
        output_path: str = "reports/assessment.html",
    ) -> str:
        """Precision tool: write HTML using input plus persisted answers."""

        merged = _merge_input_with_store(input_json, session_store)
        return _write_html_report(merged, discover_aws, output_path)

    return write_html_report
