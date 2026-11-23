# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""The agent's tools, one per module.

Every tool is pure code: it fetches data or computes exact results and never
calls the model. Classification (see .kiro/specs/saas-readiness-agent/design.md):

- Data retrieval: read_customer_document
- Precision: run_saas_readiness_assessment, get_assessment_questions,
  get_findings_summary, save_assessment_answer, get_assessment_progress,
  write_html_report, write_summary_report

build_default_tools() returns the stateless set. build_session_tools() returns
variants that merge answers persisted in a SessionStore, plus the two tools
that only make sense with a store (save_assessment_answer and
get_assessment_progress).
"""

from __future__ import annotations

from typing import Any

from src.session_store import SessionStore
from src.tools import (
    get_assessment_progress,
    get_assessment_questions,
    get_findings_summary,
    read_customer_document,
    run_saas_readiness_assessment,
    save_assessment_answer,
    write_html_report,
    write_summary_report,
)


def build_default_tools() -> list[Any]:
    """Return the tools used when the agent has no session store."""

    return [
        run_saas_readiness_assessment.run_saas_readiness_assessment,
        get_assessment_questions.get_assessment_questions,
        get_findings_summary.get_findings_summary,
        read_customer_document.read_customer_document,
        write_html_report.write_html_report,
        write_summary_report.write_summary_report,
    ]


def build_session_tools(session_store: SessionStore) -> list[Any]:
    """Return tools that hydrate every operation from persisted answers."""

    return [
        run_saas_readiness_assessment.make_session_tool(session_store),
        get_assessment_questions.make_session_tool(session_store),
        get_findings_summary.make_session_tool(session_store),
        save_assessment_answer.make_session_tool(session_store),
        get_assessment_progress.make_session_tool(session_store),
        read_customer_document.read_customer_document,
        write_html_report.make_session_tool(session_store),
        write_summary_report.make_session_tool(session_store),
    ]
