# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Precision tool: list answers saved for the current assessment.

Only available when the agent has a session store, so this module exposes a
factory rather than a module-level tool.
"""

from __future__ import annotations

from typing import Any

from strands import tool

from src.session_store import SessionStore


def make_session_tool(session_store: SessionStore) -> Any:
    """Return the get_assessment_progress tool bound to session_store."""

    @tool
    def get_assessment_progress() -> dict[str, Any]:
        """Precision tool: list saved answers when resuming a shared assessment."""

        answers = session_store.list_answers()
        return {
            "answered_count": len(answers),
            "answered_question_ids": [answer.question_id for answer in answers],
            "answers": [
                {
                    "question_id": answer.question_id,
                    "answer_value": answer.answer_value,
                    "source": answer.source,
                    "timestamp": answer.timestamp,
                    "changed": answer.changed,
                }
                for answer in answers
            ],
        }

    return get_assessment_progress
