# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Precision tool: persist one classified answer and confirm it is visible.

Only available when the agent has a session store, so this module exposes a
factory rather than a module-level tool.
"""

from __future__ import annotations

import time
from typing import Any

from strands import tool

from src.assessment_core import SessionStoreError
from src.session_store import SessionStore

SAVE_VERIFICATION_ATTEMPTS = 5
SAVE_VERIFICATION_INITIAL_DELAY_SECONDS = 0.25


def _persist_and_verify_answer(
    session_store: SessionStore,
    question_id: str,
    answer_value: str,
    source: str,
    *,
    sleep_fn: Any = time.sleep,
) -> tuple[Any, int]:
    """Persist an answer and confirm visibility before the LLM sees success.

    Local JSON confirms immediately. AgentCore Memory can briefly return a
    stale event list after a successful append, so this bounded loop absorbs
    that consistency window inside deterministic code rather than prompting
    the LLM to issue visible retry loops.
    """

    answer = session_store.set_answer(question_id, answer_value, source)
    for attempt in range(1, SAVE_VERIFICATION_ATTEMPTS + 1):
        current = {
            saved.question_id: saved for saved in session_store.list_answers()
        }.get(answer.question_id)
        if current and current.answer_value == answer.answer_value:
            return answer, attempt
        if current and current.answer_value != answer.answer_value:
            raise SessionStoreError(
                "Another contributor changed this answer before it could be confirmed."
            )
        if attempt < SAVE_VERIFICATION_ATTEMPTS:
            sleep_fn(SAVE_VERIFICATION_INITIAL_DELAY_SECONDS * (2 ** (attempt - 1)))

    raise SessionStoreError(
        "The answer was submitted but could not be confirmed in the session store. "
        "Do not retry automatically; ask the user to refresh progress or try later."
    )


def make_session_tool(session_store: SessionStore) -> Any:
    """Return the save_assessment_answer tool bound to session_store."""

    @tool
    def save_assessment_answer(
        question_id: str, answer_value: str, source: str = "agent"
    ) -> dict[str, Any]:
        """Precision tool: persist and verify one classified BQ answer once.

        The tool performs bounded internal confirmation for both local JSON
        and AgentCore Memory. A false result is final for this turn: do not
        call this tool repeatedly or claim a storage conflict to the user.
        """

        try:
            answer, verification_attempts = _persist_and_verify_answer(
                session_store,
                question_id,
                answer_value,
                source,
            )
        except SessionStoreError as exc:
            return {
                "persisted": False,
                "retryable": False,
                "message": str(exc),
            }
        return {
            "persisted": True,
            "question_id": answer.question_id,
            "answer_value": answer.answer_value,
            "source": answer.source,
            "timestamp": answer.timestamp,
            "changed": answer.changed,
            "verification_attempts": verification_attempts,
            "message": "Answer persisted and verified.",
        }

    return save_assessment_answer
