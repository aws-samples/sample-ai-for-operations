# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""The persistence tool must hide transient consistency windows from the LLM."""

import tempfile
import unittest
from pathlib import Path

from src.assessment_core import JsonSessionStore, Redactor
from src.session_store import SessionAnswer
from src.tools.save_assessment_answer import _persist_and_verify_answer, make_session_tool


def _answer(question_id, answer_value, source="agent"):
    return SessionAnswer(
        question_id=question_id,
        answer_value=answer_value,
        source=source,
        timestamp="2026-01-01T00:00:00Z",
        changed=False,
    )


class PersistAndVerifyTests(unittest.TestCase):
    def test_local_json_confirms_on_first_read(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            store = JsonSessionStore(Path(temp_dir) / "session.json", Redactor())
            answer, attempts = _persist_and_verify_answer(
                store, "BQ-001", "hybrid", "test", sleep_fn=lambda _: None
            )

        self.assertEqual("BQ-001", answer.question_id)
        self.assertEqual(1, attempts)

    def test_delayed_visibility_is_verified_inside_tool(self):
        class DelayedStore:
            def __init__(self):
                self.answer = None
                self.reads = 0

            def set_answer(self, question_id, answer_value, source="agent"):
                self.answer = _answer(question_id, answer_value, source)
                return self.answer

            def list_answers(self):
                self.reads += 1
                return () if self.reads < 3 else (self.answer,)

        answer, attempts = _persist_and_verify_answer(
            DelayedStore(), "BQ-001", "hybrid", "test", sleep_fn=lambda _: None
        )

        self.assertEqual("hybrid", answer.answer_value)
        self.assertEqual(3, attempts)


class SaveAnswerToolTests(unittest.TestCase):
    def test_tool_reports_persisted_answer(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            store = JsonSessionStore(Path(temp_dir) / "session.json", Redactor())
            result = make_session_tool(store)(question_id="BQ-001", answer_value="hybrid")

        self.assertTrue(result["persisted"])
        self.assertEqual("BQ-001", result["question_id"])

    def test_tool_reports_conflict_without_retry(self):
        class ConflictStore:
            def set_answer(self, question_id, answer_value, source="agent"):
                return _answer(question_id, answer_value, source)

            def list_answers(self):
                return (_answer("BQ-001", "someone-else"),)

        result = make_session_tool(ConflictStore())(question_id="BQ-001", answer_value="hybrid")

        self.assertFalse(result["persisted"])
        self.assertFalse(result["retryable"])


if __name__ == "__main__":
    unittest.main()
