# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""get_assessment_progress must report exactly what the session store holds."""

import tempfile
import unittest
from pathlib import Path

from src.assessment_core import JsonSessionStore, Redactor
from src.tools.get_assessment_progress import make_session_tool


class AssessmentProgressTests(unittest.TestCase):
    def test_empty_store_reports_no_answers(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = JsonSessionStore(Path(tmp) / "session.json", Redactor())
            result = make_session_tool(store)()

        self.assertEqual(0, result["answered_count"])
        self.assertEqual([], result["answers"])

    def test_lists_saved_answers(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = JsonSessionStore(Path(tmp) / "session.json", Redactor())
            store.set_answer("BQ-001", "hybrid", "test")
            result = make_session_tool(store)()

        self.assertEqual(1, result["answered_count"])
        self.assertEqual(["BQ-001"], result["answered_question_ids"])
        self.assertEqual("hybrid", result["answers"][0]["answer_value"])


if __name__ == "__main__":
    unittest.main()
