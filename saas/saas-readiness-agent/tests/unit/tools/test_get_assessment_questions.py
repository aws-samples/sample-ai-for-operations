# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""get_assessment_questions' documented modes must match the handler."""

import json
import unittest

from src.tools.get_assessment_questions import _get_assessment_questions, get_assessment_questions


class QuestionModeTests(unittest.TestCase):
    def test_essential_returns_only_essential_topics(self):
        result = _get_assessment_questions(mode="essential")
        priorities = {q["priority"] for q in result["questions"]}
        self.assertEqual({"essential"}, priorities)
        self.assertEqual(result["essential_count"], len(result["questions"]))

    def test_full_returns_every_unanswered_topic(self):
        result = _get_assessment_questions(mode="full")
        self.assertEqual(result["total_available"], len(result["questions"]))
        self.assertEqual("full", result["mode"])

    def test_all_is_an_alias_of_full(self):
        full = _get_assessment_questions(mode="full")
        alias = _get_assessment_questions(mode="all")
        self.assertEqual(
            [q["id"] for q in full["questions"]], [q["id"] for q in alias["questions"]]
        )
        self.assertEqual("full", alias["mode"])

    def test_unknown_mode_is_rejected(self):
        with self.assertRaises(ValueError):
            _get_assessment_questions(mode="exhaustive")

    def test_answered_questions_are_excluded(self):
        first = _get_assessment_questions(mode="full")["questions"][0]["id"]
        payload = {"business_context": {"answers": [{"question_id": first}]}}
        remaining = _get_assessment_questions(json.dumps(payload), mode="full")
        self.assertNotIn(first, [q["id"] for q in remaining["questions"]])

    def test_docstring_has_no_hard_coded_counts(self):
        spec = json.dumps(get_assessment_questions.tool_spec)
        for stale in ("~7", "~12", "~15", "~30"):
            self.assertNotIn(stale, spec)


if __name__ == "__main__":
    unittest.main()
