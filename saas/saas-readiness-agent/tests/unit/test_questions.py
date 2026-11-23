# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Contract tests for the adaptive customer-facing question catalog."""

import unittest

from src.questions import ANSWER_CONTROL_RULES, QUESTIONS, QUESTION_CATALOG_VERSION


class AdaptiveQuestionCatalogTests(unittest.TestCase):
    def test_catalog_has_fourteen_unique_customer_topics(self):
        self.assertEqual(2, QUESTION_CATALOG_VERSION)
        self.assertEqual(14, len(QUESTIONS))
        self.assertEqual(14, len({question["id"] for question in QUESTIONS}))
        self.assertTrue(all(question["id"].startswith("AQ-") for question in QUESTIONS))

    def test_every_question_has_persisted_signals_and_controls(self):
        for question in QUESTIONS:
            with self.subTest(question_id=question["id"]):
                self.assertTrue(question["controls"])
                self.assertTrue(question["scoring_ids"])
                for signal_id, definition in question["scoring_ids"].items():
                    self.assertTrue(signal_id.startswith("BQ-"))
                    self.assertTrue(definition["options"])

    def test_every_mapped_signal_is_a_catalog_signal(self):
        catalog_signals = {
            signal_id
            for question in QUESTIONS
            for signal_id in question["scoring_ids"]
        }
        self.assertTrue(set(ANSWER_CONTROL_RULES).issubset(catalog_signals))

    def test_customer_assertions_never_map_to_met(self):
        statuses = {
            status
            for options in ANSWER_CONTROL_RULES.values()
            for mappings in options.values()
            for _, status in mappings
        }
        self.assertNotIn("met", statuses)
