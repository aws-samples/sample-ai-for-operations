# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Shared tool input validation must bound and type-check model input (OWASP LLM04)."""

import os
import unittest
from unittest import mock

from src.tools._common import _parse_input_json, _resolve_report_path, _resolve_within_cwd


class ParseInputJsonTests(unittest.TestCase):
    def test_input_within_limit_is_accepted(self):
        with mock.patch.dict(os.environ, {"MAX_INPUT_JSON_BYTES": "64"}):
            self.assertEqual({"a": 1}, _parse_input_json('{"a": 1}'))

    def test_oversized_input_is_rejected(self):
        with (
            mock.patch.dict(os.environ, {"MAX_INPUT_JSON_BYTES": "8"}),
            self.assertRaises(ValueError),
        ):
            _parse_input_json('{"a": "too long"}')

    def test_blank_input_returns_empty_payload(self):
        self.assertEqual({}, _parse_input_json("   "))

    def test_non_object_input_is_rejected(self):
        with self.assertRaises(ValueError):
            _parse_input_json("[1, 2, 3]")


class ResolveReportPathTests(unittest.TestCase):
    def test_report_inside_reports_dir_resolves(self):
        result = _resolve_report_path("reports/x.html", frozenset({".html"}))
        self.assertNotIsInstance(result, str)

    def test_reports_dir_itself_is_denied(self):
        result = _resolve_report_path("reports", frozenset({".html"}))
        self.assertIsInstance(result, str)

    def test_suffix_check_is_case_insensitive(self):
        result = _resolve_report_path("reports/X.HTML", frozenset({".html"}))
        self.assertNotIsInstance(result, str)


class ResolveWithinCwdTests(unittest.TestCase):
    def test_relative_path_inside_cwd_resolves(self):
        self.assertNotIsInstance(_resolve_within_cwd("reports/x.html"), str)

    def test_escaping_path_is_denied(self):
        result = _resolve_within_cwd("../../outside.txt")
        self.assertIsInstance(result, str)
        self.assertTrue(result.startswith("DENIED:"))


if __name__ == "__main__":
    unittest.main()
