# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""get_findings_summary must return the same normalized shape as the CLI."""

import inspect
import json
import unittest
from pathlib import Path

from src.tools.get_findings_summary import _get_findings_summary


class FindingsSummaryTests(unittest.TestCase):
    def test_matches_build_findings_list_shape(self):
        sample = json.loads(Path("samples/minimal_assessment.json").read_text(encoding="utf-8"))
        findings = _get_findings_summary(input_json=json.dumps(sample))

        self.assertTrue(len(findings) > 0)
        # Every finding must carry the normalized shape the CLI's
        # --findings-json flag produces, so downstream consumers never see a
        # tool-specific schema.
        for finding in findings:
            self.assertIn("dimension", finding)
            self.assertIn("status", finding)
            self.assertIn("evidence_state", finding)

    def test_has_no_parameter_a_model_could_use_to_inject_a_score(self):
        params = set(inspect.signature(_get_findings_summary).parameters)
        self.assertEqual({"input_json", "discover_aws"}, params)

    def test_non_object_input_is_rejected(self):
        with self.assertRaises(ValueError):
            _get_findings_summary(input_json="[]")


if __name__ == "__main__":
    unittest.main()
