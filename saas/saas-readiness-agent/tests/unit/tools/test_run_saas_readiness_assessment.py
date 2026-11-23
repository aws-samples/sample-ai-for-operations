# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""run_saas_readiness_assessment must return exactly what the deterministic core computed."""

import inspect
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from src.assessment_core import JsonSessionStore, Redactor, assess_payload, to_plain
from src.tools.run_saas_readiness_assessment import (
    _run_saas_readiness_assessment,
    make_session_tool,
)

SAMPLE = Path("samples/minimal_assessment.json")


class RunAssessmentTests(unittest.TestCase):
    def test_matches_direct_assess_payload_call(self):
        sample = json.loads(SAMPLE.read_text(encoding="utf-8"))

        via_tool = _run_saas_readiness_assessment(input_json=json.dumps(sample))
        direct = to_plain(assess_payload(sample))

        self.assertEqual(direct["overall_score"], via_tool["overall_score"])
        self.assertEqual(direct["overall_confidence"], via_tool["overall_confidence"])
        self.assertEqual(len(direct["dimensions"]), len(via_tool["dimensions"]))

    def test_empty_input_json_starts_from_empty_payload(self):
        # "" is the documented way to start from an empty payload (every
        # control unknown) rather than requiring callers to pass "{}".
        result = _run_saas_readiness_assessment(input_json="")
        self.assertEqual(7, len(result["dimensions"]))

    def test_has_no_parameter_a_model_could_use_to_inject_a_score(self):
        params = set(inspect.signature(_run_saas_readiness_assessment).parameters)
        self.assertEqual({"input_json", "discover_aws"}, params)

    def test_oversized_input_json_is_rejected(self):
        with (
            mock.patch.dict(os.environ, {"MAX_INPUT_JSON_BYTES": "64"}),
            self.assertRaises(ValueError) as ctx,
        ):
            _run_saas_readiness_assessment(input_json=json.dumps({"pad": "x" * 100}))

        self.assertIn("MAX_INPUT_JSON_BYTES", str(ctx.exception))

    def test_session_tool_scores_saved_answers(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = JsonSessionStore(Path(tmp) / "session.json", Redactor())
            session_tool = make_session_tool(store)
            result = session_tool(input_json="")

        self.assertEqual(7, len(result["dimensions"]))


if __name__ == "__main__":
    unittest.main()
