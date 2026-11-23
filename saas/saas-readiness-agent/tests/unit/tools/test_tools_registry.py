# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""The tool registry must expose the same tools the agent had before the split."""

import tempfile
import unittest
from pathlib import Path

from src.assessment_core import JsonSessionStore, Redactor
from src.tools import build_default_tools, build_session_tools


def _names(tools):
    return [t.tool_name for t in tools]


class ToolRegistryTests(unittest.TestCase):
    def test_default_tools(self):
        self.assertEqual(
            [
                "run_saas_readiness_assessment",
                "get_assessment_questions",
                "get_findings_summary",
                "read_customer_document",
                "write_html_report",
                "write_summary_report",
            ],
            _names(build_default_tools()),
        )

    def test_session_tools_add_save_and_progress(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = JsonSessionStore(Path(tmp) / "session.json", Redactor())
            names = _names(build_session_tools(store))
        self.assertEqual(
            [
                "run_saas_readiness_assessment",
                "get_assessment_questions",
                "get_findings_summary",
                "save_assessment_answer",
                "get_assessment_progress",
                "read_customer_document",
                "write_html_report",
                "write_summary_report",
            ],
            names,
        )


if __name__ == "__main__":
    unittest.main()
