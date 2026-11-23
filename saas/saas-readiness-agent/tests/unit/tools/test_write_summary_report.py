# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""write_summary_report must write only .md files inside the reports directory."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from src.tools.write_summary_report import _write_summary_report

SAMPLE = Path("samples/minimal_assessment.json").resolve()


class WriteSummaryReportTests(unittest.TestCase):
    def setUp(self):
        self._original_cwd = Path.cwd()
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name).resolve()
        os.chdir(self.root)

    def tearDown(self):
        os.chdir(self._original_cwd)
        self._tmp.cleanup()

    def test_writes_inside_reports_dir(self):
        sample = json.loads(SAMPLE.read_text(encoding="utf-8"))
        message = _write_summary_report(
            input_json=json.dumps(sample), output_path="reports/summary.md"
        )
        self.assertIn("Wrote summary report", message)
        self.assertTrue((self.root / "reports" / "summary.md").exists())

    def test_cannot_overwrite_readme_or_session_data(self):
        readme = self.root / "README.md"
        readme.write_text("original", encoding="utf-8")
        for path in ("README.md", "sessions/session.json", "CHANGELOG.md"):
            with self.subTest(path=path):
                self.assertTrue(_write_summary_report(output_path=path).startswith("DENIED:"))
        self.assertEqual("original", readme.read_text(encoding="utf-8"))

    def test_rejects_non_markdown_suffix(self):
        for path in ("reports/summary.html", "reports/summary.json"):
            with self.subTest(path=path):
                self.assertTrue(_write_summary_report(output_path=path).startswith("DENIED:"))

    def test_rejects_traversal(self):
        self.assertTrue(
            _write_summary_report(output_path="reports/../README.md").startswith("DENIED:")
        )
        self.assertTrue(_write_summary_report(output_path="../../etc/passwd").startswith("DENIED:"))


if __name__ == "__main__":
    unittest.main()
