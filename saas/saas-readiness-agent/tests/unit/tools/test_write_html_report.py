# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""write_html_report must write only .html files inside the reports directory."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from src.tools.write_html_report import _write_html_report

SAMPLE = Path("samples/minimal_assessment.json").resolve()


class WriteHtmlReportTests(unittest.TestCase):
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
        message = _write_html_report(
            input_json=json.dumps(sample), output_path="reports/report.html"
        )
        self.assertIn("Wrote HTML report", message)
        self.assertTrue((self.root / "reports" / "report.html").exists())

    def test_cannot_overwrite_files_outside_reports_dir(self):
        readme = self.root / "README.md"
        readme.write_text("original", encoding="utf-8")
        for path in ("README.md", "README.html", "src/agent.html"):
            with self.subTest(path=path):
                self.assertTrue(_write_html_report(output_path=path).startswith("DENIED:"))
        self.assertEqual("original", readme.read_text(encoding="utf-8"))

    def test_rejects_non_html_suffix(self):
        for path in ("reports/report.md", "reports/payload.py", "reports/noext"):
            with self.subTest(path=path):
                self.assertTrue(_write_html_report(output_path=path).startswith("DENIED:"))

    def test_rejects_traversal_and_symlink_escape(self):
        (self.root / "reports").mkdir()
        target = self.root / "README.html"
        target.write_text("original", encoding="utf-8")
        (self.root / "reports" / "link.html").symlink_to(target)

        self.assertTrue(
            _write_html_report(output_path="reports/../README.html").startswith("DENIED:")
        )
        self.assertTrue(_write_html_report(output_path="reports/link.html").startswith("DENIED:"))
        self.assertTrue(_write_html_report(output_path="../../etc/passwd").startswith("DENIED:"))
        self.assertEqual("original", target.read_text(encoding="utf-8"))

    def test_denied_path_does_not_run_discovery(self):
        with mock.patch("src.tools.write_html_report._run_assessment") as run:
            message = _write_html_report(discover_aws=True, output_path="README.md")
        self.assertTrue(message.startswith("DENIED:"))
        run.assert_not_called()

    def test_reports_dir_is_configurable(self):
        with mock.patch.dict(os.environ, {"REPORTS_DIR": "out"}):
            self.assertIn("Wrote HTML report", _write_html_report(output_path="out/a.html"))
            self.assertTrue(
                _write_html_report(output_path="reports/a.html").startswith("DENIED:")
            )


if __name__ == "__main__":
    unittest.main()
