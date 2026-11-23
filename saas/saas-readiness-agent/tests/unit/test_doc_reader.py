# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Tests for the document reader's containment rules (src/doc_reader.py).

The model chooses file_path, so every escape route must be refused: parent
traversal, absolute paths, home-directory paths, and symlinks pointing out of
the documents directory. Containment must be checked before existence.
"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from src.doc_reader import read_document


class DocumentReaderContainmentTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name).resolve()
        self.docs = self.root / "documents"
        self.docs.mkdir()
        (self.docs / "architecture.md").write_text("tenant isolation: silo", encoding="utf-8")
        (self.docs / "nested").mkdir()
        (self.docs / "nested" / "runbook.txt").write_text("onboarding runbook", encoding="utf-8")
        self.outside = self.root / "secret.cfg"
        self.outside.write_text("password=not-for-the-model", encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def _read(self, file_path):
        return read_document(file_path, base_dir=self.docs)

    def test_reads_file_by_name_inside_documents_dir(self):
        result = self._read("architecture.md")
        self.assertTrue(result["success"])
        self.assertIn("silo", result["content"])

    def test_reads_nested_relative_path(self):
        self.assertTrue(self._read("nested/runbook.txt")["success"])

    def test_absolute_path_inside_documents_dir_is_allowed(self):
        self.assertTrue(self._read(str(self.docs / "architecture.md"))["success"])

    def test_parent_traversal_is_denied(self):
        result = self._read("../secret.cfg")
        self.assertFalse(result["success"])
        self.assertTrue(result["error"].startswith("DENIED"))
        self.assertNotIn("content", result)

    def test_absolute_path_outside_is_denied(self):
        result = self._read(str(self.outside))
        self.assertFalse(result["success"])
        self.assertTrue(result["error"].startswith("DENIED"))

    def test_system_file_is_denied(self):
        result = self._read("/etc/hosts")
        self.assertFalse(result["success"])
        self.assertTrue(result["error"].startswith("DENIED"))

    def test_home_directory_path_is_denied(self):
        result = self._read("~/.aws/config")
        self.assertFalse(result["success"])
        self.assertTrue(result["error"].startswith("DENIED"))

    def test_symlink_escaping_documents_dir_is_denied(self):
        link = self.docs / "innocent.cfg"
        os.symlink(self.outside, link)
        result = self._read("innocent.cfg")
        self.assertFalse(result["success"])
        self.assertTrue(result["error"].startswith("DENIED"))

    def test_symlinked_directory_escape_is_denied(self):
        os.symlink(self.root, self.docs / "up")
        result = self._read("up/secret.cfg")
        self.assertFalse(result["success"])
        self.assertTrue(result["error"].startswith("DENIED"))

    def test_existence_outside_is_not_revealed(self):
        existing = self._read("../secret.cfg")["error"]
        missing = self._read("../does-not-exist.cfg")["error"]
        self.assertTrue(existing.startswith("DENIED"))
        self.assertTrue(missing.startswith("DENIED"))
        self.assertNotIn("not found", existing.lower())

    def test_missing_file_inside_is_reported_as_not_found(self):
        result = self._read("missing.md")
        self.assertFalse(result["success"])
        self.assertIn("not found", result["error"].lower())

    def test_unsupported_extension_inside_is_rejected(self):
        (self.docs / "script.sh").write_text("echo hi", encoding="utf-8")
        result = self._read("script.sh")
        self.assertFalse(result["success"])
        self.assertIn("Unsupported file type", result["error"])

    def test_missing_documents_dir_gives_setup_guidance(self):
        result = read_document("architecture.md", base_dir=self.root / "nope")
        self.assertFalse(result["success"])
        self.assertIn("Documents directory not found", result["error"])

    def test_default_base_dir_comes_from_documents_dir_env(self):
        with mock.patch.dict(os.environ, {"DOCUMENTS_DIR": str(self.docs)}):
            self.assertTrue(read_document("architecture.md")["success"])
            self.assertFalse(read_document(str(self.outside))["success"])


if __name__ == "__main__":
    unittest.main()
