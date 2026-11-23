# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""read_customer_document must delegate to the DOCUMENTS_DIR-restricted reader.

The reader's own containment rules are tested in tests/unit/test_doc_reader.py.
"""

import unittest
from unittest import mock

from src.tools.read_customer_document import read_customer_document


class ReadCustomerDocumentTests(unittest.TestCase):
    def test_delegates_to_read_document(self):
        with mock.patch(
            "src.tools.read_customer_document.read_document",
            return_value={"content": "hello"},
        ) as reader:
            result = read_customer_document(file_path="notes.md")

        reader.assert_called_once_with("notes.md")
        self.assertEqual({"content": "hello"}, result)

    def test_returns_reader_error_unchanged(self):
        with mock.patch(
            "src.tools.read_customer_document.read_document",
            return_value={"error": "DENIED"},
        ):
            result = read_customer_document(file_path="../secret")

        self.assertEqual({"error": "DENIED"}, result)


if __name__ == "__main__":
    unittest.main()
