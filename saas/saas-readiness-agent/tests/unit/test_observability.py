# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Tests for structured JSON logging (src/observability.py)."""

import io
import json
import logging
import unittest

from src.config import ConfigurationError, load_log_level
from src.observability import configure_logging, get_logger


class JsonLoggingTests(unittest.TestCase):
    def setUp(self):
        self.stream = io.StringIO()
        configure_logging("INFO", stream=self.stream)

    def tearDown(self):
        configure_logging("INFO")

    def _records(self):
        return [json.loads(line) for line in self.stream.getvalue().splitlines()]

    def test_each_record_is_one_json_object_with_extra_fields(self):
        get_logger("test").info(
            "something_happened", extra={"assessment_id": "a-001", "duration_ms": 12}
        )

        (record,) = self._records()
        self.assertEqual("something_happened", record["event"])
        self.assertEqual("INFO", record["level"])
        self.assertEqual("saas_readiness.test", record["logger"])
        self.assertEqual("a-001", record["assessment_id"])
        self.assertEqual(12, record["duration_ms"])
        self.assertIn("timestamp", record)

    def test_exceptions_log_type_only_not_message(self):
        try:
            raise ValueError("customer secret text")
        except ValueError:
            get_logger("test").exception("failed")

        (record,) = self._records()
        self.assertEqual("ValueError", record["exception_type"])
        self.assertNotIn("customer secret text", self.stream.getvalue())

    def test_level_filters_records(self):
        configure_logging("WARNING", stream=self.stream)
        get_logger("test").info("hidden")
        get_logger("test").warning("shown")

        self.assertEqual(["shown"], [r["event"] for r in self._records()])

    def test_reconfiguring_does_not_duplicate_handlers(self):
        configure_logging("INFO", stream=self.stream)
        configure_logging("INFO", stream=self.stream)
        get_logger("test").info("once")

        self.assertEqual(1, len(self._records()))

    def test_records_do_not_propagate_to_the_root_logger(self):
        self.assertFalse(logging.getLogger("saas_readiness").propagate)


class LogLevelConfigTests(unittest.TestCase):
    def test_default_and_case_insensitive(self):
        self.assertEqual("INFO", load_log_level({}))
        self.assertEqual("DEBUG", load_log_level({"LOG_LEVEL": "debug"}))

    def test_unknown_level_is_rejected(self):
        with self.assertRaises(ConfigurationError):
            load_log_level({"LOG_LEVEL": "verbose"})


if __name__ == "__main__":
    unittest.main()
