# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Configuration validation tests for release-critical settings."""

import unittest

from src.config import (
    DEFAULT_AWS_MAX_ATTEMPTS,
    DEFAULT_BEDROCK_MAX_TOKENS,
    DEFAULT_MAX_INPUT_JSON_BYTES,
    ConfigurationError,
    load_documents_dir,
    load_limits,
    load_settings,
)


class GuardrailConfigurationTests(unittest.TestCase):
    def test_guardrail_id_and_version_must_be_set_together(self):
        with self.assertRaises(ConfigurationError):
            load_settings({"BEDROCK_GUARDRAIL_ID": "guardrail-example"})
        with self.assertRaises(ConfigurationError):
            load_settings({"BEDROCK_GUARDRAIL_VERSION": "1"})

    def test_guardrail_pair_is_accepted_for_local_profile(self):
        settings = load_settings(
            {
                "BEDROCK_GUARDRAIL_ID": "guardrail-example",
                "BEDROCK_GUARDRAIL_VERSION": "1",
            }
        )

        self.assertEqual("guardrail-example", settings.bedrock_guardrail_id)
        self.assertEqual("1", settings.bedrock_guardrail_version)


class DocumentsDirConfigTests(unittest.TestCase):
    def test_default_and_override(self):
        self.assertEqual("documents", load_documents_dir({}))
        self.assertEqual("/data/docs", load_documents_dir({"DOCUMENTS_DIR": "/data/docs"}))


class RuntimeLimitsTests(unittest.TestCase):
    def test_defaults_apply_when_unset(self):
        limits = load_limits({})

        self.assertEqual(DEFAULT_MAX_INPUT_JSON_BYTES, limits.max_input_json_bytes)
        self.assertEqual(DEFAULT_BEDROCK_MAX_TOKENS, limits.bedrock_max_tokens)
        self.assertEqual(DEFAULT_AWS_MAX_ATTEMPTS, limits.aws_max_attempts)
        self.assertEqual("adaptive", limits.aws_retry_mode)

    def test_environment_overrides_are_applied(self):
        limits = load_limits(
            {
                "MAX_INPUT_JSON_BYTES": "1024",
                "BEDROCK_MAX_TOKENS": "2000",
                "AWS_DISCOVERY_MAX_ATTEMPTS": "3",
                "AWS_DISCOVERY_RETRY_MODE": "standard",
            }
        )

        self.assertEqual(1024, limits.max_input_json_bytes)
        self.assertEqual(2000, limits.bedrock_max_tokens)
        self.assertEqual(3, limits.aws_max_attempts)
        self.assertEqual("standard", limits.aws_retry_mode)

    def test_non_positive_or_non_numeric_limits_are_rejected(self):
        for value in ("0", "-5", "abc"):
            with self.subTest(value=value), self.assertRaises(ConfigurationError):
                load_limits({"MAX_INPUT_JSON_BYTES": value})

    def test_unknown_retry_mode_is_rejected(self):
        with self.assertRaises(ConfigurationError):
            load_limits({"AWS_DISCOVERY_RETRY_MODE": "aggressive"})


if __name__ == "__main__":
    unittest.main()
