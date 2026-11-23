# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Tests for the agent wiring in src/agent.py.

Each tool has its own test module under tests/unit/tools/. These tests cover
build_agent(): which tools are registered, the configurable model ID, the
guardrail and token-cap configuration, and removing the document reader for
the hosted runtime. They construct a Strands Agent but never call a model.
"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from src.agent import DEFAULT_MODEL_ID, build_agent
from src.assessment_core import JsonSessionStore, Redactor


class StrandsAgentConstructionTests(unittest.TestCase):
    """build_agent() must wire up the expected tools and a configurable
    (never hard-coded-only) model ID, without making any network call."""

    def test_build_agent_registers_all_tools(self):
        agent = build_agent()
        self.assertEqual(
            {
                "run_saas_readiness_assessment",
                "get_assessment_questions",
                "get_findings_summary",
                "read_customer_document",
                "write_html_report",
                "write_summary_report",
            },
            set(agent.tool_names),
        )

    def test_build_agent_with_session_store_adds_session_tools(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            store = JsonSessionStore(Path(temp_dir) / "session.json", Redactor())
            names = set(build_agent(session_store=store).tool_names)

        self.assertIn("save_assessment_answer", names)
        self.assertIn("get_assessment_progress", names)

    def test_build_agent_uses_default_model_id_unless_overridden(self):
        agent = build_agent()
        self.assertEqual(DEFAULT_MODEL_ID, agent.model.config["model_id"])

    def test_build_agent_accepts_a_different_model_id(self):
        agent = build_agent(model_id="anthropic.claude-3-5-haiku-20241022-v1:0")
        self.assertEqual("anthropic.claude-3-5-haiku-20241022-v1:0", agent.model.config["model_id"])


class BedrockGuardrailConfigurationTests(unittest.TestCase):
    def test_build_agent_passes_configured_guardrail_to_model(self):
        agent = build_agent(
            guardrail_id="guardrail-example",
            guardrail_version="1",
        )

        self.assertEqual("guardrail-example", agent.model.config["guardrail_id"])
        self.assertEqual("1", agent.model.config["guardrail_version"])
        self.assertTrue(agent.model.config["guardrail_redact_input"])
        self.assertTrue(agent.model.config["guardrail_redact_output"])


class ModelOutputLimitTests(unittest.TestCase):
    """Model output must be bounded (OWASP LLM04). Input limits are tested
    in tests/unit/tools/test_common.py."""

    def test_build_agent_caps_max_tokens_from_config(self):
        with mock.patch.dict(os.environ, {"BEDROCK_MAX_TOKENS": "1234"}):
            agent = build_agent()

        self.assertEqual(1234, agent.model.config["max_tokens"])

    def test_build_agent_explicit_max_tokens_wins(self):
        agent = build_agent(max_tokens=512)

        self.assertEqual(512, agent.model.config["max_tokens"])


class DocumentReaderExposureTests(unittest.TestCase):
    """The filesystem-reading tool must be removable for the hosted runtime."""

    def test_document_reader_is_available_by_default(self):
        self.assertIn("read_customer_document", build_agent().tool_names)

    def test_document_reader_can_be_disabled(self):
        self.assertNotIn(
            "read_customer_document", build_agent(enable_document_reader=False).tool_names
        )

    def test_document_reader_disabled_with_session_tools(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            store = JsonSessionStore(Path(temp_dir) / "session.json", Redactor())
            names = build_agent(session_store=store, enable_document_reader=False).tool_names

        self.assertNotIn("read_customer_document", names)


if __name__ == "__main__":
    unittest.main()
