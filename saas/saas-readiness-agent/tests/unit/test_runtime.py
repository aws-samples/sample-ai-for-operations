# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Tests for the AgentCore Runtime entrypoint (src/runtime.py).

The agent, AgentCore Memory store, and session manager are replaced with
fakes, so no model or AWS call is made. The focus is the logging contract:
operational fields are logged; prompts and responses never are.
"""

import io
import json
import os
import unittest
from unittest import mock

from bedrock_agentcore.runtime import RequestContext

from src import runtime
from src.config import ConfigurationError
from src.observability import configure_logging

PROMPT = "Our tenant Contoso stores card data in table X"
RESPONSE = "Here is the confidential assessment narrative"
ENV = {"AGENTCORE_MEMORY_ID": "memory-example-001"}
PAYLOAD = {
    "assessment_id": "assessment-demo-001",
    "contributor_id": "participant-platform-01",
    "prompt": PROMPT,
}


class RuntimeInvocationLoggingTests(unittest.TestCase):
    def setUp(self):
        self.stream = io.StringIO()
        configure_logging("INFO", stream=self.stream)
        patches = [
            mock.patch.dict(os.environ, ENV),
            mock.patch.object(runtime, "build_session_store", return_value=object()),
            mock.patch.object(runtime, "build_strands_session_manager", return_value=None),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def tearDown(self):
        configure_logging("INFO")

    def _events(self):
        return [json.loads(line) for line in self.stream.getvalue().splitlines()]

    def test_successful_invocation_logs_start_and_completion_without_content(self):
        with mock.patch.object(runtime, "build_agent", return_value=lambda prompt: RESPONSE):
            result = runtime.invoke(PAYLOAD, RequestContext(session_id="rt-session-1"))

        self.assertEqual(RESPONSE, result["response"])
        events = self._events()
        self.assertEqual(
            ["invocation_started", "invocation_completed"], [e["event"] for e in events]
        )
        completed = events[-1]
        self.assertEqual("assessment-demo-001", completed["assessment_id"])
        self.assertEqual("participant-platform-01", completed["contributor_id"])
        self.assertEqual("rt-session-1", completed["runtime_session_id"])
        self.assertIsInstance(completed["duration_ms"], int)
        self.assertNotIn(PROMPT, self.stream.getvalue())
        self.assertNotIn(RESPONSE, self.stream.getvalue())

    def test_agent_failure_logs_error_type_and_reraises(self):
        def failing_agent(prompt):
            raise RuntimeError(f"model echoed: {prompt}")

        with (
            mock.patch.object(runtime, "build_agent", return_value=failing_agent),
            self.assertRaises(RuntimeError),
        ):
            runtime.invoke(PAYLOAD, RequestContext(session_id="rt-session-2"))

        failed = self._events()[-1]
        self.assertEqual("invocation_failed", failed["event"])
        self.assertEqual("RuntimeError", failed["error_type"])
        self.assertEqual("WARNING", failed["level"])
        self.assertNotIn(PROMPT, self.stream.getvalue())

    def test_runtime_disables_the_document_reader(self):
        with mock.patch.object(runtime, "build_agent", return_value=lambda prompt: RESPONSE) as build:
            runtime.invoke(PAYLOAD, RequestContext(session_id="rt-session-4"))

        self.assertIs(False, build.call_args.kwargs["enable_document_reader"])

    def test_unvalidated_identifiers_are_not_logged(self):
        bad = {**PAYLOAD, "assessment_id": "bad id\n{injected}"}

        with self.assertRaises(ConfigurationError):
            runtime.invoke(bad, RequestContext(session_id="rt-session-3"))

        (failed,) = self._events()
        self.assertEqual("invocation_failed", failed["event"])
        self.assertNotIn("assessment_id", failed)
        self.assertNotIn("injected", self.stream.getvalue())


if __name__ == "__main__":
    unittest.main()
