# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Tests for the optional LLM explanation adapter.

The central property under test: no explainer can influence a score, status,
or confidence value. NoopExplainer proves the default (no-LLM) path adds
nothing. BedrockExplainer is tested with a fake client so no real model call
or AWS credential is required.
"""

import io
import json
import os
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any
from unittest import mock

from src import assessment_core
from src.assessment_core import assess_payload, to_plain
from src.explainer import (
    BedrockExplainer,
    ExplanationBundle,
    NoopExplainer,
    build_explainer,
    build_explanation_prompt,
)
from src.observability import configure_logging


# FakeBedrockBody/FakeBedrockClient stand in for the real botocore
# bedrock-runtime response shape: invoke_model() returns a dict with a
# "body" whose .read() yields the JSON bytes containing Claude's message
# content blocks. Mirroring that exact nesting (rather than a flatter fake)
# is what lets BedrockExplainer.explain() run unmodified against these fakes.
class FakeBedrockBody:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")


class FakeBedrockClient:
    def __init__(self, text: str) -> None:
        self._text = text

    def invoke_model(self, **_kwargs: Any) -> dict[str, Any]:
        return {"body": FakeBedrockBody({"content": [{"text": self._text}]})}


# Simulates a model call that raises, so tests can confirm BedrockExplainer
# degrades to an empty ExplanationBundle instead of letting the exception
# propagate and fail the whole assessment.
class RaisingBedrockClient:
    def invoke_model(self, **_kwargs: Any) -> dict[str, Any]:
        raise RuntimeError("model unavailable")


class ExplainerTests(unittest.TestCase):
    def test_noop_explainer_never_calls_a_model_and_returns_empty_bundle(self):
        bundle = NoopExplainer().explain({"overall_score": 3.0})

        self.assertEqual("", bundle.executive_summary)
        self.assertEqual({}, bundle.dimension_narratives)
        self.assertEqual("none", bundle.generated_by)

    def test_build_explainer_defaults_to_noop_for_unknown_mode(self):
        explainer = build_explainer("typo-mode")
        self.assertIsInstance(explainer, NoopExplainer)

    def test_prompt_forbids_the_model_from_changing_scores(self):
        result = to_plain(assess_payload({}))
        prompt = build_explanation_prompt(result)

        self.assertIn("FINAL and were computed by", prompt)
        self.assertIn("Do not propose different scores", prompt)

    def test_explanation_bundle_has_no_status_or_score_fields(self):
        # Structural guarantee: enumerate the dataclass fields and confirm
        # none of them could plausibly hold a status/score/confidence value.
        from dataclasses import fields

        field_names = {f.name for f in fields(ExplanationBundle)}
        self.assertEqual(
            {
                "executive_summary",
                "dimension_narratives",
                "contradictions",
                "generated_by",
                "failure_reason",
            },
            field_names,
        )

    def test_bedrock_explainer_returns_model_text_via_fake_client(self):
        # BedrockExplainer.__init__ imports boto3, so tests build the
        # instance via __new__() (bypassing __init__ entirely) and set its
        # attributes directly. This is the one place a real boto3 install
        # would otherwise be required just to construct the object.
        explainer = BedrockExplainer.__new__(BedrockExplainer)
        explainer._boto3 = type(
            "FakeBoto3",
            (),
            {
                "client": staticmethod(
                    lambda *a, **k: FakeBedrockClient("Overall posture is early stage.")
                )
            },
        )()
        explainer._model_id = "anthropic.claude-sonnet-4-20250514-v1:0"
        explainer._region = None

        bundle = explainer.explain(to_plain(assess_payload({})))

        self.assertEqual("Overall posture is early stage.", bundle.executive_summary)
        self.assertEqual("anthropic.claude-sonnet-4-20250514-v1:0", bundle.generated_by)

    def test_bedrock_explainer_degrades_gracefully_on_model_error(self):
        # Same __new__() construction trick as above, but wired to a client
        # that raises - proves a failed model call returns a "bedrock-error"
        # bundle rather than propagating and failing the whole assessment.
        explainer = BedrockExplainer.__new__(BedrockExplainer)
        explainer._boto3 = type(
            "FakeBoto3", (), {"client": staticmethod(lambda *a, **k: RaisingBedrockClient())}
        )()
        explainer._model_id = "anthropic.claude-sonnet-4-20250514-v1:0"
        explainer._region = None

        bundle = explainer.explain(to_plain(assess_payload({})))

        self.assertEqual("", bundle.executive_summary)
        self.assertEqual("bedrock-error", bundle.generated_by)
        self.assertEqual("RuntimeError", bundle.failure_reason)


class ExplainerFailureVisibilityTests(unittest.TestCase):
    """Fallbacks stay graceful but are never silent (review finding)."""

    def _explainer(self, client_factory):
        explainer = BedrockExplainer.__new__(BedrockExplainer)
        explainer._boto3 = type("FakeBoto3", (), {"client": staticmethod(client_factory)})()
        explainer._model_id = "model-under-test"
        explainer._region = "us-east-1"
        return explainer

    def _capture(self):
        stream = io.StringIO()
        configure_logging("INFO", stream=stream)
        self.addCleanup(configure_logging, "INFO")
        return stream

    def test_model_error_logs_aws_error_code(self):
        class AccessDenied(Exception):
            response = {"Error": {"Code": "AccessDeniedException"}}

        class DenyingClient:
            def invoke_model(self, **_kwargs):
                raise AccessDenied("not authorized")

        stream = self._capture()
        bundle = self._explainer(lambda *a, **k: DenyingClient()).explain({})

        self.assertEqual("AccessDeniedException", bundle.failure_reason)
        (record,) = [json.loads(line) for line in stream.getvalue().splitlines()]
        self.assertEqual("explainer_failed", record["event"])
        self.assertEqual("invoke_model", record["stage"])
        self.assertEqual("AccessDeniedException", record["error_code"])
        self.assertNotIn("not authorized", stream.getvalue())

    def test_client_construction_error_is_logged(self):
        def broken_factory(*_a, **_k):
            raise ValueError("bad region")

        stream = self._capture()
        bundle = self._explainer(broken_factory).explain({})

        self.assertEqual("bedrock-unavailable", bundle.generated_by)
        self.assertEqual("ValueError", bundle.failure_reason)
        self.assertIn('"stage": "client"', stream.getvalue())

    def test_default_model_and_region_come_from_config(self):
        fake_boto3 = types.ModuleType("boto3")
        env = {"BEDROCK_MODEL_ID": "us.example.model-v1", "BEDROCK_REGION": "eu-west-1"}
        with mock.patch.dict(sys.modules, {"boto3": fake_boto3}), mock.patch.dict(os.environ, env):
            explainer = BedrockExplainer()

        self.assertEqual("us.example.model-v1", explainer._model_id)
        self.assertEqual("eu-west-1", explainer._region)

    def test_explicit_model_id_overrides_config(self):
        fake_boto3 = types.ModuleType("boto3")
        with mock.patch.dict(sys.modules, {"boto3": fake_boto3}):
            explainer = BedrockExplainer(model_id="explicit-model")

        self.assertEqual("explicit-model", explainer._model_id)

    def test_no_hard_coded_model_id_in_explainer(self):
        source = Path("src/explainer.py").read_text(encoding="utf-8")
        self.assertNotIn("anthropic.claude-sonnet-4-20250514-v1:0", source)


class CliExplainWarningTests(unittest.TestCase):
    """`--explain bedrock` must tell the user when no narrative was produced."""

    def _run_cli(self, bundle):
        stderr = io.StringIO()
        fake = types.SimpleNamespace(explain=lambda _assessment: bundle)
        with tempfile.TemporaryDirectory() as tmp:
            cwd = os.getcwd()
            os.chdir(tmp)
            try:
                with (
                    mock.patch.object(assessment_core, "build_explainer", return_value=fake),
                    redirect_stderr(stderr),
                    redirect_stdout(io.StringIO()),
                ):
                    code = assessment_core.main(
                        [
                            "assess", "--output", "report.html", "--summary-md", "summary.md",
                            "--no-session", "--explain", "bedrock",
                        ]
                    )
                summary_written = Path("summary.md").exists()
            finally:
                os.chdir(cwd)
        return code, stderr.getvalue(), summary_written

    def test_failed_narrative_prints_warning_but_still_succeeds(self):
        bundle = ExplanationBundle(
            generated_by="bedrock-error", failure_reason="AccessDeniedException"
        )
        code, err, summary_written = self._run_cli(bundle)

        self.assertIn(code, (0, None))
        self.assertTrue(summary_written)
        self.assertIn("Warning: --explain bedrock produced no narrative", err)
        self.assertIn("AccessDeniedException", err)

    def test_missing_boto3_fallback_is_reported(self):
        _, err, _ = self._run_cli(ExplanationBundle(generated_by="none"))

        self.assertIn("boto3 is not installed", err)

    def test_successful_narrative_prints_no_warning(self):
        bundle = ExplanationBundle(executive_summary="Early stage.", generated_by="model-x")
        _, err, _ = self._run_cli(bundle)

        self.assertNotIn("Warning", err)


if __name__ == "__main__":
    unittest.main()
