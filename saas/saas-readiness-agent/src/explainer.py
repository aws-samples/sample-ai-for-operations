# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Optional LLM explanation adapter.

This module is the ONLY place an LLM may be invoked in this project, and even
here it is deliberately kept out of the scoring path. The design notes are
explicit about this boundary: "The LLM should NOT decide scores. Deterministic
code should score; the LLM should explain." Concretely that means:

  - Explainers receive an already-computed AssessmentResult (scores,
    statuses, confidence, gates all final) and may only return additional
    prose strings to attach to the report.
  - Explainers can never see or return anything that agent.py would treat as
    a status, score, or confidence value. The return type below
    (ExplanationBundle) only has string/tuple-of-string fields for exactly
    this reason - there is no field an explainer could populate that would
    change a control's status.
  - No-LLM mode is the default and must keep working with zero optional
    dependencies installed. NoopExplainer is what runs by default.
  - Prompts sent to a real model must never include raw customer secrets or
    unredacted sensitive values. build_explanation_prompt() below only ever
    receives already-redacted AssessmentResult data, since agent.py always
    sanitizes before this point (see Redactor).

Runtime modes from the design notes map directly to the two explainer
implementations here:
  - "No-LLM mode": NoopExplainer (deterministic scan/score/report only).
  - "LLM-assisted mode": BedrockExplainer (deterministic score, plus a model-
    generated narrative layer using the same JSON evidence).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

try:
    from src.config import load_bedrock_model
    from src.observability import get_logger
except ModuleNotFoundError:  # pragma: no cover - supports direct execution from src/
    from config import load_bedrock_model  # type: ignore[import-not-found, no-redef]
    from observability import get_logger  # type: ignore[import-not-found, no-redef]

_LOGGER = get_logger("explainer")


def _error_code(exc: Exception) -> str:
    """AWS error code from a botocore-style error, else the exception type."""

    response = getattr(exc, "response", None)
    if isinstance(response, Mapping):
        error = response.get("Error")
        if isinstance(error, Mapping) and error.get("Code"):
            return str(error["Code"])
    return type(exc).__name__


@dataclass(frozen=True)
class ExplanationBundle:
    """Additional prose an explainer may contribute to a report.

    Every field here is free text or a tuple of free text. None of them can
    represent a status, score, or confidence value, which is what makes it
    structurally impossible for an explainer to alter scoring even by
    accident - there is simply no field for it to write to.
    """

    executive_summary: str = ""
    dimension_narratives: dict[str, str] = field(default_factory=dict)
    contradictions: tuple[str, ...] = ()
    generated_by: str = "none"
    # Why no narrative was produced (AWS error code or exception type), so
    # callers can surface the fallback instead of failing silently.
    failure_reason: str = ""


class Explainer(Protocol):
    """Anything that can turn a finished assessment into extra narrative text."""

    def explain(self, assessment: Mapping[str, Any]) -> ExplanationBundle: ...


class NoopExplainer:
    """Default explainer. Adds no narrative text and calls no model.

    This is what --no-llm (and the absence of any --explain flag) selects.
    It exists so "no LLM installed or configured" is a first-class, fully
    supported, zero-dependency mode rather than a degraded fallback path.
    """

    def explain(self, assessment: Mapping[str, Any]) -> ExplanationBundle:
        return ExplanationBundle(generated_by="none")


def build_explanation_prompt(assessment: Mapping[str, Any]) -> str:
    """Build a structured, evidence-grounded prompt for an LLM explainer.

    The prompt is built entirely from the already-scored, already-redacted
    assessment payload. It explicitly instructs the model not to change any
    status/score/confidence value, and to ground every sentence in the
    supplied evidence rather than general SaaS knowledge, mirroring the
    rubric's "AWS source references are rationale, not proof" rule.
    """

    dimensions = assessment.get("dimensions", [])
    weak_points = [
        f"- {dim.get('name')}: {dim.get('score')} / 5 (confidence: {dim.get('confidence')})"
        for dim in dimensions
        if isinstance(dim.get("score"), int | float) and dim["score"] <= 2
    ]
    evidence_gaps = assessment.get("evidence_gaps", [])

    return (
        "You are writing a short, plain-language explanation of a SaaS readiness "
        "assessment for a technical founder or engineering lead. The scores, "
        "statuses, and confidence levels below are FINAL and were computed by "
        "deterministic code. Do not propose different scores, statuses, or "
        "confidence levels anywhere in your response. Only explain what is "
        "already there, in plain language, grounded strictly in the evidence "
        "summaries provided. If evidence is thin, say so plainly instead of "
        "inferring additional detail.\n\n"
        f"Overall score: {assessment.get('overall_score')} / 5 "
        f"(confidence: {assessment.get('overall_confidence')}).\n\n"
        "Weakest dimensions:\n"
        + ("\n".join(weak_points) if weak_points else "- None scored at or below 2 / 5.")
        + "\n\nEvidence gaps (unknown status, missing permission or unanswered question):\n"
        + ("\n".join(f"- {gap}" for gap in evidence_gaps[:15]) if evidence_gaps else "- None.")
        + "\n\nWrite a 3-5 sentence executive summary a non-technical stakeholder "
        "could read first, and one sentence per weak dimension explaining, in "
        "plain language, why it scored the way it did based on the evidence above.\n\n"
        "Full assessment JSON for grounding (do not restate this verbatim):\n"
        + json.dumps(assessment, indent=2, sort_keys=True)[:12000]
    )


class BedrockExplainer:
    """Optional explainer that calls Amazon Bedrock for narrative text only.

    Import of boto3 is deferred to construction time so the rest of the
    project has zero required dependency on it, matching NoopExplainer being
    the default. Model ID and region default to BEDROCK_MODEL_ID and
    BEDROCK_REGION from src/config.py, the same settings the agent uses.

    Failures never fail the assessment, but they are not silent: each one is
    logged (stage, exception type, AWS error code) and recorded in
    ExplanationBundle.failure_reason for the caller to report.
    """

    def __init__(self, model_id: str | None = None, region: str | None = None) -> None:
        import boto3  # type: ignore[import-not-found]  # noqa: F401 - optional dependency

        default_model_id, default_region = load_bedrock_model()
        self._boto3 = boto3
        self._model_id = model_id or default_model_id
        self._region = region or default_region

    def _failed(self, generated_by: str, stage: str, exc: Exception) -> ExplanationBundle:
        reason = _error_code(exc)
        _LOGGER.warning(
            "explainer_failed",
            extra={
                "stage": stage,
                "error_type": type(exc).__name__,
                "error_code": reason,
                "model_id": self._model_id,
            },
        )
        return ExplanationBundle(generated_by=generated_by, failure_reason=reason)

    def explain(self, assessment: Mapping[str, Any]) -> ExplanationBundle:
        try:
            client = (
                self._boto3.client("bedrock-runtime", region_name=self._region)
                if self._region
                else self._boto3.client("bedrock-runtime")
            )
        except Exception as exc:  # noqa: BLE001 - degrade to no narrative rather than fail the assessment
            return self._failed("bedrock-unavailable", "client", exc)

        prompt = build_explanation_prompt(assessment)
        try:
            response = client.invoke_model(
                modelId=self._model_id,
                body=json.dumps(
                    {
                        "anthropic_version": "bedrock-2023-05-31",
                        "max_tokens": 1024,
                        "messages": [{"role": "user", "content": prompt}],
                    }
                ),
                contentType="application/json",
                accept="application/json",
            )
            payload = json.loads(response["body"].read())
            text = "".join(
                block.get("text", "")
                for block in payload.get("content", [])
                if isinstance(block, Mapping)
            ).strip()
        except Exception as exc:  # noqa: BLE001 - a failed model call must not fail the assessment
            return self._failed("bedrock-error", "invoke_model", exc)

        return ExplanationBundle(executive_summary=text, generated_by=self._model_id)


def build_explainer(mode: str, model_id: str | None = None, region: str | None = None) -> Explainer:
    """Factory selecting an explainer by name. Defaults to NoopExplainer.

    `mode` values: "none" (default, no-LLM mode) or "bedrock" (LLM-assisted
    mode). Any unrecognized value falls back to NoopExplainer rather than
    raising, so a typo in a CLI flag degrades safely instead of crashing the
    assessment.
    """

    if mode == "bedrock":
        try:
            return BedrockExplainer(model_id=model_id, region=region)
        except ModuleNotFoundError:
            _LOGGER.warning(
                "explainer_failed", extra={"stage": "import", "error_code": "boto3-missing"}
            )
            return NoopExplainer()
    return NoopExplainer()
