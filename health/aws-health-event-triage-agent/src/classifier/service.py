# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Classifier service — orchestrates the Strands classification agent.

Flow:
  1. Load system prompt (embedded file or S3 override).
  2. Inject the current event into the get_affected_entities registry.
  3. Build the agent with three read-only tools.
  4. Invoke the agent with the consolidated event as input.
  5. Parse and schema-validate the JSON response.
  6. On schema failure: retry once with the error appended.
  7. On second failure: return UNCLASSIFIED with reason "schema_failure".

The model never produces a count, urgency, cost, or HTML — only the six
classification fields defined in classification_result_v1.json.
"""

from __future__ import annotations

import json
import logging
import random
import time
from pathlib import Path
from typing import Any

from src import config
from src.tools.get_affected_entities import set_current_event
from src.tools.get_affected_entities import get_affected_entities
from src.tools.get_event_type_guidance import get_event_type_guidance
from src.tools.normalize_dates import normalize_dates

logger = logging.getLogger(__name__)

_SCHEMA_PATH = Path(__file__).parents[1] / "schemas" / "classification_result_v1.json"
_PROMPT_PATH = Path(__file__).parents[1] / "prompts" / "classifier.md"

# fix-guardrail-not-wired (PCSR blocker 3, DOS2): base delay for the
# jittered exponential backoff applied between agent-invocation retries.
# Full-jitter per AWS's own retry guidance — a random delay in
# [0, base * 2**attempt] avoids every concurrent Lambda invocation retrying
# in lockstep against a throttled Bedrock endpoint.
_RETRY_BASE_DELAY_SECONDS = 0.5

# Sentinel result returned when the LLM output cannot be validated
_UNCLASSIFIED_FALLBACK = {
    "classification": "UNCLASSIFIED",
    "reason": "schema_failure: The model response could not be validated against the ClassificationResult schema after two attempts.",
    "deadline": None,
    "deadline_basis": None,
    "verification_steps": [
        "Review the original AWS Health event in the AWS Health Dashboard.",
        "Contact AWS Support if the event requires immediate action.",
    ],
    "notes_for_operator": None,
}


def _load_schema() -> dict:
    with open(_SCHEMA_PATH, encoding='utf-8') as f:
        return json.load(f)


def _load_prompt() -> str:
    """Load the classifier system prompt from S3 if configured, else from file."""
    bucket = config.SYSTEM_PROMPT_S3_BUCKET
    if bucket:
        key = config.SYSTEM_PROMPT_S3_KEY.replace("system_prompt.txt", "classifier.md")
        try:
            import boto3
            s3 = boto3.client("s3", region_name=config.AWS_REGION)
            obj = s3.get_object(Bucket=bucket, Key=key)
            prompt = obj["Body"].read().decode("utf-8")
            logger.info("Classifier prompt loaded from s3://%s/%s", bucket, key)
            return prompt
        except Exception as exc:
            logger.warning("Failed to load classifier prompt from S3: %s — using embedded", exc)
    with open(_PROMPT_PATH, encoding='utf-8') as f:
        return f.read()


def _validate(result: dict, schema: dict) -> list[str]:
    """Validate result against schema; return list of error strings (empty = valid)."""
    errors: list[str] = []
    required = schema.get("required", [])
    properties = schema.get("properties", {})

    for field in required:
        if field not in result:
            errors.append(f"Missing required field: '{field}'")

    # Validate classification enum
    if "classification" in result:
        enum_vals = properties.get("classification", {}).get("enum", [])
        if enum_vals and result["classification"] not in enum_vals:
            errors.append(
                f"Invalid classification '{result['classification']}'. "
                f"Must be one of: {enum_vals}"
            )

    # Validate reason min length
    if "reason" in result:
        min_len = properties.get("reason", {}).get("minLength", 0)
        if len(result.get("reason", "")) < min_len:
            errors.append(f"'reason' must be at least {min_len} characters")

    return errors


def _extract_json(text: str) -> dict | None:
    """Extract the first JSON object from a potentially prose-wrapped response."""
    # Direct parse
    try:
        return json.loads(text.strip())
    except json.JSONDecodeError:
        pass
    # Look for ```json ... ``` fences
    import re
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    # Look for first { ... } block
    m2 = re.search(r"\{.*\}", text, re.DOTALL)
    if m2:
        try:
            return json.loads(m2.group(0))
        except json.JSONDecodeError:
            pass
    return None


class ClassifierService:
    """Runs the Strands classification agent for a single consolidated event."""

    def __init__(self, agent=None):
        self._agent = agent  # injected in tests; None → create lazily
        self._schema = _load_schema()

    def _get_agent(self):
        if self._agent is not None:
            return self._agent
        from strands import Agent
        from strands.models import BedrockModel

        prompt = _load_prompt()
        model_kwargs: dict[str, Any] = {
            "model_id": config.BEDROCK_MODEL_ID,
            "region_name": config.BEDROCK_REGION,
        }
        if config.GUARDRAIL_ID:
            model_kwargs["guardrail_id"] = config.GUARDRAIL_ID
            model_kwargs["guardrail_version"] = config.GUARDRAIL_VERSION

        model = BedrockModel(**model_kwargs)
        self._agent = Agent(
            model=model,
            system_prompt=prompt,
            tools=[get_event_type_guidance, get_affected_entities, normalize_dates],
        )
        return self._agent

    def classify(self, event: dict) -> dict:
        """Classify a consolidated health event.

        Args:
            event: A consolidated event dict (output of the Intake Lambda merge).

        Returns:
            A ClassificationResult dict validated against the schema.
            Falls back to UNCLASSIFIED on persistent validation failure.
        """
        # Inject event for get_affected_entities
        set_current_event(event)

        user_input = (
            "Classify the following AWS Health event. "
            "Return only a JSON object matching the ClassificationResult schema.\n\n"
            f"Event ARN: {event.get('eventArn', '')}\n"
            f"Service: {event.get('service', '')}\n"
            f"Event type code: {event.get('eventTypeCode', '')}\n"
            f"Category: {event.get('eventTypeCategory', '')}\n"
            f"Status: {event.get('statusCode', '')}\n"
            f"Affected accounts: {len(event.get('affectedAccounts', []))}\n"
            f"Actionability: {event.get('actionability', '')}\n\n"
            f"--- BEGIN EVENT DESCRIPTION ---\n"
            f"{event.get('eventDescription', '(no description)')}\n"
            f"--- END EVENT DESCRIPTION ---"
        )

        for attempt in range(2):
            try:
                agent = self._get_agent()
                response = agent(user_input)
                response_text = str(response)
            except Exception as exc:
                logger.error("Agent invocation failed (attempt %d): %s", attempt + 1, exc)
                if attempt == 1:
                    return dict(_UNCLASSIFIED_FALLBACK)
                # fix-guardrail-not-wired (PCSR blocker 3, DOS2): jittered
                # exponential backoff before retrying — previously retried
                # immediately with no delay, so a Bedrock throttling
                # exception was retried at the same rate that caused it.
                delay = random.uniform(0, _RETRY_BASE_DELAY_SECONDS * (2 ** attempt))  # nosec B311 -- jittered retry-backoff delay, not a cryptographic value
                logger.info("Retrying agent invocation in %.2fs", delay)
                time.sleep(delay)
                continue

            parsed = _extract_json(response_text)
            if parsed is None:
                logger.warning("Attempt %d: could not extract JSON from response", attempt + 1)
                user_input += "\n\nYour previous response was not valid JSON. Return ONLY the JSON object."
                continue

            errors = _validate(parsed, self._schema)
            if not errors:
                return parsed

            logger.warning("Attempt %d schema errors: %s", attempt + 1, errors)
            user_input += (
                f"\n\nYour previous response failed schema validation:\n"
                + "\n".join(f"- {e}" for e in errors)
                + "\n\nPlease fix and return only the corrected JSON object."
            )

        return dict(_UNCLASSIFIED_FALLBACK)
