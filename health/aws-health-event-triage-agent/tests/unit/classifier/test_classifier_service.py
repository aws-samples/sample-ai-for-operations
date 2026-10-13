# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Unit tests for src.classifier.service.ClassifierService.

The Strands agent is replaced by a mock callable so no Bedrock calls are made.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from src.classifier.service import (
    ClassifierService,
    _UNCLASSIFIED_FALLBACK,
    _extract_json,
    _validate,
)

EVENT_ARN = "arn:aws:health:us-east-1::event/EKS/TEST/001"

_VALID_RESULT = {
    "classification": "BREAKING_CHANGE",
    "reason": "The EKS cluster will be auto-upgraded after end-of-standard-support on 2026-09-01.",
    "deadline": "2026-09-01",
    "deadline_basis": "end-of-standard-support on 2026-09-01",
    "verification_steps": ["Check cluster version", "Plan upgrade"],
    "notes_for_operator": None,
}

_SAMPLE_EVENT = {
    "eventArn": EVENT_ARN,
    "service": "EKS",
    "eventTypeCode": "AWS_EKS_PLANNED_LIFECYCLE_EVENT",
    "eventTypeCategory": "scheduledChange",
    "statusCode": "upcoming",
    "affectedAccounts": ["123456789012"],
    "affectedEntities": {},
    "eventDescription": "Your EKS cluster will reach end-of-standard-support on September 1, 2026.",
    "actionability": "ACTIONABLE",
}


def _mock_agent(response: str):
    """Return a mock agent callable that returns response."""
    agent = MagicMock()
    agent.return_value = response
    return agent


class TestValidResponse:
    def test_returns_valid_classification_result(self):
        service = ClassifierService(agent=_mock_agent(json.dumps(_VALID_RESULT)))
        result = service.classify(_SAMPLE_EVENT)
        assert result["classification"] == "BREAKING_CHANGE"
        assert result["deadline"] == "2026-09-01"

    def test_reason_preserved(self):
        service = ClassifierService(agent=_mock_agent(json.dumps(_VALID_RESULT)))
        result = service.classify(_SAMPLE_EVENT)
        assert "auto-upgraded" in result["reason"]

    def test_verification_steps_returned(self):
        service = ClassifierService(agent=_mock_agent(json.dumps(_VALID_RESULT)))
        result = service.classify(_SAMPLE_EVENT)
        assert isinstance(result["verification_steps"], list)
        assert len(result["verification_steps"]) == 2


class TestSchemaFallback:
    def test_invalid_json_falls_back_to_unclassified(self):
        service = ClassifierService(agent=_mock_agent("This is not JSON at all."))
        result = service.classify(_SAMPLE_EVENT)
        assert result["classification"] == "UNCLASSIFIED"
        assert "schema_failure" in result["reason"]

    def test_wrong_classification_enum_falls_back(self):
        bad = {**_VALID_RESULT, "classification": "INVALID_CLASS"}
        service = ClassifierService(agent=_mock_agent(json.dumps(bad)))
        result = service.classify(_SAMPLE_EVENT)
        assert result["classification"] == "UNCLASSIFIED"

    def test_missing_reason_field_falls_back(self):
        bad = {k: v for k, v in _VALID_RESULT.items() if k != "reason"}
        service = ClassifierService(agent=_mock_agent(json.dumps(bad)))
        result = service.classify(_SAMPLE_EVENT)
        assert result["classification"] == "UNCLASSIFIED"

    def test_short_reason_falls_back(self):
        bad = {**_VALID_RESULT, "reason": "Short."}
        # 6 chars < minLength 10
        service = ClassifierService(agent=_mock_agent(json.dumps(bad)))
        result = service.classify(_SAMPLE_EVENT)
        assert result["classification"] == "UNCLASSIFIED"

    def test_second_attempt_succeeds(self):
        """First response invalid JSON, second response valid."""
        call_count = {"n": 0}
        def side_effect(prompt):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return "not json"
            return json.dumps(_VALID_RESULT)

        mock_agent = MagicMock()
        mock_agent.side_effect = side_effect
        service = ClassifierService(agent=mock_agent)
        result = service.classify(_SAMPLE_EVENT)
        assert result["classification"] == "BREAKING_CHANGE"


class TestRetryBackoff:
    """PCSR blocker 3 / DOS2: agent-invocation retries must back off, not
    retry immediately at the same rate that caused a throttling exception."""

    def test_sleeps_between_retries_on_exception(self):
        mock_agent = MagicMock(side_effect=Exception("ThrottlingException"))
        service = ClassifierService(agent=mock_agent)
        with patch("src.classifier.service.time.sleep") as mock_sleep:
            result = service.classify(_SAMPLE_EVENT)
        assert result["classification"] == "UNCLASSIFIED"
        assert mock_agent.call_count == 2
        # One retry after the first failure; no sleep after the final
        # (second) failure since the loop returns immediately.
        mock_sleep.assert_called_once()
        (delay,), _ = mock_sleep.call_args
        assert 0 <= delay <= 1.0  # _RETRY_BASE_DELAY_SECONDS * 2**0 upper bound

    def test_no_sleep_when_first_attempt_succeeds(self):
        service = ClassifierService(agent=_mock_agent(json.dumps(_VALID_RESULT)))
        with patch("src.classifier.service.time.sleep") as mock_sleep:
            service.classify(_SAMPLE_EVENT)
        mock_sleep.assert_not_called()


class TestJsonExtraction:
    def test_direct_json(self):
        data = {"classification": "INFORMATIONAL", "reason": "No action needed."}
        assert _extract_json(json.dumps(data))["classification"] == "INFORMATIONAL"

    def test_fenced_json(self):
        text = '```json\n{"classification": "BREAKING_CHANGE", "reason": "Test."}\n```'
        assert _extract_json(text)["classification"] == "BREAKING_CHANGE"

    def test_prose_wrapped_json(self):
        text = 'Here is the result: {"classification": "INFORMATIONAL", "reason": "Renewal."} Done.'
        assert _extract_json(text)["classification"] == "INFORMATIONAL"

    def test_no_json_returns_none(self):
        assert _extract_json("No JSON here at all.") is None


class TestValidationHelper:
    def test_valid_result_no_errors(self):
        from src.classifier.service import _load_schema
        schema = _load_schema()
        errors = _validate(_VALID_RESULT, schema)
        assert errors == []

    def test_missing_required_field_reported(self):
        from src.classifier.service import _load_schema
        schema = _load_schema()
        bad = {k: v for k, v in _VALID_RESULT.items() if k != "classification"}
        errors = _validate(bad, schema)
        assert any("classification" in e for e in errors)

    def test_invalid_enum_reported(self):
        from src.classifier.service import _load_schema
        schema = _load_schema()
        bad = {**_VALID_RESULT, "classification": "MADE_UP"}
        errors = _validate(bad, schema)
        assert any("MADE_UP" in e for e in errors)
