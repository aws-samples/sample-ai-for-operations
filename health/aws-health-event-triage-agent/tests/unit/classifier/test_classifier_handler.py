# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Unit tests for src.classifier.handler — the Lambda entry point."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from src.classifier import handler as handler_mod
from src.classifier.handler import handler

_SAMPLE_EVENT = {
    "eventArn": "arn:aws:health:us-east-1::event/EKS/TEST/001",
    "service": "EKS",
    "eventTypeCode": "AWS_EKS_PLANNED_LIFECYCLE_EVENT",
    "eventTypeCategory": "scheduledChange",
    "statusCode": "upcoming",
    "affectedAccounts": ["123456789012"],
    "affectedEntities": {},
    "eventDescription": "EKS clusters will be auto-upgraded after September 1, 2026.",
    "actionability": "ACTIONABLE",
}

_CLASSIFY_RESULT = {
    "classification": "BREAKING_CHANGE",
    "reason": "EKS clusters will be auto-upgraded after end-of-support.",
    "deadline": "2026-09-01",
    "deadline_basis": "September 1, 2026",
    "verification_steps": ["Check cluster version"],
    "notes_for_operator": None,
}


def _make_handler_event(consolidated=None):
    return {
        "eventArn": _SAMPLE_EVENT["eventArn"],
        "event": consolidated or _SAMPLE_EVENT,
    }


class TestHandlerOutput:
    """classifier/handler.py classifies only — urgency and disposition are
    separate Step Functions states (ComputeUrgency, DecideDisposition),
    each their own Lambda invocation, per design.md's state diagram
    (Classify --> ComputeUrgency --> DecideDisposition). Fusing them into
    this handler was a real wiring bug found and fixed during Build
    validation (a real cdk deploy + test event surfaced "Unknown step:
    CLASSIFY" because this Lambda was never meant to be invoked with a
    step dispatch at all — it always classifies unconditionally)."""

    def test_returns_classification(self):
        mock_service = MagicMock()
        mock_service.classify.return_value = _CLASSIFY_RESULT
        original = handler_mod._service
        handler_mod._service = mock_service
        try:
            result = handler(_make_handler_event(), None)
            assert result["classification"] == "BREAKING_CHANGE"
        finally:
            handler_mod._service = original

    def test_does_not_compute_urgency_or_disposition(self):
        """Confirms the handler no longer fuses ComputeUrgency/DecideDisposition
        into this Lambda's output — those are separate workflow states."""
        mock_service = MagicMock()
        mock_service.classify.return_value = _CLASSIFY_RESULT
        original = handler_mod._service
        handler_mod._service = mock_service
        try:
            result = handler(_make_handler_event(), None)
            assert "urgency" not in result
            assert "disposition" not in result
            assert "precheck" not in result
        finally:
            handler_mod._service = original

    def test_returns_reason_deadline_and_verification_steps(self):
        mock_service = MagicMock()
        mock_service.classify.return_value = _CLASSIFY_RESULT
        original = handler_mod._service
        handler_mod._service = mock_service
        try:
            result = handler(_make_handler_event(), None)
            assert result["reason"] == _CLASSIFY_RESULT["reason"]
            assert result["deadline"] == _CLASSIFY_RESULT["deadline"]
            assert result["deadline_basis"] == _CLASSIFY_RESULT["deadline_basis"]
            assert result["verification_steps"] == _CLASSIFY_RESULT["verification_steps"]
            assert result["notes_for_operator"] == _CLASSIFY_RESULT["notes_for_operator"]
        finally:
            handler_mod._service = original

    def test_event_arn_preserved(self):
        mock_service = MagicMock()
        mock_service.classify.return_value = _CLASSIFY_RESULT
        original = handler_mod._service
        handler_mod._service = mock_service
        try:
            result = handler(_make_handler_event(), None)
            assert result["eventArn"] == _SAMPLE_EVENT["eventArn"]
        finally:
            handler_mod._service = original

    def test_informational_classification_passed_through(self):
        mock_service = MagicMock()
        mock_service.classify.return_value = {
            **_CLASSIFY_RESULT,
            "classification": "INFORMATIONAL",
            "deadline": None,
        }
        original = handler_mod._service
        handler_mod._service = mock_service
        try:
            result = handler(_make_handler_event(), None)
            assert result["classification"] == "INFORMATIONAL"
            assert result["deadline"] is None
        finally:
            handler_mod._service = original

    def test_service_disruption_classification_passed_through(self):
        mock_service = MagicMock()
        mock_service.classify.return_value = {
            **_CLASSIFY_RESULT,
            "classification": "SERVICE_DISRUPTION",
            "deadline": None,
        }
        original = handler_mod._service
        handler_mod._service = mock_service
        try:
            result = handler(_make_handler_event(), None)
            assert result["classification"] == "SERVICE_DISRUPTION"
        finally:
            handler_mod._service = original

    def test_string_event_body_deserialized(self):
        """handler accepts event.event as a JSON string."""
        mock_service = MagicMock()
        mock_service.classify.return_value = _CLASSIFY_RESULT
        original = handler_mod._service
        handler_mod._service = mock_service
        try:
            result = handler(
                {"eventArn": _SAMPLE_EVENT["eventArn"], "event": json.dumps(_SAMPLE_EVENT)},
                None,
            )
            assert result["classification"] == "BREAKING_CHANGE"
        finally:
            handler_mod._service = original

    def test_unclassified_fallback_from_service(self):
        mock_service = MagicMock()
        mock_service.classify.return_value = {
            "classification": "UNCLASSIFIED",
            "reason": "schema_failure: Could not validate.",
            "deadline": None,
            "deadline_basis": None,
            "verification_steps": [],
            "notes_for_operator": None,
        }
        original = handler_mod._service
        handler_mod._service = mock_service
        try:
            result = handler(_make_handler_event(), None)
            assert result["classification"] == "UNCLASSIFIED"
        finally:
            handler_mod._service = original
