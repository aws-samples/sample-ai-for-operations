# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Unit tests for src.triage.disposition.decide_disposition."""

from __future__ import annotations

import pytest

from src.triage.disposition import DIGEST, TICKET, decide_disposition


class TestClassDefaults:
    """Default per-classification disposition without overrides."""

    def _decide(self, classification: str) -> str:
        return decide_disposition(classification, "AWS_GENERIC_EVENT", overrides={})["disposition"]

    def test_service_disruption_is_ticket(self):
        assert self._decide("SERVICE_DISRUPTION") == TICKET

    def test_breaking_change_is_ticket(self):
        assert self._decide("BREAKING_CHANGE") == TICKET

    def test_security_related_is_ticket(self):
        assert self._decide("SECURITY_RELATED") == TICKET

    def test_cost_implication_is_ticket(self):
        assert self._decide("COST_IMPLICATION") == TICKET

    def test_informational_is_digest(self):
        assert self._decide("INFORMATIONAL") == DIGEST

    def test_unclassified_is_ticket(self):
        assert self._decide("UNCLASSIFIED") == TICKET

    def test_unknown_classification_is_ticket(self):
        assert self._decide("FUTURE_CLASS") == TICKET


class TestCodeOverrides:
    """Per-code overrides take precedence over class defaults."""

    def test_override_forces_digest(self):
        overrides = {
            "AWS_EKS_FARGATE_POD_EVICTIONS": {
                "eventTypeCode": "AWS_EKS_FARGATE_POD_EVICTIONS",
                "disposition": DIGEST,
                "precheck": "fargate_posture",
                "note": "Run precheck before ticketing.",
            }
        }
        result = decide_disposition("BREAKING_CHANGE", "AWS_EKS_FARGATE_POD_EVICTIONS", overrides=overrides)
        assert result["disposition"] == DIGEST
        assert result["rule"] == "code_override"
        assert result["precheck"] == "fargate_posture"

    def test_override_forces_ticket_on_informational(self):
        overrides = {
            "AWS_SHIELD_ADVANCED_RENEWAL": {
                "eventTypeCode": "AWS_SHIELD_ADVANCED_RENEWAL",
                "disposition": TICKET,
                "precheck": None,
                "note": "Always ticket shield renewals.",
            }
        }
        result = decide_disposition("INFORMATIONAL", "AWS_SHIELD_ADVANCED_RENEWAL", overrides=overrides)
        assert result["disposition"] == TICKET

    def test_no_override_uses_class_default(self):
        result = decide_disposition("INFORMATIONAL", "AWS_SOME_NOTICE", overrides={})
        assert result["disposition"] == DIGEST
        assert result["rule"] == "class_default"

    def test_override_includes_precheck_for_msk(self):
        overrides = {
            "AWS_KAFKA_SECURITY_PATCHING_EVENT": {
                "eventTypeCode": "AWS_KAFKA_SECURITY_PATCHING_EVENT",
                "disposition": DIGEST,
                "precheck": "msk_patch_safety",
                "note": "Safety check before digest.",
            }
        }
        result = decide_disposition("SECURITY_RELATED", "AWS_KAFKA_SECURITY_PATCHING_EVENT", overrides=overrides)
        assert result["precheck"] == "msk_patch_safety"
        assert result["disposition"] == DIGEST


class TestResultShape:
    def test_result_has_required_keys(self):
        result = decide_disposition("BREAKING_CHANGE", "AWS_GENERIC_EVENT", overrides={})
        assert "disposition" in result
        assert "precheck" in result
        assert "rule" in result
        assert "note" in result

    def test_no_precheck_when_class_default(self):
        result = decide_disposition("BREAKING_CHANGE", "AWS_GENERIC_EVENT", overrides={})
        assert result["precheck"] is None
