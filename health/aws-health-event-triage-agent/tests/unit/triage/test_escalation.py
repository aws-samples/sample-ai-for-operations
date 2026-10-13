# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Unit tests for src.triage.disposition.escalate_on_precheck_failure."""

from __future__ import annotations

import pytest

from src.triage.disposition import DIGEST, TICKET, escalate_on_precheck_failure


def _disposition(disposition=DIGEST, precheck="fargate_posture"):
    return {"disposition": disposition, "precheck": precheck, "rule": "code_override", "note": "test"}


def _precheck(result="pass", precheck="fargate_posture", failing=None):
    return {
        "result": result,
        "precheck": precheck,
        "failing_resources": failing or [],
        "remediation_guidance": [],
        "reason": None,
    }


class TestEscalation:
    def test_digest_and_fail_escalates_to_ticket(self):
        result = escalate_on_precheck_failure(
            _disposition(disposition=DIGEST),
            _precheck(result="fail", failing=[{"resource": "ns/pod-1", "reason": "single replica"}]),
        )
        assert result["disposition"] == TICKET
        assert result["escalated"] is True

    def test_escalation_names_failing_resources(self):
        result = escalate_on_precheck_failure(
            _disposition(disposition=DIGEST),
            _precheck(result="fail", failing=[{"resource": "ns/pod-1", "reason": "x"}]),
        )
        assert "ns/pod-1" in result["escalation_reason"]

    def test_escalation_carries_failing_resources_forward(self):
        failing = [{"resource": "ns/pod-1", "reason": "x"}]
        result = escalate_on_precheck_failure(_disposition(disposition=DIGEST), _precheck(result="fail", failing=failing))
        assert result["failing_resources"] == failing


class TestNoEscalation:
    def test_digest_and_pass_stays_digest(self):
        result = escalate_on_precheck_failure(_disposition(disposition=DIGEST), _precheck(result="pass"))
        assert result["disposition"] == DIGEST
        assert result["escalated"] is False

    def test_digest_and_not_checked_stays_digest(self):
        result = escalate_on_precheck_failure(_disposition(disposition=DIGEST), _precheck(result="not_checked"))
        assert result["disposition"] == DIGEST
        assert result["escalated"] is False

    def test_ticket_disposition_unaffected_by_fail(self):
        """An event already TICKET-bound is not touched by escalation logic."""
        result = escalate_on_precheck_failure(_disposition(disposition=TICKET), _precheck(result="fail"))
        assert result["disposition"] == TICKET
        assert result["escalated"] is False


class TestOriginalFieldsPreserved:
    def test_precheck_name_preserved_after_escalation(self):
        result = escalate_on_precheck_failure(_disposition(disposition=DIGEST, precheck="msk_patch_safety"), _precheck(result="fail", precheck="msk_patch_safety"))
        assert result["precheck"] == "msk_patch_safety"

    def test_rule_and_note_preserved(self):
        result = escalate_on_precheck_failure(_disposition(disposition=DIGEST), _precheck(result="pass"))
        assert result["rule"] == "code_override"
        assert result["note"] == "test"
