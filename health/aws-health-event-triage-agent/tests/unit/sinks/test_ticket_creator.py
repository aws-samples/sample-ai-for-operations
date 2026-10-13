# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Unit tests for the ticket creator tool.

Requirements covered: 12.1, 12.2, 12.3, 12.4, 12.5
"""

from __future__ import annotations

import pytest

from src.sinks import ticket_creator
from src.sinks.ticket_creator import create_jira_ticket

_create = create_jira_ticket._tool_func


def _notif(
    arn: str = "arn:aws:health:us-east-1::event/EKS/123",
    service: str = "EKS",
    event_type: str = "AWS_EKS_PLANNED_LIFECYCLE_EVENT",
    description: str = "EKS version deprecated",
) -> dict:
    return {
        "arn": arn,
        "service": service,
        "eventTypeCode": event_type,
        "eventDescription": description,
    }


def _impact(
    action_required: bool = True,
    risk_level: str = "high",
    accounts: list[dict] | None = None,
) -> dict:
    return {
        "notification_id": "arn:test",
        "action_required": action_required,
        "risk_level": risk_level,
        "affected_accounts": accounts or [
            {
                "account_id": "111111111111",
                "environment_type": "production",
                "affected_resources": ["arn:resource:1"],
                "required_action": "Upgrade EKS cluster",
            },
        ],
        "summary": "EKS breaking change affects 1 account(s)",
    }


def _mock_aha_success(payload: dict) -> dict:
    return {"ticket_id": "OPS-1234", "url": "https://jira.example.com/browse/OPS-1234"}


def _mock_aha_failure(payload: dict) -> dict:
    raise RuntimeError("AHA Jira integration timeout")


@pytest.fixture(autouse=True)
def _reset():
    ticket_creator._ticket_ledger.clear()
    original = ticket_creator.aha_jira_create
    yield
    ticket_creator._ticket_ledger.clear()
    ticket_creator.aha_jira_create = original


# ---------------------------------------------------------------------------
# Req 12.1 – Successful ticket creation
# ---------------------------------------------------------------------------

class TestSuccessfulCreation:

    def test_ticket_created_with_mocked_aha(self):
        ticket_creator.aha_jira_create = _mock_aha_success
        result = _create(notification=_notif(), impact_summary=_impact())
        assert result["status"] == "created"
        assert result["ticket_id"] == "OPS-1234"
        assert result["url"] == "https://jira.example.com/browse/OPS-1234"

    def test_ticket_description_includes_accounts(self):
        """Verify the AHA payload includes affected account info (Req 12.2)."""
        captured = {}

        def capture_aha(payload):
            captured.update(payload)
            return {"ticket_id": "OPS-99", "url": "https://jira.example.com/browse/OPS-99"}

        ticket_creator.aha_jira_create = capture_aha
        _create(notification=_notif(), impact_summary=_impact())
        assert "111111111111" in captured["description"]


# ---------------------------------------------------------------------------
# Req 12.3 – Team assignment based on affected services
# ---------------------------------------------------------------------------

class TestTeamAssignment:

    def test_eks_assigned_to_kubernetes_team(self):
        ticket_creator.aha_jira_create = _mock_aha_success
        result = _create(notification=_notif(service="EKS"), impact_summary=_impact())
        assert result["team"] == "Platform-Kubernetes"

    def test_rds_assigned_to_database_team(self):
        ticket_creator.aha_jira_create = _mock_aha_success
        result = _create(notification=_notif(service="RDS"), impact_summary=_impact())
        assert result["team"] == "Platform-Database"

    def test_unknown_service_assigned_to_default_team(self):
        ticket_creator.aha_jira_create = _mock_aha_success
        result = _create(notification=_notif(service="NEWSERVICE"), impact_summary=_impact())
        assert result["team"] == "Platform-Operations"


# ---------------------------------------------------------------------------
# Req 12.4 – Duplicate prevention
# ---------------------------------------------------------------------------

class TestDeduplication:

    def test_related_notifications_link_to_single_ticket(self):
        ticket_creator.aha_jira_create = _mock_aha_success
        # Same event type + service → same dedup key
        r1 = _create(notification=_notif(), impact_summary=_impact())
        r2 = _create(notification=_notif(arn="arn:different"), impact_summary=_impact())
        assert r1["ticket_id"] == r2["ticket_id"]
        assert r2.get("deduplicated") is True

    def test_different_events_create_separate_tickets(self):
        call_count = 0

        def counting_aha(payload):
            nonlocal call_count
            call_count += 1
            return {"ticket_id": f"OPS-{call_count}", "url": f"https://jira.example.com/browse/OPS-{call_count}"}

        ticket_creator.aha_jira_create = counting_aha
        r1 = _create(notification=_notif(service="EKS", event_type="EKS_EVENT"), impact_summary=_impact())
        r2 = _create(notification=_notif(service="RDS", event_type="RDS_EVENT"), impact_summary=_impact())
        assert r1["ticket_id"] != r2["ticket_id"]


# ---------------------------------------------------------------------------
# Req 12.5 – AHA Jira failure
# ---------------------------------------------------------------------------

class TestAhaFailure:

    def test_aha_failure_returns_failed_status(self):
        ticket_creator.aha_jira_create = _mock_aha_failure
        result = _create(notification=_notif(), impact_summary=_impact())
        assert result["status"] == "failed"
        assert "error" in result
        assert "AHA Jira integration" in result["error"]

    def test_aha_not_configured_returns_failed(self):
        ticket_creator.aha_jira_create = None
        result = _create(notification=_notif(), impact_summary=_impact())
        assert result["status"] == "failed"
        assert "not configured" in result["error"]
