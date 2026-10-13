# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Unit tests for the messaging notifier tools.

Requirements covered: 13.1, 13.2, 13.3, 13.4, 13.5, 13.6, 13.7
"""

from __future__ import annotations

import pytest

from src.sinks import messaging_notifier
from src.sinks.messaging_notifier import (
    send_teams_notification,
    send_slack_notification,
)

_send_teams = send_teams_notification._tool_func
_send_slack = send_slack_notification._tool_func


def _summary_with_notifications() -> dict:
    return {
        "notifications": [
            {
                "notification_id": "arn:aws:health:us-east-1::event/EKS/123",
                "classification": "BREAKING_CHANGE",
                "reason": "EKS version deprecated",
                "affected_service": "EKS",
                "affected_accounts": [
                    {"account_id": "111111111111", "environment_type": "production"},
                ],
                "impact_analysis": {
                    "action_required": True,
                    "summary": "Upgrade EKS cluster before EOL",
                },
                "jira_ticket": {
                    "ticket_id": "OPS-1234",
                    "url": "https://jira.example.com/browse/OPS-1234",
                },
            }
        ],
    }


def _empty_summary() -> dict:
    return {"notifications": []}


@pytest.fixture(autouse=True)
def _reset_webhooks():
    orig_teams = messaging_notifier.aha_teams_webhook
    orig_slack = messaging_notifier.aha_slack_webhook
    yield
    messaging_notifier.aha_teams_webhook = orig_teams
    messaging_notifier.aha_slack_webhook = orig_slack


# ---------------------------------------------------------------------------
# Req 13.1 – Successful Teams send
# ---------------------------------------------------------------------------

class TestTeamsSend:

    def test_teams_sent_successfully(self):
        captured = []
        messaging_notifier.aha_teams_webhook = lambda p: captured.append(p)
        result = _send_teams(summary=_summary_with_notifications())
        assert result["status"] == "sent"
        assert result["channel"] == "teams"
        assert len(captured) == 1

    def test_teams_webhook_failure(self):
        messaging_notifier.aha_teams_webhook = lambda p: (_ for _ in ()).throw(
            RuntimeError("Teams timeout")
        )
        result = _send_teams(summary=_summary_with_notifications())
        assert result["status"] == "failed"
        assert "Teams" in result["error"]

    def test_teams_not_configured(self):
        messaging_notifier.aha_teams_webhook = None
        result = _send_teams(summary=_summary_with_notifications())
        assert result["status"] == "failed"
        assert "not configured" in result["error"]


# ---------------------------------------------------------------------------
# Req 13.2 – Successful Slack send
# ---------------------------------------------------------------------------

class TestSlackSend:

    def test_slack_sent_successfully(self):
        captured = []
        messaging_notifier.aha_slack_webhook = lambda p: captured.append(p)
        result = _send_slack(summary=_summary_with_notifications())
        assert result["status"] == "sent"
        assert result["channel"] == "slack"
        assert len(captured) == 1

    def test_slack_webhook_failure(self):
        messaging_notifier.aha_slack_webhook = lambda p: (_ for _ in ()).throw(
            RuntimeError("Slack timeout")
        )
        result = _send_slack(summary=_summary_with_notifications())
        assert result["status"] == "failed"
        assert "Slack" in result["error"]

    def test_slack_not_configured(self):
        messaging_notifier.aha_slack_webhook = None
        result = _send_slack(summary=_summary_with_notifications())
        assert result["status"] == "failed"
        assert "not configured" in result["error"]


# ---------------------------------------------------------------------------
# Req 13.7 – No actionable notifications
# ---------------------------------------------------------------------------

class TestNoActionableNotifications:

    def test_teams_no_action_required_message(self):
        captured = []
        messaging_notifier.aha_teams_webhook = lambda p: captured.append(p)
        _send_teams(summary=_empty_summary())
        assert "no action required" in captured[0]["text"].lower()

    def test_slack_no_action_required_message(self):
        captured = []
        messaging_notifier.aha_slack_webhook = lambda p: captured.append(p)
        _send_slack(summary=_empty_summary())
        assert "no action required" in captured[0]["text"].lower()


# ---------------------------------------------------------------------------
# Req 13.3, 13.4 – Message content verification
# ---------------------------------------------------------------------------

class TestMessageContent:

    def test_message_includes_classification(self):
        captured = []
        messaging_notifier.aha_teams_webhook = lambda p: captured.append(p)
        _send_teams(summary=_summary_with_notifications())
        assert "BREAKING_CHANGE" in captured[0]["text"]

    def test_message_includes_affected_accounts(self):
        captured = []
        messaging_notifier.aha_teams_webhook = lambda p: captured.append(p)
        _send_teams(summary=_summary_with_notifications())
        assert "111111111111" in captured[0]["text"]

    def test_message_includes_required_actions(self):
        captured = []
        messaging_notifier.aha_teams_webhook = lambda p: captured.append(p)
        _send_teams(summary=_summary_with_notifications())
        assert "action required" in captured[0]["text"].lower()

    def test_message_includes_health_console_link(self):
        captured = []
        messaging_notifier.aha_teams_webhook = lambda p: captured.append(p)
        _send_teams(summary=_summary_with_notifications())
        assert "health.aws.amazon.com" in captured[0]["text"]

    def test_message_includes_jira_link(self):
        captured = []
        messaging_notifier.aha_teams_webhook = lambda p: captured.append(p)
        _send_teams(summary=_summary_with_notifications())
        assert "jira.example.com/browse/OPS-1234" in captured[0]["text"]
