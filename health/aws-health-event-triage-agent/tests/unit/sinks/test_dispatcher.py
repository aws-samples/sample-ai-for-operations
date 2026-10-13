# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Unit tests for src.sinks.dispatcher.dispatch."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from src.sinks.dispatcher import dispatch

_TABLE = [
    {"ruleType": "SERVICE", "key": "EKS", "team": "Platform-Kubernetes",
     "jiraProject": "PLATK8S", "chatChannel": "#k8s-alerts"},
    {"ruleType": "DEFAULT", "key": "*", "team": "Platform-Operations"},
]


def _record(**overrides) -> dict:
    base = {
        "eventArn": "arn:test",
        "service": "EKS",
        "statusCode": "open",
        "affectedEntities": {},
        "accountContexts": [],
    }
    base.update(overrides)
    return base


def _payload() -> dict:
    return {"eventArn": "arn:test", "classification": "BREAKING_CHANGE"}


class TestSnsAlwaysDispatched:
    def test_sns_always_called(self):
        sns = MagicMock()
        sns.upsert.return_value = {"status": "sent", "message_id": "m1"}
        result = dispatch(_record(), _payload(), {}, sns_sink=sns, routing_table=_TABLE)
        assert "sns" in result["results"]
        sns.upsert.assert_called_once()

    def test_no_optional_sinks_called_when_channels_absent(self):
        sns = MagicMock()
        sns.upsert.return_value = {"status": "sent"}
        jira = MagicMock()
        result = dispatch(
            _record(service="UNKNOWN"), _payload(), {},
            sns_sink=sns, jira_sink=jira, routing_table=_TABLE,
        )
        # UNKNOWN service falls to DEFAULT rule which has no jiraProject
        assert "jira" not in result["results"]
        jira.upsert.assert_not_called()


class TestConditionalSinkDispatch:
    def test_jira_dispatched_when_jira_project_configured(self):
        sns = MagicMock()
        sns.upsert.return_value = {"status": "sent"}
        jira = MagicMock()
        jira.upsert.return_value = {"status": "created", "ticket_id": "PLATK8S-1"}
        result = dispatch(_record(), _payload(), {}, sns_sink=sns, jira_sink=jira, routing_table=_TABLE)
        assert result["results"]["jira"]["ticket_id"] == "PLATK8S-1"

    def test_slack_dispatched_when_chat_channel_configured(self):
        sns = MagicMock()
        sns.upsert.return_value = {"status": "sent"}
        slack = MagicMock()
        slack.upsert.return_value = {"status": "sent"}
        result = dispatch(_record(), _payload(), {}, sns_sink=sns, slack_sink=slack, routing_table=_TABLE)
        assert result["results"]["slack"]["status"] == "sent"


class TestCloseSemantics:
    def test_closed_status_calls_close_on_sinks_with_prior_ref(self):
        sns = MagicMock()
        sns.close.return_value = {"status": "skipped"}
        jira = MagicMock()
        jira.close.return_value = {"status": "closed"}
        record = _record(statusCode="closed")
        result = dispatch(
            record, _payload(), {"jira": {"ticket_id": "PLATK8S-1"}},
            sns_sink=sns, jira_sink=jira, routing_table=_TABLE,
        )
        assert result["closed"] is True
        jira.close.assert_called_once()
        jira.upsert.assert_not_called()

    def test_closed_status_no_prior_ref_calls_upsert_instead(self):
        """If closing but there's no prior ticket, nothing to close — upsert instead."""
        sns = MagicMock()
        sns.upsert.return_value = {"status": "sent"}
        record = _record(statusCode="closed")
        result = dispatch(record, _payload(), {}, sns_sink=sns, routing_table=_TABLE)
        sns.upsert.assert_called_once()
        sns.close.assert_not_called()

    def test_open_status_calls_upsert(self):
        sns = MagicMock()
        sns.upsert.return_value = {"status": "sent"}
        result = dispatch(_record(statusCode="open"), _payload(), {}, sns_sink=sns, routing_table=_TABLE)
        assert result["closed"] is False
        sns.upsert.assert_called_once()


class TestFailureIsolation:
    def test_one_sink_failure_does_not_block_others(self):
        sns = MagicMock()
        sns.upsert.side_effect = Exception("SNS throttled")
        jira = MagicMock()
        jira.upsert.return_value = {"status": "created", "ticket_id": "X-1"}
        result = dispatch(_record(), _payload(), {}, sns_sink=sns, jira_sink=jira, routing_table=_TABLE)
        assert result["results"]["sns"]["status"] == "failed"
        assert result["results"]["jira"]["status"] == "created"


class TestTeamResolutionIncluded:
    def test_team_dict_in_result(self):
        sns = MagicMock()
        sns.upsert.return_value = {"status": "sent"}
        result = dispatch(_record(), _payload(), {}, sns_sink=sns, routing_table=_TABLE)
        assert result["team"]["team"] == "Platform-Kubernetes"

    def test_assigned_team_added_to_payload_sent_to_sns(self):
        sns = MagicMock()
        sns.upsert.return_value = {"status": "sent"}
        dispatch(_record(), _payload(), {}, sns_sink=sns, routing_table=_TABLE)
        call_args = sns.upsert.call_args[0]
        assert call_args[0]["assignedTeam"] == "Platform-Kubernetes"
