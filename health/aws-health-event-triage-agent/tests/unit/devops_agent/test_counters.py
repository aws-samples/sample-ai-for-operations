# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Unit tests for src.devops_agent.counters."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

from src.devops_agent.counters import (
    get_incident_counter,
    get_readiness_counter,
    increment_incident_counter,
)


class TestGetIncidentCounter:
    @patch("src.config.AGENT_SPACE_COUNTERS_TABLE_NAME", "")
    def test_no_table_configured_returns_zero_count(self):
        result = get_incident_counter("space-1", cap=10)
        assert result == {"incident_count_this_month": 0, "cap": 10}

    @patch("src.config.AGENT_SPACE_COUNTERS_TABLE_NAME", "counters")
    @patch("src.devops_agent.counters.boto3")
    def test_no_item_returns_zero_count(self, mock_boto3):
        mock_table = MagicMock()
        mock_table.get_item.return_value = {}
        mock_boto3.resource.return_value.Table.return_value = mock_table

        result = get_incident_counter("space-1", cap=10)
        assert result == {"incident_count_this_month": 0, "cap": 10}

    @patch("src.config.AGENT_SPACE_COUNTERS_TABLE_NAME", "counters")
    @patch("src.devops_agent.counters.boto3")
    def test_existing_item_returns_current_count(self, mock_boto3):
        mock_table = MagicMock()
        mock_table.get_item.return_value = {"Item": {"incidentCount": 7}}
        mock_boto3.resource.return_value.Table.return_value = mock_table

        result = get_incident_counter("space-1", cap=10)
        assert result == {"incident_count_this_month": 7, "cap": 10}

    @patch("src.config.AGENT_SPACE_COUNTERS_TABLE_NAME", "counters")
    @patch("src.devops_agent.counters.boto3")
    def test_read_error_fails_closed(self, mock_boto3):
        mock_boto3.resource.side_effect = Exception("throttled")
        result = get_incident_counter("space-1", cap=10)
        assert result == {"incident_count_this_month": 10, "cap": 10}


class TestIncrementIncidentCounter:
    @patch("src.config.AGENT_SPACE_COUNTERS_TABLE_NAME", "")
    def test_no_table_configured_not_incremented(self):
        result = increment_incident_counter("space-1", cap=10)
        assert result == {"incremented": False, "incident_count_this_month": 0}

    @patch("src.config.AGENT_SPACE_COUNTERS_TABLE_NAME", "counters")
    @patch("src.devops_agent.counters.boto3")
    def test_successful_increment(self, mock_boto3):
        mock_table = MagicMock()
        mock_table.update_item.return_value = {"Attributes": {"incidentCount": 1}}
        mock_boto3.resource.return_value.Table.return_value = mock_table

        result = increment_incident_counter("space-1", cap=10)
        assert result == {"incremented": True, "incident_count_this_month": 1}

        call_kwargs = mock_table.update_item.call_args.kwargs
        assert call_kwargs["ExpressionAttributeValues"][":cap"] == 10

    @patch("src.config.AGENT_SPACE_COUNTERS_TABLE_NAME", "counters")
    @patch("src.devops_agent.counters.boto3")
    def test_conditional_check_failure_not_incremented(self, mock_boto3):
        mock_table = MagicMock()
        mock_table.update_item.side_effect = ClientError(
            {"Error": {"Code": "ConditionalCheckFailedException", "Message": "cap reached"}},
            "UpdateItem",
        )
        mock_boto3.resource.return_value.Table.return_value = mock_table

        result = increment_incident_counter("space-1", cap=10)
        assert result == {"incremented": False, "incident_count_this_month": 10}

    @patch("src.config.AGENT_SPACE_COUNTERS_TABLE_NAME", "counters")
    @patch("src.devops_agent.counters.boto3")
    def test_other_client_error_does_not_raise(self, mock_boto3):
        mock_table = MagicMock()
        mock_table.update_item.side_effect = ClientError(
            {"Error": {"Code": "ProvisionedThroughputExceededException", "Message": "throttled"}},
            "UpdateItem",
        )
        mock_boto3.resource.return_value.Table.return_value = mock_table

        result = increment_incident_counter("space-1", cap=10)
        assert result == {"incremented": False, "incident_count_this_month": 0}

    @patch("src.config.AGENT_SPACE_COUNTERS_TABLE_NAME", "counters")
    @patch("src.devops_agent.counters.boto3")
    def test_unexpected_error_does_not_raise(self, mock_boto3):
        mock_boto3.resource.side_effect = Exception("network error")
        result = increment_incident_counter("space-1", cap=10)
        assert result == {"incremented": False, "incident_count_this_month": 0}


class TestGetReadinessCounter:
    @patch("src.config.AGENT_SPACE_COUNTERS_TABLE_NAME", "")
    def test_no_table_configured_returns_zero_count(self):
        result = get_readiness_counter("space-1", cap=5)
        assert result == {"readiness_count_this_month": 0, "cap": 5}

    @patch("src.config.AGENT_SPACE_COUNTERS_TABLE_NAME", "counters")
    @patch("src.devops_agent.counters.boto3")
    def test_no_item_returns_zero_count(self, mock_boto3):
        mock_table = MagicMock()
        mock_table.get_item.return_value = {}
        mock_boto3.resource.return_value.Table.return_value = mock_table

        result = get_readiness_counter("space-1", cap=5)
        assert result == {"readiness_count_this_month": 0, "cap": 5}

    @patch("src.config.AGENT_SPACE_COUNTERS_TABLE_NAME", "counters")
    @patch("src.devops_agent.counters.boto3")
    def test_existing_item_returns_current_count(self, mock_boto3):
        mock_table = MagicMock()
        mock_table.get_item.return_value = {"Item": {"readinessCount": 3}}
        mock_boto3.resource.return_value.Table.return_value = mock_table

        result = get_readiness_counter("space-1", cap=5)
        assert result == {"readiness_count_this_month": 3, "cap": 5}

    @patch("src.config.AGENT_SPACE_COUNTERS_TABLE_NAME", "counters")
    @patch("src.devops_agent.counters.boto3")
    def test_read_error_fails_closed(self, mock_boto3):
        mock_boto3.resource.side_effect = Exception("throttled")
        result = get_readiness_counter("space-1", cap=5)
        assert result == {"readiness_count_this_month": 5, "cap": 5}

    @patch("src.config.AGENT_SPACE_COUNTERS_TABLE_NAME", "counters")
    @patch("src.devops_agent.counters.boto3")
    def test_readiness_counter_key_independent_of_incident_counter(self, mock_boto3):
        # incidentCount present but readinessCount absent -> readiness reads as 0,
        # confirming the two budgets don't share the same attribute.
        mock_table = MagicMock()
        mock_table.get_item.return_value = {"Item": {"incidentCount": 9}}
        mock_boto3.resource.return_value.Table.return_value = mock_table

        result = get_readiness_counter("space-1", cap=5)
        assert result == {"readiness_count_this_month": 0, "cap": 5}
