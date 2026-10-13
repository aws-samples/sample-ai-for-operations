# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Unit tests for src.devops_agent.readiness_tracker."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from src.devops_agent.readiness_tracker import has_prior_assessment, record_assessment


class TestHasPriorAssessment:
    @patch("src.config.READINESS_ASSESSMENTS_TABLE_NAME", "")
    def test_no_table_configured_returns_empty_list(self):
        result = has_prior_assessment("arn:health:event/1")
        assert result == {"assessed_accounts": []}

    @patch("src.config.READINESS_ASSESSMENTS_TABLE_NAME", "readiness-assessments")
    @patch("src.devops_agent.readiness_tracker.boto3")
    def test_no_items_returns_empty_list(self, mock_boto3):
        mock_table = MagicMock()
        mock_table.query.return_value = {"Items": []}
        mock_boto3.resource.return_value.Table.return_value = mock_table

        result = has_prior_assessment("arn:health:event/1")
        assert result == {"assessed_accounts": []}

    @patch("src.config.READINESS_ASSESSMENTS_TABLE_NAME", "readiness-assessments")
    @patch("src.devops_agent.readiness_tracker.boto3")
    def test_existing_items_returns_assessed_accounts(self, mock_boto3):
        mock_table = MagicMock()
        mock_table.query.return_value = {
            "Items": [
                {"eventArn": "arn:health:event/1", "accountId": "111111111111"},
                {"eventArn": "arn:health:event/1", "accountId": "222222222222"},
            ]
        }
        mock_boto3.resource.return_value.Table.return_value = mock_table

        result = has_prior_assessment("arn:health:event/1")
        assert result == {"assessed_accounts": ["111111111111", "222222222222"]}

    @patch("src.config.READINESS_ASSESSMENTS_TABLE_NAME", "readiness-assessments")
    @patch("src.devops_agent.readiness_tracker.boto3")
    def test_items_missing_account_id_are_skipped(self, mock_boto3):
        mock_table = MagicMock()
        mock_table.query.return_value = {
            "Items": [
                {"eventArn": "arn:health:event/1", "accountId": "111111111111"},
                {"eventArn": "arn:health:event/1"},
            ]
        }
        mock_boto3.resource.return_value.Table.return_value = mock_table

        result = has_prior_assessment("arn:health:event/1")
        assert result == {"assessed_accounts": ["111111111111"]}

    @patch("src.config.READINESS_ASSESSMENTS_TABLE_NAME", "readiness-assessments")
    @patch("src.devops_agent.readiness_tracker.boto3")
    def test_read_error_fails_open(self, mock_boto3):
        mock_boto3.resource.side_effect = Exception("throttled")
        result = has_prior_assessment("arn:health:event/1")
        assert result == {"assessed_accounts": []}

    @patch("src.config.READINESS_ASSESSMENTS_TABLE_NAME", "readiness-assessments")
    @patch("src.devops_agent.readiness_tracker.boto3")
    def test_query_uses_event_arn_key_condition(self, mock_boto3):
        mock_table = MagicMock()
        mock_table.query.return_value = {"Items": []}
        mock_boto3.resource.return_value.Table.return_value = mock_table

        has_prior_assessment("arn:health:event/1")

        mock_table.query.assert_called_once()


class TestRecordAssessment:
    @patch("src.config.READINESS_ASSESSMENTS_TABLE_NAME", "")
    def test_no_table_configured_is_noop(self):
        # Should not raise even with no client mocked.
        record_assessment("arn:health:event/1", "111111111111", "space-1", "health-ec2-1-abcd")

    @patch("src.config.READINESS_ASSESSMENTS_TABLE_NAME", "readiness-assessments")
    @patch("src.devops_agent.readiness_tracker.boto3")
    def test_put_item_called_with_expected_shape(self, mock_boto3):
        mock_table = MagicMock()
        mock_boto3.resource.return_value.Table.return_value = mock_table

        record_assessment("arn:health:event/1", "111111111111", "space-1", "health-ec2-1-abcd")

        mock_table.put_item.assert_called_once()
        item = mock_table.put_item.call_args.kwargs["Item"]
        assert item["eventArn"] == "arn:health:event/1"
        assert item["accountId"] == "111111111111"
        assert item["agentSpaceId"] == "space-1"
        assert item["incidentId"] == "health-ec2-1-abcd"
        assert item["status"] == "triggered"
        assert "assessedAt" in item
        assert "ttl" not in item

    @patch("src.config.READINESS_ASSESSMENTS_TABLE_NAME", "readiness-assessments")
    @patch("src.devops_agent.readiness_tracker.boto3")
    def test_write_error_does_not_raise(self, mock_boto3):
        mock_boto3.resource.side_effect = Exception("throttled")
        record_assessment("arn:health:event/1", "111111111111", "space-1", "health-ec2-1-abcd")
