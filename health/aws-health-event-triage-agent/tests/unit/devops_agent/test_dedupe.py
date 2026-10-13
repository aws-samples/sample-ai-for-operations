# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Unit tests for src.devops_agent.dedupe."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from src.devops_agent.dedupe import dedupe_check, record_active_investigation


class TestDedupeCheck:
    @patch("src.config.ACTIVE_INVESTIGATIONS_TABLE_NAME", "")
    def test_no_table_configured_returns_no_duplicate(self):
        result = dedupe_check("space-1", "arn:health:event/1")
        assert result == {"duplicate": False, "existing_investigation_id": None}

    @patch("src.config.ACTIVE_INVESTIGATIONS_TABLE_NAME", "active-investigations")
    @patch("src.devops_agent.dedupe.boto3")
    def test_no_item_found_returns_no_duplicate(self, mock_boto3):
        mock_table = MagicMock()
        mock_table.get_item.return_value = {}
        mock_boto3.resource.return_value.Table.return_value = mock_table

        result = dedupe_check("space-1", "arn:health:event/1")
        assert result == {"duplicate": False, "existing_investigation_id": None}

    @patch("src.config.ACTIVE_INVESTIGATIONS_TABLE_NAME", "active-investigations")
    @patch("src.devops_agent.dedupe.boto3")
    def test_recent_item_is_duplicate(self, mock_boto3):
        now = datetime.now(timezone.utc)
        mock_table = MagicMock()
        mock_table.get_item.return_value = {
            "Item": {
                "investigationId": "health-ec2-123-abcd1234",
                "triggeredAt": now.isoformat(),
            }
        }
        mock_boto3.resource.return_value.Table.return_value = mock_table

        result = dedupe_check("space-1", "arn:health:event/1", window_minutes=60)
        assert result == {"duplicate": True, "existing_investigation_id": "health-ec2-123-abcd1234"}

    @patch("src.config.ACTIVE_INVESTIGATIONS_TABLE_NAME", "active-investigations")
    @patch("src.devops_agent.dedupe.boto3")
    def test_stale_item_outside_window_is_not_duplicate(self, mock_boto3):
        old = datetime.now(timezone.utc) - timedelta(hours=2)
        mock_table = MagicMock()
        mock_table.get_item.return_value = {
            "Item": {"investigationId": "health-ec2-123-abcd1234", "triggeredAt": old.isoformat()}
        }
        mock_boto3.resource.return_value.Table.return_value = mock_table

        result = dedupe_check("space-1", "arn:health:event/1", window_minutes=60)
        assert result == {"duplicate": False, "existing_investigation_id": None}

    @patch("src.config.ACTIVE_INVESTIGATIONS_TABLE_NAME", "active-investigations")
    @patch("src.devops_agent.dedupe.boto3")
    def test_missing_triggered_at_treated_as_duplicate(self, mock_boto3):
        # No timestamp to age-check against -> conservatively treat as duplicate
        # rather than silently ignore a real record.
        mock_table = MagicMock()
        mock_table.get_item.return_value = {"Item": {"investigationId": "health-ec2-123-abcd1234"}}
        mock_boto3.resource.return_value.Table.return_value = mock_table

        result = dedupe_check("space-1", "arn:health:event/1")
        assert result["duplicate"] is True

    @patch("src.config.ACTIVE_INVESTIGATIONS_TABLE_NAME", "active-investigations")
    @patch("src.devops_agent.dedupe.boto3")
    def test_read_error_fails_open(self, mock_boto3):
        mock_boto3.resource.side_effect = Exception("throttled")
        result = dedupe_check("space-1", "arn:health:event/1")
        assert result == {"duplicate": False, "existing_investigation_id": None}


class TestRecordActiveInvestigation:
    @patch("src.config.ACTIVE_INVESTIGATIONS_TABLE_NAME", "")
    def test_no_table_configured_is_noop(self):
        # Should not raise even with no client mocked.
        record_active_investigation("space-1", "arn:health:event/1", "health-ec2-1-abcd")

    @patch("src.config.ACTIVE_INVESTIGATIONS_TABLE_NAME", "active-investigations")
    @patch("src.devops_agent.dedupe.boto3")
    def test_put_item_called_with_expected_shape(self, mock_boto3):
        mock_table = MagicMock()
        mock_boto3.resource.return_value.Table.return_value = mock_table

        record_active_investigation("space-1", "arn:health:event/1", "health-ec2-1-abcd")

        mock_table.put_item.assert_called_once()
        item = mock_table.put_item.call_args.kwargs["Item"]
        assert item["agentSpaceId"] == "space-1"
        assert item["eventArn"] == "arn:health:event/1"
        assert item["investigationId"] == "health-ec2-1-abcd"
        assert "triggeredAt" in item
        assert "ttl" in item

    @patch("src.config.ACTIVE_INVESTIGATIONS_TABLE_NAME", "active-investigations")
    @patch("src.devops_agent.dedupe.boto3")
    def test_write_error_does_not_raise(self, mock_boto3):
        mock_boto3.resource.side_effect = Exception("throttled")
        record_active_investigation("space-1", "arn:health:event/1", "health-ec2-1-abcd")
