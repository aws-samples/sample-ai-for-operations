# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Unit tests for src.sinks.sns_sink.SnsSink and _build_payload."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from src.sinks.sns_sink import SnsSink, _build_payload, _message_attributes

TOPIC_ARN = "arn:aws:sns:us-east-1:123456789012:health-triage-classification-results"


def _sample_record(**overrides) -> dict:
    base = {
        "eventArn": "arn:aws:health:us-east-1::event/EKS/TEST/001",
        "service": "EKS",
        "eventTypeCode": "AWS_EKS_PLANNED_LIFECYCLE_EVENT",
        "eventTypeCategory": "scheduledChange",
        "statusCode": "upcoming",
        "lastUpdatedTime": "2026-01-01T00:00:00Z",
        "region": "us-east-1",
        "affectedAccounts": ["123456789012"],
        "classification": "BREAKING_CHANGE",
        "urgency": "high",
        "deadline": "2026-09-01",
        "disposition": "TICKET",
        "impactSummary": {"impact_status": "confirmed", "resources": []},
        "costProjection": {"unknown": False, "monthly_increment": 365.0},
    }
    base.update(overrides)
    return base


class TestBuildPayload:
    def test_impact_summary_included(self):
        payload = _build_payload(_sample_record(), update_of=None)
        assert payload["impactSummary"]["impact_status"] == "confirmed"

    def test_cost_projection_included(self):
        payload = _build_payload(_sample_record(), update_of=None)
        assert payload["costProjection"]["monthly_increment"] == 365.0

    def test_null_for_skipped_classes(self):
        record = _sample_record(classification="INFORMATIONAL", impactSummary=None, costProjection=None)
        payload = _build_payload(record, update_of=None)
        assert payload["impactSummary"] is None
        assert payload["costProjection"] is None

    def test_update_of_set_when_provided(self):
        payload = _build_payload(_sample_record(), update_of="msg-123")
        assert payload["updateOf"] == "msg-123"

    def test_version_is_1(self):
        payload = _build_payload(_sample_record(), update_of=None)
        assert payload["version"] == "1"


class TestMessageAttributes:
    def test_classification_attribute_present(self):
        attrs = _message_attributes(_sample_record(), is_update=False)
        assert attrs["classification"]["StringValue"] == "BREAKING_CHANGE"

    def test_urgency_attribute_present(self):
        attrs = _message_attributes(_sample_record(), is_update=False)
        assert attrs["urgency"]["StringValue"] == "high"

    def test_update_type_create_vs_update(self):
        attrs_create = _message_attributes(_sample_record(), is_update=False)
        attrs_update = _message_attributes(_sample_record(), is_update=True)
        assert attrs_create["updateType"]["StringValue"] == "create"
        assert attrs_update["updateType"]["StringValue"] == "update"

    def test_missing_optional_fields_never_produce_empty_string_attributes(self):
        """Regression test: a real Publish call during live-deploy validation
        failed with ParameterValueInvalid because eventTypeCategory was sent
        as a String-type attribute with an empty StringValue — SNS rejects
        empty strings for String attributes. worker_handler.py's
        notification_payload doesn't always populate every field
        _sample_record() carries, so this must be exercised with a minimal
        record, not just the full fixture."""
        minimal_record = {"eventArn": "arn:aws:health:us-east-1::event/EC2/TEST/001"}
        attrs = _message_attributes(minimal_record, is_update=False)
        for attr in attrs.values():
            if attr.get("DataType") == "String":
                assert attr["StringValue"] != "", (
                    f"Empty-string String attribute would be rejected by SNS: {attr}"
                )
        assert "eventTypeCategory" not in attrs
        assert "statusCode" not in attrs
        assert "classification" not in attrs


class TestSnsSinkPublish:
    def test_skipped_when_topic_arn_not_configured(self):
        ddb = MagicMock()
        sns = MagicMock()
        sink = SnsSink(sns_client=sns, dynamodb_client=ddb, topic_arn="", ticket_map_table_name="test-tickets")
        result = sink.publish(_sample_record())
        assert result["status"] == "skipped"

    def test_publish_success_returns_message_id(self, monkeypatch):
        ddb = MagicMock()
        ddb.get_item.return_value = {}
        mock_sns_client = MagicMock()
        mock_sns_client.publish.return_value = {"MessageId": "msg-abc"}

        import src.sinks.sns_sink as sns_sink_mod
        monkeypatch.setattr(sns_sink_mod.boto3, "client", lambda *a, **k: mock_sns_client)

        sink = SnsSink(dynamodb_client=ddb, topic_arn=TOPIC_ARN, ticket_map_table_name="test-tickets")
        result = sink.publish(_sample_record())

        assert result["status"] == "sent"
        assert result["message_id"] == "msg-abc"

    def test_publish_includes_impact_and_cost_in_message(self, monkeypatch):
        ddb = MagicMock()
        ddb.get_item.return_value = {}
        mock_sns_client = MagicMock()
        mock_sns_client.publish.return_value = {"MessageId": "msg-1"}

        import src.sinks.sns_sink as sns_sink_mod
        monkeypatch.setattr(sns_sink_mod.boto3, "client", lambda *a, **k: mock_sns_client)

        sink = SnsSink(dynamodb_client=ddb, topic_arn=TOPIC_ARN, ticket_map_table_name="test-tickets")
        sink.publish(_sample_record())

        call_kwargs = mock_sns_client.publish.call_args[1]
        message = json.loads(call_kwargs["Message"])
        assert message["impactSummary"]["impact_status"] == "confirmed"
        assert message["costProjection"]["monthly_increment"] == 365.0

    def test_update_of_set_from_ticket_map(self, monkeypatch):
        ddb = MagicMock()
        ddb.get_item.return_value = {"Item": {"snsMessageId": {"S": "prior-msg-id"}}}
        mock_sns_client = MagicMock()
        mock_sns_client.publish.return_value = {"MessageId": "msg-new"}

        import src.sinks.sns_sink as sns_sink_mod
        monkeypatch.setattr(sns_sink_mod.boto3, "client", lambda *a, **k: mock_sns_client)

        sink = SnsSink(dynamodb_client=ddb, topic_arn=TOPIC_ARN, ticket_map_table_name="test-tickets")
        result = sink.publish(_sample_record())

        assert result["update_of"] == "prior-msg-id"

    def test_publish_failure_returns_failed_status(self, monkeypatch):
        ddb = MagicMock()
        ddb.get_item.return_value = {}
        mock_sns_client = MagicMock()
        mock_sns_client.publish.side_effect = Exception("Throttled")

        import src.sinks.sns_sink as sns_sink_mod
        monkeypatch.setattr(sns_sink_mod.boto3, "client", lambda *a, **k: mock_sns_client)

        sink = SnsSink(dynamodb_client=ddb, topic_arn=TOPIC_ARN, ticket_map_table_name="test-tickets")
        result = sink.publish(_sample_record())

        assert result["status"] == "failed"
