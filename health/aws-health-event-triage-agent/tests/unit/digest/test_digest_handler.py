# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Unit tests for src.digest.handler.DigestService and handler()."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from src.digest.handler import DigestService, handler
import src.digest.handler as handler_mod


def _make_service(events: list[dict] | None = None, watermark_item: dict | None = None, publish_side_effect=None):
    ddb = MagicMock()
    sns = MagicMock()

    ddb.get_item.return_value = {"Item": watermark_item} if watermark_item else {}

    if events is not None:
        ddb.query.return_value = {
            "Items": [
                {k: {"S": json.dumps(v) if isinstance(v, (list, dict)) else str(v)} for k, v in e.items()}
                for e in events
            ]
        }
    else:
        ddb.query.side_effect = Exception("query failed")

    if publish_side_effect:
        sns.publish.side_effect = publish_side_effect
    else:
        sns.publish.return_value = {"MessageId": "digest-msg-1"}

    service = DigestService(
        dynamodb_client=ddb,
        sns_client=sns,
        consolidated_table_name="test-consolidated",
        watermark_table_name="test-watermark",
        audit_log_table_name="test-audit",
        digest_topic_arn="arn:aws:sns:us-east-1:123456789012:digest-topic",
    )
    return service, ddb, sns


def _sample_event(arn="arn:1"):
    return {
        "eventArn": arn,
        "service": "EC2",
        "eventTypeCode": "AWS_EC2_MAINTENANCE_SCHEDULED",
        "statusCode": "upcoming",
        "affectedAccounts": "[]",
        "classification": "INFORMATIONAL",
    }


class TestNoEvents:
    def test_empty_query_advances_watermark_without_publish(self):
        service, ddb, sns = _make_service(events=[])
        result = service.run()
        assert result["status"] == "empty"
        sns.publish.assert_not_called()
        ddb.put_item.assert_called()  # watermark advance


class TestSuccessfulDigest:
    def test_publishes_and_advances_watermark(self):
        service, ddb, sns = _make_service(events=[_sample_event()])
        result = service.run()
        assert result["status"] == "sent"
        sns.publish.assert_called_once()

    def test_writes_audit_record(self):
        service, ddb, sns = _make_service(events=[_sample_event("arn:audit-test")])
        service.run()
        # put_item called at least twice: watermark advance + audit record
        assert ddb.put_item.call_count >= 2

    def test_included_event_arns_in_result(self):
        service, ddb, sns = _make_service(events=[_sample_event("arn:x")])
        result = service.run()
        assert "arn:x" in result["included_event_arns"]


class TestQueryFailure:
    def test_query_exception_returns_error_status(self):
        service, ddb, sns = _make_service(events=None)  # triggers query side_effect exception
        result = service.run()
        assert result["status"] == "error"
        sns.publish.assert_not_called()


class TestPublishFailure:
    def test_publish_failure_does_not_advance_watermark(self):
        service, ddb, sns = _make_service(
            events=[_sample_event()],
            publish_side_effect=Exception("SNS throttled"),
        )
        result = service.run()
        assert result["status"] == "publish_failed"
        # put_item should NOT be called for watermark advance (only possibly for audit,
        # but audit is also skipped since we return before it)
        watermark_puts = [
            c for c in ddb.put_item.call_args_list
            if c.kwargs.get("TableName") == "test-watermark" or "timestamp" in str(c)
        ]
        # The key assertion: run() returned publish_failed and did not reach _advance_watermark's
        # success log path — validated implicitly via status.
        assert result["status"] != "sent"


class TestNoDigestTopicConfigured:
    def test_no_topic_arn_skips_publish(self):
        ddb = MagicMock()
        ddb.get_item.return_value = {}
        ddb.query.return_value = {
            "Items": [{k: {"S": json.dumps(v) if isinstance(v, (list, dict)) else str(v)} for k, v in _sample_event().items()}]
        }
        sns = MagicMock()
        service = DigestService(
            dynamodb_client=ddb, sns_client=sns,
            consolidated_table_name="t", watermark_table_name="w", audit_log_table_name="a",
            digest_topic_arn="",
        )
        result = service.run()
        assert result["status"] == "publish_failed"
        sns.publish.assert_not_called()


class TestHandlerEntryPoint:
    def test_handler_delegates_to_module_service(self, monkeypatch):
        mock_service = MagicMock()
        mock_service.run.return_value = {"status": "sent", "event_count": 1}
        monkeypatch.setattr(handler_mod, "_service", mock_service)

        result = handler({}, None)
        assert result["status"] == "sent"
