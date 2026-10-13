# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Unit tests for src.intake.settle_handler.

Requirements covered: req §1b of working spec feat-devops-agent-enrichment
(task -1b) — the settle consumer Lambda.
"""

from __future__ import annotations

import json
from unittest.mock import patch

from src.intake import settle_handler


def _sqs_record(body: dict | str, message_id: str = "msg-1") -> dict:
    return {
        "messageId": message_id,
        "body": body if isinstance(body, str) else json.dumps(body),
    }


class TestSettleHandlerHappyPath:
    def test_calls_start_settled_workflow_with_parsed_fields(self):
        with patch.object(settle_handler._service, "start_settled_workflow") as mock_start:
            mock_start.return_value = {"event_arn": "arn:test", "execution_name": "abc123"}
            event = {
                "Records": [
                    _sqs_record({"eventArn": "arn:test", "lastUpdatedTime": "2026-01-01T00:00:00Z"})
                ]
            }

            result = settle_handler.handler(event, None)

            mock_start.assert_called_once_with("arn:test", "2026-01-01T00:00:00Z")
            assert result["batchItemFailures"] == []

    def test_multiple_records_processed_independently(self):
        with patch.object(settle_handler._service, "start_settled_workflow") as mock_start:
            mock_start.return_value = {"event_arn": "arn:x", "execution_name": "n"}
            event = {
                "Records": [
                    _sqs_record({"eventArn": "arn:1", "lastUpdatedTime": "t1"}, "m1"),
                    _sqs_record({"eventArn": "arn:2", "lastUpdatedTime": "t2"}, "m2"),
                ]
            }

            result = settle_handler.handler(event, None)

            assert mock_start.call_count == 2
            assert result["batchItemFailures"] == []


class TestSettleHandlerFailureModes:
    def test_missing_event_arn_reported_as_batch_item_failure(self):
        with patch.object(settle_handler._service, "start_settled_workflow") as mock_start:
            event = {"Records": [_sqs_record({"lastUpdatedTime": "t1"}, "bad-msg")]}

            result = settle_handler.handler(event, None)

            mock_start.assert_not_called()
            assert result["batchItemFailures"] == [{"itemIdentifier": "bad-msg"}]

    def test_start_settled_workflow_exception_reported_as_batch_item_failure(self):
        with patch.object(settle_handler._service, "start_settled_workflow") as mock_start:
            mock_start.side_effect = RuntimeError("boom")
            event = {
                "Records": [_sqs_record({"eventArn": "arn:test", "lastUpdatedTime": "t1"}, "err-msg")]
            }

            result = settle_handler.handler(event, None)

            assert result["batchItemFailures"] == [{"itemIdentifier": "err-msg"}]

    def test_one_bad_record_does_not_block_a_good_one(self):
        with patch.object(settle_handler._service, "start_settled_workflow") as mock_start:
            mock_start.return_value = {"event_arn": "arn:good", "execution_name": "n"}
            event = {
                "Records": [
                    _sqs_record({"lastUpdatedTime": "t1"}, "bad-msg"),
                    _sqs_record({"eventArn": "arn:good", "lastUpdatedTime": "t2"}, "good-msg"),
                ]
            }

            result = settle_handler.handler(event, None)

            assert result["batchItemFailures"] == [{"itemIdentifier": "bad-msg"}]
            mock_start.assert_called_once_with("arn:good", "t2")
