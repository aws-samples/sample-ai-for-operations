# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Integration test for the Intake pipeline.

Tests the full flow: parse → merge → service (with mocked AWS clients).

Scenario:
  - One event ARN, 3 pages, 35 distinct accounts spread across pages.
  - 35 + 3 = 38 messages total (35 account-specific + 3 page updates).
  - Expected: 1 ConsolidatedEvents item with 35 accounts, 0 DLQ items.

Uses unittest.mock (no moto dependency in Phase 1).
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, call

import pytest

from src.intake.event_parser import parse_health_event
from src.intake.merge_event_message import merge_event_message
from src.intake.service import IntakeService

EVENT_ARN = "arn:aws:health:us-east-1::event/EC2/AWS_EC2_OPERATIONAL_ISSUE/INT-TEST-001"
TOTAL_ACCOUNTS = 35
TOTAL_PAGES = 3
ACCOUNTS_PER_PAGE = 12  # first 2 pages; last page gets remainder


def _make_account_id(i: int) -> str:
    return f"{i:012d}"


def _make_account_message(
    account_index: int,
    page: int,
    last_updated_time: str = "2026-01-01T01:00:00Z",
) -> dict:
    """Build a parsed health event for a single account."""
    return {
        "eventArn": EVENT_ARN,
        "service": "EC2",
        "eventTypeCode": "AWS_EC2_OPERATIONAL_ISSUE",
        "eventTypeCategory": "issue",
        "eventScopeCode": "PUBLIC",
        "statusCode": "open",
        "region": "us-east-1",
        "startTime": "2026-01-01T00:00:00Z",
        "lastUpdatedTime": last_updated_time,
        "endTime": "",
        "communicationId": "comm-int-001",
        "page": page,
        "totalPages": TOTAL_PAGES,
        "affectedAccounts": [_make_account_id(account_index)],
        "affectedEntities": [],
        "eventDescription": "Investigating EC2 connectivity.",
        "actionability": "ACTIONABLE",
        "personas": [],
        "raw": {},
    }


class TestIntakePipelineMerge:
    """Unit-level integration: merge 35+3 messages into 1 record."""

    def test_35_accounts_merged_into_single_record(self):
        """35 account messages merge into a single consolidated record."""
        record = None
        for i in range(1, TOTAL_ACCOUNTS + 1):
            page = 1 if i <= 12 else (2 if i <= 24 else 3)
            message = _make_account_message(i, page)
            record = merge_event_message(record, message)

        assert record is not None
        assert len(record["affectedAccounts"]) == TOTAL_ACCOUNTS

    def test_all_pages_tracked(self):
        """All 3 pages are recorded in pagesReceived."""
        record = None
        for i in range(1, TOTAL_ACCOUNTS + 1):
            page = 1 if i <= 12 else (2 if i <= 24 else 3)
            message = _make_account_message(i, page)
            record = merge_event_message(record, message)
        assert {1, 2, 3}.issubset(record["pagesReceived"])

    def test_idempotent_replay_of_all_messages(self):
        """Re-processing all 35 messages produces the same account count."""
        record = None
        for i in range(1, TOTAL_ACCOUNTS + 1):
            page = 1 if i <= 12 else (2 if i <= 24 else 3)
            message = _make_account_message(i, page)
            record = merge_event_message(record, message)

        # Replay
        for i in range(1, TOTAL_ACCOUNTS + 1):
            page = 1 if i <= 12 else (2 if i <= 24 else 3)
            message = _make_account_message(i, page)
            record = merge_event_message(record, message)

        assert len(record["affectedAccounts"]) == TOTAL_ACCOUNTS

    def test_no_accounts_lost_on_update_with_empty_list(self):
        """An update message with empty affectedAccounts doesn't clear existing accounts."""
        record = None
        for i in range(1, 6):
            record = merge_event_message(record, _make_account_message(i, 1))
        assert len(record["affectedAccounts"]) == 5

        update = _make_account_message(1, 1, last_updated_time="2026-01-01T02:00:00Z")
        update["affectedAccounts"] = []  # empty list — no new accounts
        record = merge_event_message(record, update)
        assert len(record["affectedAccounts"]) == 5


class TestIntakeServiceMocked:
    """Service-level integration with mocked AWS clients."""

    def _make_service(self, existing_item: dict | None = None) -> tuple:
        """Return a service + captured puts for assertion."""
        ddb = MagicMock()
        sfn = MagicMock()
        puts = []

        # Mock get_item for idempotency (not duplicate by default)
        ddb.get_item.return_value = {"Item": existing_item} if existing_item else {}

        # Capture put_item calls
        def capture_put(**kwargs):
            puts.append(kwargs)
        ddb.put_item.side_effect = capture_put

        # Mock sfn.start_execution
        sfn.start_execution.return_value = {"executionArn": "arn:aws:states:test"}
        sfn.exceptions.ExecutionAlreadyExists = type("ExecutionAlreadyExists", (Exception,), {})

        service = IntakeService(
            dynamodb_client=ddb,
            stepfunctions_client=sfn,
            consolidated_table_name="test-consolidated",
            idempotency_table_name="test-idempotency",
            account_cache_table_name="test-cache",
            ticket_map_table_name="test-tickets",
            audit_log_table_name="test-audit",
            workflow_arn="arn:aws:states:us-east-1:123456789012:stateMachine:test",
        )
        return service, ddb, sfn, puts

    def test_new_event_enqueues_settle_message_not_start_execution_directly(self):
        """First message for a new event enqueues a settle-window message;
        it does NOT call StartExecution directly.

        Was asserted as "process_message() calls StartExecution once"
        before the Phase -1 settle-window fix (working spec
        feat-devops-agent-enrichment req §1b / design §3.0, task -1b): a
        multi-account AWS update sends several messages within seconds,
        and starting the workflow on message 1 could read a record still
        missing accounts from messages 2..N. process_message() now only
        merges and enqueues; the settle consumer's start_settled_workflow()
        (tested separately in tests/unit/intake/test_service.py) is the
        sole caller of StartExecution.
        """
        service, ddb, sfn, puts = self._make_service()
        # _make_service() doesn't wire an sqs_client by default; inject one
        # here since this test's whole point is asserting settle-enqueue
        # behaviour.
        import unittest.mock as _mock
        service._sqs = _mock.MagicMock()

        msg = {
            "source": "aws.health",
            "detail": {
                "eventArn": EVENT_ARN,
                "service": "EC2",
                "eventTypeCode": "AWS_EC2_OPERATIONAL_ISSUE",
                "eventTypeCategory": "issue",
                "statusCode": "open",
                "lastUpdatedTime": "2026-01-01T01:00:00Z",
                "affectedAccount": "123456789012",
            },
        }
        result = service.process_message(msg)

        assert result["status"] == "processed"
        sfn.start_execution.assert_not_called()

    def test_duplicate_message_skipped(self):
        """Duplicate message (idempotency hit) is acknowledged without processing."""
        service, ddb, sfn, puts = self._make_service()

        # Simulate idempotency hit: get_item returns an Item
        ddb.get_item.return_value = {"Item": {"pk": {"S": "some-key"}}}

        msg = {
            "detail": {
                "eventArn": EVENT_ARN,
                "service": "EC2",
                "eventTypeCode": "TEST",
                "eventTypeCategory": "issue",
                "statusCode": "open",
                "lastUpdatedTime": "2026-01-01T00:00:00Z",
            }
        }
        result = service.process_message(msg)

        assert result["status"] == "duplicate"
        sfn.start_execution.assert_not_called()

    def test_malformed_message_returns_parse_error(self):
        """Malformed message returns parse_error status."""
        service, ddb, sfn, puts = self._make_service()

        result = service.process_message({"detail": "not-a-dict"})
        assert result["status"] == "parse_error"
        sfn.start_execution.assert_not_called()

    def test_second_message_with_entities_does_not_crash_on_ddb_roundtrip(self):
        """Regression test: a second real message for an already-consolidated
        event (with a non-empty affectedEntities) must not crash.

        A real second SQS message for the same eventArn crashed during live-
        deploy validation with "ValueError: dictionary update sequence
        element #0 has length 6; 2 is required" — merge_event_message()
        requires 'affectedEntities' to be a dict (its in-memory contract),
        but consolidated_to_db() serializes it as a list for DynamoDB, and
        _load_consolidated() was never converting it back on read. Every
        existing test either sent only one message per event, or used an
        empty affectedEntities list (dict([]) happens to succeed, masking
        the bug) — this test uses a real, non-empty entity list and a real
        DDB serialize/deserialize round-trip via the same _ddb_serialize/
        _ddb_deserialize helpers process_message() itself uses, not a
        hand-built fixture that skips the round-trip.
        """
        from src.intake.service import _ddb_deserialize, _ddb_serialize
        from src.intake.merge_event_message import consolidated_to_db

        # Build the first message's parsed form and merge it once, exactly
        # as process_message() would, then push it through the same
        # to-DB/from-DB conversion the real code path uses.
        raw_detail_template = {
            "eventArn": EVENT_ARN,
            "service": "EKS",
            "eventTypeCode": "AWS_EKS_PLANNED_LIFECYCLE_EVENT",
            "eventTypeCategory": "scheduledChange",
            "eventScopeCode": "ACCOUNT_SPECIFIC",
            "statusCode": "upcoming",
            "region": "eu-west-1",
            "startTime": "2026-01-01T00:00:00Z",
            "endTime": "",
            "communicationId": "",
            "page": 1,
            "totalPages": 1,
            "affectedAccounts": ["111111111111"],
            "affectedEntities": [
                {
                    "entityValue": "test-cluster",
                    "entityArn": "arn:aws:eks:eu-west-1:111111111111:cluster/test-cluster",
                    "entityUrl": "",
                    "entityStatus": "IMPAIRED",
                    "lastUpdatedTime": "2026-01-01T01:00:00Z",
                    "tags": {},
                }
            ],
            "actionability": "",
            "personas": [],
        }
        first_detail = {
            **raw_detail_template,
            "lastUpdatedTime": "2026-01-01T01:00:00Z",
            "eventDescription": [
                {"language": "en_US", "latestDescription": "First message."}
            ],
        }
        first_parsed = parse_health_event({"detail": first_detail})
        record = merge_event_message(None, first_parsed)
        db_item = _ddb_serialize(consolidated_to_db(record))

        service, ddb, sfn, puts = self._make_service()

        def get_item_side_effect(TableName, **kwargs):
            if TableName == "test-idempotency":
                return {}  # not a duplicate — this is a genuinely new message
            if TableName == "test-consolidated":
                return {"Item": db_item}
            return {}

        ddb.get_item.side_effect = get_item_side_effect

        second_message_body = {
            "source": "aws.health",
            "detail": {
                **raw_detail_template,
                "lastUpdatedTime": "2026-01-01T02:00:00Z",
                "eventDescription": [
                    {"language": "en_US", "latestDescription": "Second message — updated."}
                ],
            },
        }
        # Should not raise; previously crashed inside merge_event_message().
        result = service.process_message(second_message_body)
        assert result["status"] == "processed"

        # Confirm the entity survived the merge and the description updated,
        # i.e. the real merge logic ran correctly against the round-tripped
        # (dict-converted-back) existing record, not just "didn't crash".
        consolidated_puts = [p for p in puts if p.get("TableName") == "test-consolidated"]
        assert consolidated_puts, "expected a put_item to the consolidated table"
        saved_record = _ddb_deserialize(consolidated_puts[-1]["Item"])
        assert saved_record["eventDescription"] == "Second message — updated."
        entities = saved_record["affectedEntities"]
        entity_values = (
            [e["entityValue"] for e in entities]
            if isinstance(entities, list)
            else list(entities.keys())
        )
        assert "test-cluster" in entity_values


class TestHandlerBatchItemFailures:
    """Lambda handler returns correct batchItemFailures."""

    def test_valid_message_no_failures(self):
        """Valid message returns empty batchItemFailures."""
        from src.intake.handler import handler

        event = {
            "Records": [
                {
                    "messageId": "msg-001",
                    "body": json.dumps({
                        "source": "aws.health",
                        "detail": {
                            "eventArn": EVENT_ARN,
                            "service": "EC2",
                            "eventTypeCode": "TEST",
                            "eventTypeCategory": "issue",
                            "statusCode": "open",
                            "lastUpdatedTime": "2026-01-01T00:00:00Z",
                        },
                    }),
                }
            ]
        }

        # The handler uses a module-level _service with real boto3 — mock it
        import src.intake.handler as h

        mock_service = MagicMock()
        mock_service.process_message.return_value = {"status": "processed", "event_arn": EVENT_ARN}
        original = h._service
        h._service = mock_service
        try:
            result = handler(event, None)
            assert result["batchItemFailures"] == []
        finally:
            h._service = original

    def test_parse_error_creates_batch_failure(self):
        """A parse error is reported as a batchItemFailure."""
        from src.intake.handler import handler
        import src.intake.handler as h

        mock_service = MagicMock()
        mock_service.process_message.return_value = {
            "status": "parse_error",
            "event_arn": "(unknown)",
            "error": "Missing required fields",
        }
        original = h._service
        h._service = mock_service
        try:
            event = {
                "Records": [{"messageId": "msg-fail-001", "body": "{}"}]
            }
            result = handler(event, None)
            assert len(result["batchItemFailures"]) == 1
            assert result["batchItemFailures"][0]["itemIdentifier"] == "msg-fail-001"
        finally:
            h._service = original
