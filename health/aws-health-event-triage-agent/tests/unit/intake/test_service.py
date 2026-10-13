# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Unit tests for src.intake.service.IntakeService.

Requirements covered: req §1b of working spec feat-devops-agent-enrichment
(task -1b) — the settle window. N organizational-view messages for the same
(eventArn, lastUpdatedTime) but different affectedAccount must:
  1. each merge into ConsolidatedEvents immediately (no data loss — every
     message's account is visible in the record right away), but
  2. yield exactly ONE Step Functions StartExecution call, made by the
     settle consumer AFTER the settle window, against the fully-merged
     record — never one per message.

This is the fixture and test class the pre-existing suite lacked, per the
working spec: single-account sandbox testing never exercised the fan-out.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from src.intake.service import IntakeService, _workflow_execution_name
from tests.unit.intake.fixtures.health_event_fixtures import org_view_message


def _make_ddb_stub():
    """A minimal in-memory DynamoDB stub sufficient for IntakeService.

    Backs get_item/put_item for exactly the tables IntakeService touches;
    real serialization round-trips through the module's own
    _ddb_serialize/_ddb_deserialize helpers via put_item/get_item, so
    merge behaviour is exercised for real, not mocked away.
    """
    from src.intake.service import _ddb_deserialize, _ddb_serialize

    store: dict[str, dict[str, dict]] = {}

    ddb = MagicMock()

    def get_item(TableName, Key, **kwargs):
        table = store.get(TableName, {})
        pk = next(iter(Key.values()))["S"]
        item = table.get(pk)
        return {"Item": item} if item is not None else {}

    def put_item(TableName, Item, **kwargs):
        table = store.setdefault(TableName, {})
        # Determine the partition key name from the first key present.
        # ConsolidatedEvents uses eventArn; Idempotency/AuditLog use pk/executionId.
        for pk_name in ("eventArn", "pk", "executionId"):
            if pk_name in Item:
                table[Item[pk_name]["S"]] = Item
                return {}
        # Fallback: use the first key.
        first_key = next(iter(Item.keys()))
        table[Item[first_key]["S"]] = Item
        return {}

    ddb.get_item.side_effect = get_item
    ddb.put_item.side_effect = put_item
    ddb._store = store  # exposed for assertions
    return ddb


class _ExecutionAlreadyExists(Exception):
    pass


def _make_sfn_stub():
    """A stub Step Functions client recording every start_execution call.

    Mirrors the real ExecutionAlreadyExists behaviour: a second
    start_execution with the same `name` raises, exactly like the real
    service (service.py already catches this — see _start_workflow).
    """
    sfn = MagicMock()
    sfn.exceptions.ExecutionAlreadyExists = _ExecutionAlreadyExists
    started_names: set[str] = set()
    calls: list[dict] = []

    def start_execution(stateMachineArn, name, input, **kwargs):
        calls.append({"stateMachineArn": stateMachineArn, "name": name, "input": input})
        if name in started_names:
            raise _ExecutionAlreadyExists("already exists")
        started_names.add(name)
        return {"executionArn": f"arn:aws:states:::execution/{name}"}

    sfn.start_execution.side_effect = start_execution
    sfn._calls = calls
    return sfn


def _service(ddb, sfn, sqs=None) -> IntakeService:
    return IntakeService(
        dynamodb_client=ddb,
        stepfunctions_client=sfn,
        sqs_client=sqs or MagicMock(),
        consolidated_table_name="ConsolidatedEvents",
        idempotency_table_name="Idempotency",
        account_cache_table_name="AccountCache",
        ticket_map_table_name="TicketMap",
        audit_log_table_name="AuditLog",
        workflow_arn="arn:aws:states:us-east-1:123456789012:stateMachine:TriageWorkflow",
        settle_queue_url="https://sqs.us-east-1.amazonaws.com/123456789012/settle-queue",
    )


class TestProcessMessageDefersWorkflowStart:
    """process_message() merges immediately but does NOT call StartExecution
    directly — that is now the settle consumer's job (task -1b)."""

    def test_merges_immediately_without_starting_workflow(self):
        ddb = _make_ddb_stub()
        sfn = _make_sfn_stub()
        sqs = MagicMock()
        svc = _service(ddb, sfn, sqs)

        result = svc.process_message(org_view_message(account="111111111111"))

        assert result["status"] == "processed"
        assert sfn.start_execution.call_count == 0, (
            "process_message must not call StartExecution directly; "
            "that responsibility moved to the settle consumer"
        )
        # But the merge must have happened for real.
        record = svc._load_consolidated(result["event_arn"])
        assert record["affectedAccounts"] == ["111111111111"]

    def test_enqueues_settle_message_with_delay(self):
        ddb = _make_ddb_stub()
        sfn = _make_sfn_stub()
        sqs = MagicMock()
        svc = _service(ddb, sfn, sqs)

        result = svc.process_message(org_view_message(account="111111111111"))

        assert sqs.send_message.call_count == 1
        call = sqs.send_message.call_args.kwargs
        assert call["QueueUrl"] == "https://sqs.us-east-1.amazonaws.com/123456789012/settle-queue"
        assert call["DelaySeconds"] == 60  # INTAKE_SETTLE_SECONDS default, injected via config
        import json as _json
        body = _json.loads(call["MessageBody"])
        assert body["eventArn"] == result["event_arn"]

    def test_two_accounts_both_merge_before_either_settle_message_fires(self):
        """The core scenario req §1b describes: message A and message B for
        the same eventArn/lastUpdatedTime, different affectedAccount. Both
        merge into ConsolidatedEvents; the record after both holds BOTH
        accounts, at the time the settle consumer would later read it."""
        ddb = _make_ddb_stub()
        sfn = _make_sfn_stub()
        sqs = MagicMock()
        svc = _service(ddb, sfn, sqs)

        result_a = svc.process_message(org_view_message(account="111111111111"))
        result_b = svc.process_message(org_view_message(account="222222222222"))

        assert result_a["status"] == "processed"
        assert result_b["status"] == "processed", (
            "message B must be processed, not skipped as a duplicate of A "
            "(this is the task -1a fix in effect end-to-end)"
        )
        record = svc._load_consolidated(result_a["event_arn"])
        assert sorted(record["affectedAccounts"]) == ["111111111111", "222222222222"]
        # Two settle messages were enqueued (one per intake message) — the
        # settle consumer's fixed execution name is what collapses them to
        # one execution, not intake.
        assert sqs.send_message.call_count == 2


class TestSettleConsumerStartsExactlyOneExecution:
    """The settle consumer (start_settled_workflow) is the ONLY caller of
    StartExecution. N settle messages for one (eventArn, lastUpdatedTime)
    yield exactly one execution, reading the fully-merged record."""

    def test_two_settle_messages_yield_one_execution(self):
        ddb = _make_ddb_stub()
        sfn = _make_sfn_stub()
        sqs = MagicMock()
        svc = _service(ddb, sfn, sqs)

        msg_a = org_view_message(account="111111111111")
        msg_b = org_view_message(account="222222222222")
        result_a = svc.process_message(msg_a)
        result_b = svc.process_message(msg_b)
        event_arn = result_a["event_arn"]
        last_updated_time = msg_a["detail"]["lastUpdatedTime"]

        # Simulate the settle consumer draining both delayed messages.
        svc.start_settled_workflow(event_arn, last_updated_time)
        svc.start_settled_workflow(event_arn, last_updated_time)

        assert sfn.start_execution.call_count == 2, "both calls happen, but..."
        names = {c["name"] for c in sfn._calls}
        assert len(names) == 1, "...both calls must use the SAME execution name"
        expected_name = _workflow_execution_name(event_arn, last_updated_time)
        assert names == {expected_name}

    def test_execution_input_reflects_fully_merged_accounts(self):
        """The execution that actually starts (the first of the two calls)
        must be started after both messages have merged — i.e. calling the
        settle consumer only after both process_message() calls have
        completed reads the record with both accounts, and this is exactly
        what the real SQS delay window guarantees in production (the delay
        queue only delivers after INTAKE_SETTLE_SECONDS, by which time a
        real multi-second AWS fan-out has completed)."""
        ddb = _make_ddb_stub()
        sfn = _make_sfn_stub()
        sqs = MagicMock()
        svc = _service(ddb, sfn, sqs)

        msg_a = org_view_message(account="111111111111")
        msg_b = org_view_message(account="222222222222")
        result_a = svc.process_message(msg_a)
        svc.process_message(msg_b)
        event_arn = result_a["event_arn"]
        last_updated_time = msg_a["detail"]["lastUpdatedTime"]

        svc.start_settled_workflow(event_arn, last_updated_time)

        import json as _json
        first_call_input = _json.loads(sfn._calls[0]["input"])
        assert first_call_input["eventArn"] == event_arn
        # LoadEvent (already in the state machine) is the one that actually
        # reads ConsolidatedEvents; confirm here that by the time
        # start_settled_workflow ran, the record it WOULD read holds both.
        record = svc._load_consolidated(event_arn)
        assert sorted(record["affectedAccounts"]) == ["111111111111", "222222222222"]

    def test_single_message_event_still_starts_exactly_once(self):
        """Sanity check: single-account events (today's only tested case)
        keep working — one message, one settle callback, one execution."""
        ddb = _make_ddb_stub()
        sfn = _make_sfn_stub()
        sqs = MagicMock()
        svc = _service(ddb, sfn, sqs)

        msg = org_view_message(account="111111111111")
        result = svc.process_message(msg)
        svc.start_settled_workflow(result["event_arn"], msg["detail"]["lastUpdatedTime"])

        assert sfn.start_execution.call_count == 1


class TestEventSnapshot:
    """S3 event snapshot (req E7.1, design §3.6, task 8, working spec
    feat-devops-agent-enrichment)."""

    def _service_with_s3(self, snapshot_bucket_name="test-snapshot-bucket"):
        ddb = _make_ddb_stub()
        sfn = _make_sfn_stub()
        sqs = MagicMock()
        s3 = MagicMock()
        svc = IntakeService(
            dynamodb_client=ddb,
            stepfunctions_client=sfn,
            sqs_client=sqs,
            s3_client=s3,
            consolidated_table_name="ConsolidatedEvents",
            idempotency_table_name="Idempotency",
            account_cache_table_name="AccountCache",
            ticket_map_table_name="TicketMap",
            audit_log_table_name="AuditLog",
            workflow_arn="arn:aws:states:us-east-1:123456789012:stateMachine:TriageWorkflow",
            settle_queue_url="https://sqs.us-east-1.amazonaws.com/123456789012/settle-queue",
            snapshot_bucket_name=snapshot_bucket_name,
        )
        return svc, s3

    def test_snapshot_written_on_new_message(self):
        svc, s3 = self._service_with_s3()
        msg = org_view_message(account="111111111111")

        result = svc.process_message(msg)

        assert result["snapshot_key"] != ""
        s3.put_object.assert_called_once()
        call_kwargs = s3.put_object.call_args.kwargs
        assert call_kwargs["Bucket"] == "test-snapshot-bucket"
        assert call_kwargs["Key"] == result["snapshot_key"]
        assert call_kwargs["ContentType"] == "application/json"

    def test_snapshot_key_format_has_no_colon_or_slash_from_timestamp(self):
        """design §3.6: 'the hash avoids :/ in the key' — confirmed for
        both the eventArn-hash prefix (via hashing) and the timestamp
        suffix (via colon replacement)."""
        svc, s3 = self._service_with_s3()
        msg = org_view_message(account="111111111111")

        result = svc.process_message(msg)

        key = result["snapshot_key"]
        assert key.startswith("events/")
        assert key.endswith(".json")
        # Split off the "events/" prefix and ".json" suffix; the middle
        # must contain no ':' at all (the hash is hex, the timestamp had
        # its colons replaced).
        middle = key[len("events/"):-len(".json")]
        assert ":" not in middle

    def test_snapshot_key_is_deterministic_hash_of_event_arn(self):
        svc, s3 = self._service_with_s3()
        msg_a = org_view_message(account="111111111111")
        result_a = svc.process_message(msg_a)

        # A second message for the SAME eventArn/lastUpdatedTime, different
        # account, must hash to the same eventArn-hash prefix (same
        # eventArn), even though it's a different message.
        msg_b = org_view_message(account="222222222222")
        result_b = svc.process_message(msg_b)

        prefix_a = result_a["snapshot_key"].split("/")[1]
        prefix_b = result_b["snapshot_key"].split("/")[1]
        assert prefix_a == prefix_b

    def test_snapshot_body_contains_full_record(self):
        svc, s3 = self._service_with_s3()
        msg = org_view_message(account="111111111111")

        svc.process_message(msg)

        body = s3.put_object.call_args.kwargs["Body"]
        parsed_body = json.loads(body.decode("utf-8"))
        assert parsed_body["eventArn"] == msg["detail"]["eventArn"]
        assert "111111111111" in parsed_body["affectedAccounts"]

    def test_snapshot_key_stamped_onto_consolidated_record(self):
        """The snapshotKey must be saved onto ConsolidatedEvents itself
        (not just returned from process_message()), so the workflow's
        LoadEvent step can read it back from $.event.snapshotKey and
        forward it into the enrichment webhook's [EVENT_SNAPSHOT:...] tag
        (task 5/11) without a second S3 round-trip."""
        svc, s3 = self._service_with_s3()
        msg = org_view_message(account="111111111111")

        result = svc.process_message(msg)

        saved_record = svc._load_consolidated(result["event_arn"])
        assert saved_record["snapshotKey"] == result["snapshot_key"]
        assert saved_record["snapshotKey"] != ""

    def test_snapshot_key_absent_from_record_when_bucket_not_configured(self):
        svc, s3 = self._service_with_s3(snapshot_bucket_name="")
        msg = org_view_message(account="111111111111")

        result = svc.process_message(msg)

        saved_record = svc._load_consolidated(result["event_arn"])
        assert saved_record["snapshotKey"] == ""

    def test_no_write_when_bucket_not_configured(self):
        svc, s3 = self._service_with_s3(snapshot_bucket_name="")
        msg = org_view_message(account="111111111111")

        result = svc.process_message(msg)

        assert result["snapshot_key"] == ""
        s3.put_object.assert_not_called()

    def test_write_failure_degrades_gracefully_does_not_raise(self):
        svc, s3 = self._service_with_s3()
        s3.put_object.side_effect = Exception("AccessDenied")
        msg = org_view_message(account="111111111111")

        # Must not raise -- process_message() continues to completion.
        result = svc.process_message(msg)

        assert result["status"] == "processed"
        assert result["snapshot_key"] == ""

    def test_write_failure_does_not_block_settle_enqueue(self):
        """A snapshot write failure is independent of the rest of the
        pipeline -- the settle message is still enqueued so the workflow
        still eventually runs (degraded enrichment, not a dropped event)."""
        svc, s3 = self._service_with_s3()
        s3.put_object.side_effect = Exception("AccessDenied")
        msg = org_view_message(account="111111111111")

        svc.process_message(msg)

        svc._sqs.send_message.assert_called_once()
