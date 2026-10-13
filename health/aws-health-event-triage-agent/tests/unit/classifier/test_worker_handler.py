# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Unit tests for src.classifier.worker_handler.WorkerService and handler()."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from src import config
from src.classifier.worker_handler import WorkerService, handler
import src.classifier.worker_handler as worker_mod

EVENT_ARN = "arn:aws:health:us-east-1::event/EKS/TEST/001"


def _make_service(ddb=None, sns=None, jira=None, slack=None, teams=None):
    ddb = ddb or MagicMock()
    sns = sns or MagicMock()
    service = WorkerService(dynamodb_client=ddb, sns_sink=sns, jira_sink=jira, slack_sink=slack, teams_sink=teams)
    return service, ddb, sns


class TestLoadEvent:
    def test_returns_event_when_found(self):
        ddb = MagicMock()
        ddb.get_item.return_value = {
            "Item": {"eventArn": {"S": EVENT_ARN}, "service": {"S": "EKS"}}
        }
        service, _, _ = _make_service(ddb=ddb)
        result = service.load_event(EVENT_ARN)
        assert result["event"]["eventArn"] == EVENT_ARN

    def test_returns_empty_event_when_not_found(self):
        ddb = MagicMock()
        ddb.get_item.return_value = {}
        service, _, _ = _make_service(ddb=ddb)
        result = service.load_event(EVENT_ARN)
        assert result["event"] == {}

    def test_never_raises_on_ddb_failure(self):
        ddb = MagicMock()
        ddb.get_item.side_effect = Exception("throttled")
        service, _, _ = _make_service(ddb=ddb)
        result = service.load_event(EVENT_ARN)
        assert result["event"] == {}


class TestComputeUrgencyStep:
    def test_returns_urgency(self):
        service, _, _ = _make_service()
        result = service.compute_urgency_step("SERVICE_DISRUPTION", None)
        assert result["urgency"] == "critical"


class TestDecideDispositionStep:
    def test_returns_disposition(self):
        service, _, _ = _make_service()
        result = service.decide_disposition_step("INFORMATIONAL", "AWS_GENERIC")
        assert result["disposition"] == "DIGEST"


class TestNotify:
    def test_dispatches_and_saves_ticket_refs(self):
        ddb = MagicMock()
        ddb.get_item.return_value = {}  # no prior ticket refs
        sns = MagicMock()
        sns.upsert.return_value = {"status": "sent", "message_id": "m1"}
        service, _, _ = _make_service(ddb=ddb, sns=sns)

        # 'service'/'eventTypeCode'/'statusCode'/'affectedEntities' live
        # nested under 'event' (the consolidated event), matching what
        # PrepareNotifyInput's ASL parameters actually carry — not flat on
        # the payload. A real deploy + test event caught this: the
        # previous flat-key version of this test never exercised the real
        # payload shape and so never caught worker_handler.py reading the
        # wrong location.
        payload = {
            "eventArn": EVENT_ARN,
            "event": {
                "service": "EKS",
                "eventTypeCode": "AWS_EKS_TEST",
                "statusCode": "open",
                "affectedEntities": [],
            },
            "classification": "BREAKING_CHANGE",
            "urgency": "high",
            "deadline": "2026-09-01",
            "disposition": "TICKET",
            "reason": "test",
        }
        result = service.notify(payload)
        assert result["results"]["sns"]["status"] == "sent"
        ddb.put_item.assert_called_once()

    def test_persists_disposition_to_consolidated_events(self):
        """Real bug regression test: notify() must write disposition/
        dispositionUpdatedAt back onto the ConsolidatedEvents record.
        Confirmed via a real deployed Digest Lambda invocation returning
        {"status": "empty", "event_count": 0} despite a real DIGEST-
        disposition event existing, and a direct DynamoDB get_item showing
        no 'disposition' attribute on the stored item at all — the
        byDispositionUpdatedAt GSI query the digest depends on can never
        match anything without this write."""
        ddb = MagicMock()
        ddb.get_item.return_value = {}
        sns = MagicMock()
        sns.upsert.return_value = {"status": "sent", "message_id": "m1"}
        service, _, _ = _make_service(ddb=ddb, sns=sns)

        payload = {
            "eventArn": EVENT_ARN,
            "event": {
                "service": "EKS",
                "eventTypeCode": "AWS_EKS_TEST",
                "statusCode": "open",
                "affectedEntities": [],
            },
            "classification": "INFORMATIONAL",
            "urgency": "low",
            "deadline": None,
            "disposition": "DIGEST",
            "reason": "test",
        }
        service.notify(payload)

        ddb.update_item.assert_called_once()
        call_kwargs = ddb.update_item.call_args.kwargs
        assert call_kwargs["TableName"] == config.CONSOLIDATED_TABLE_NAME
        assert call_kwargs["Key"] == {"eventArn": {"S": EVENT_ARN}}
        values = call_kwargs["ExpressionAttributeValues"]
        assert values[":disposition"] == {"S": "DIGEST"}
        assert values[":classification"] == {"S": "INFORMATIONAL"}
        assert "dispositionUpdatedAt" in call_kwargs["UpdateExpression"]

    def test_save_disposition_never_raises_on_ddb_failure(self):
        """_save_disposition() must never raise past notify() — a failure
        to persist the digest-query fields must not block the NOTIFY
        step's actual notification dispatch, which has already completed
        by the time this write happens."""
        ddb = MagicMock()
        ddb.get_item.return_value = {}
        ddb.update_item.side_effect = Exception("throttled")
        sns = MagicMock()
        sns.upsert.return_value = {"status": "sent", "message_id": "m1"}
        service, _, _ = _make_service(ddb=ddb, sns=sns)

        payload = {
            "eventArn": EVENT_ARN,
            "event": {"service": "EKS", "statusCode": "open", "affectedEntities": []},
            "classification": "INFORMATIONAL",
            "disposition": "DIGEST",
        }
        # Should not raise.
        result = service.notify(payload)
        assert result["results"]["sns"]["status"] == "sent"

    def test_closing_event_calls_close(self):
        ddb = MagicMock()
        ddb.get_item.return_value = {
            "Item": {"sinkRefs": {"S": json.dumps({"sns": {"message_id": "m1"}})}}
        }
        sns = MagicMock()
        sns.close.return_value = {"status": "skipped"}
        service, _, _ = _make_service(ddb=ddb, sns=sns)

        payload = {
            "eventArn": EVENT_ARN,
            "event": {"service": "EKS", "statusCode": "closed", "affectedEntities": []},
            "classification": "BREAKING_CHANGE",
            "disposition": "TICKET",
        }
        result = service.notify(payload)
        assert result["closed"] is True

    def test_resolves_team_from_nested_event_service(self, monkeypatch):
        """Real bug regression test: notify() must read 'service' from
        payload['event'], not a flat payload['service'] key that
        PrepareNotifyInput's ASL parameters never actually set. A real
        eu-west-1 deploy + AWS_EKS_PLANNED_LIFECYCLE_EVENT test event
        (service: "EKS") always resolved to the DEFAULT routing rule
        instead of config/routing.example.json's SERVICE/EKS ->
        Platform-Kubernetes rule until this was fixed."""
        ddb = MagicMock()
        ddb.get_item.return_value = {}
        sns = MagicMock()
        sns.upsert.return_value = {"status": "sent", "message_id": "m1"}
        service, _, _ = _make_service(ddb=ddb, sns=sns)

        real_routing_table = [
            {
                "ruleType": "SERVICE",
                "key": "EKS",
                "team": "Platform-Kubernetes",
                "snsTopicArn": "arn:aws:sns:us-east-1:123456789012:pk-notifications",
                "jiraProject": "PLATK8S",
                "chatChannel": "#platform-kubernetes-alerts",
                "escalation": "pk-oncall@example.com",
            },
            {
                "ruleType": "DEFAULT",
                "key": "*",
                "team": "Platform-Operations",
                "snsTopicArn": "arn:aws:sns:us-east-1:123456789012:default",
                "jiraProject": "PLATOPS",
                "chatChannel": "#platform-operations-alerts",
                "escalation": "ops-oncall@example.com",
            },
        ]
        monkeypatch.setattr(
            "src.triage.routing._load_routing_table", lambda: real_routing_table
        )
        monkeypatch.setattr("src.triage.routing._routing_cache", None)

        payload = {
            "eventArn": EVENT_ARN,
            "event": {
                "service": "EKS",
                "eventTypeCode": "AWS_EKS_PLANNED_LIFECYCLE_EVENT",
                "statusCode": "open",
                "affectedEntities": [],
            },
            "classification": "BREAKING_CHANGE",
            "disposition": "TICKET",
        }
        result = service.notify(payload)
        assert result["team"]["team"] == "Platform-Kubernetes"
        assert result["team"]["routing"] == "service"


class TestAudit:
    def test_writes_audit_record(self):
        ddb = MagicMock()
        service, _, _ = _make_service(ddb=ddb)
        result = service.audit(EVENT_ARN, "exec-1", "SUCCESS", None)
        assert result["status"] == "written"
        ddb.put_item.assert_called_once()

    def test_never_raises_on_write_failure(self):
        ddb = MagicMock()
        ddb.put_item.side_effect = Exception("throttled")
        service, _, _ = _make_service(ddb=ddb)
        result = service.audit(EVENT_ARN, "exec-1", "ERROR", "boom")
        assert result["status"] == "failed"


class TestHandlerDispatch:
    def test_load_event_step(self, monkeypatch):
        mock_service = MagicMock()
        mock_service.load_event.return_value = {"event": {"eventArn": EVENT_ARN}}
        monkeypatch.setattr(worker_mod, "_service", mock_service)
        result = handler({"step": "LOAD_EVENT", "eventArn": EVENT_ARN}, None)
        assert result["event"]["eventArn"] == EVENT_ARN

    def test_notify_step(self, monkeypatch):
        mock_service = MagicMock()
        mock_service.notify.return_value = {"closed": False, "results": {}}
        monkeypatch.setattr(worker_mod, "_service", mock_service)
        result = handler({"step": "NOTIFY", "eventArn": EVENT_ARN}, None)
        assert result["closed"] is False

    def test_unknown_step_returns_error(self):
        result = handler({"step": "BOGUS", "eventArn": EVENT_ARN}, None)
        assert "error" in result
