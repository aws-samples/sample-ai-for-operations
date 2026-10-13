# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Unit tests for src.devops_agent.callback_handler."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from src.devops_agent.callback_handler import (
    CallbackService,
    DevOpsAgentClientUnavailable,
    _extract_correlation_key,
    _message_text,
)


def _user_message(text: str) -> dict:
    return {"role": "user", "content": [{"type": "text", "text": text}]}


def _assistant_message(text: str) -> dict:
    return {"role": "assistant", "content": [{"type": "text", "text": text}]}


class TestExtractCorrelationKey:
    def test_investigation_id_preferred(self):
        text = "[CORRELATION_ID:arn:1] [INVESTIGATION_ID:health-ec2-1-abcd] rest of prompt"
        assert _extract_correlation_key(text) == "health-ec2-1-abcd"

    def test_correlation_id_fallback_prefixed_with_arn(self):
        text = "[CORRELATION_ID:arn:aws:health:us-east-1::event/1] rest of prompt"
        assert _extract_correlation_key(text) == "arn:arn:aws:health:us-east-1::event/1"

    def test_title_fallback(self):
        text = "TITLE: [health-ec2-1-abcd] AWS Health: EC2 issue in us-east-1"
        assert _extract_correlation_key(text) == "health-ec2-1-abcd"

    def test_no_tags_returns_none(self):
        assert _extract_correlation_key("just some text with no tags") is None

    def test_investigation_id_wins_over_title(self):
        text = "[INVESTIGATION_ID:health-abc] TITLE: [health-other] AWS Health: ..."
        assert _extract_correlation_key(text) == "health-abc"


class TestMessageText:
    def test_joins_text_parts(self):
        content = [{"type": "text", "text": "hello"}, {"type": "text", "text": "world"}]
        assert _message_text(content) == "hello world"

    def test_ignores_non_text_parts(self):
        content = [{"type": "thinking", "text": "internal"}, {"type": "text", "text": "hello"}]
        assert _message_text(content) == "hello"


def _service(**overrides) -> CallbackService:
    return CallbackService(
        dynamodb_client=overrides.get("dynamodb_client", MagicMock()),
        sfn_client=overrides.get("sfn_client", MagicMock()),
        devopsagent_client=overrides.get("devopsagent_client", MagicMock()),
    )


class TestHandleNoExecutionId:
    def test_missing_execution_id_skips(self):
        svc = _service()
        result = svc.handle("Investigation Completed", {"metadata": {}})
        assert result["status"] == "skipped"


class TestHandleNoJournalMessages:
    def test_no_records_skips(self):
        devopsagent = MagicMock()
        devopsagent.list_journal_records.return_value = {"records": []}
        svc = _service(devopsagent_client=devopsagent)
        result = svc.handle(
            "Investigation Completed",
            {"metadata": {"agent_space_id": "space-1", "task_id": "task-1", "execution_id": "exec-1"}},
        )
        assert result["status"] == "skipped"
        assert result["reason"] == "no journal messages"


class TestHandleNoCorrelationKey:
    def test_uncorrelated_message_skips(self):
        devopsagent = MagicMock()
        devopsagent.list_journal_records.return_value = {
            "records": [{"content": json.dumps(_user_message("no tags here"))}]
        }
        svc = _service(devopsagent_client=devopsagent)
        result = svc.handle(
            "Investigation Completed",
            {"metadata": {"agent_space_id": "space-1", "task_id": "task-1", "execution_id": "exec-1"}},
        )
        assert result["status"] == "skipped"
        assert result["reason"] == "no correlation key"


class TestHandleNoTaskToken:
    def test_missing_task_token_skips(self):
        ddb = MagicMock()
        ddb.get_item.return_value = {}
        devopsagent = MagicMock()
        devopsagent.list_journal_records.return_value = {
            "records": [{"content": json.dumps(_user_message("[INVESTIGATION_ID:health-1]"))}]
        }
        svc = _service(dynamodb_client=ddb, devopsagent_client=devopsagent)
        result = svc.handle(
            "Investigation Completed",
            {"metadata": {"agent_space_id": "space-1", "task_id": "task-1", "execution_id": "exec-1"}},
        )
        assert result["status"] == "skipped"
        assert result["reason"] == "no task token"


class TestHandleCompletedWithAnalysis:
    def test_send_task_success_with_summarized_outcome(self):
        ddb = MagicMock()
        ddb.get_item.return_value = {"Item": {"taskToken": {"S": "token-abc"}}}
        sfn = MagicMock()

        analysis = (
            "## Summary\n\nSomething broke.\n\n## Key Findings\n\n"
            "- **payments-api**: CRITICAL — no redundancy. Affected resources: i-1. Redundancy: no.\n"
        )
        first_msg = _user_message("[INVESTIGATION_ID:health-1]")
        last_msg = _assistant_message(analysis)

        devopsagent = MagicMock()
        devopsagent.list_journal_records.side_effect = [
            {"records": [{"content": json.dumps(first_msg)}]},  # first message (ASC)
            {"records": [{"content": json.dumps(last_msg)}]},  # analysis (DESC)
        ]

        svc = _service(dynamodb_client=ddb, sfn_client=sfn, devopsagent_client=devopsagent)
        result = svc.handle(
            "Investigation Completed",
            {
                "metadata": {"agent_space_id": "space-1", "task_id": "task-1", "execution_id": "exec-1"},
                "data": {"priority": "MEDIUM"},
            },
        )

        assert result["status"] == "completed"
        sfn.send_task_success.assert_called_once()
        output = json.loads(sfn.send_task_success.call_args.kwargs["output"])
        assert output["impact"] == "confirmed"
        assert output["taskId"] == "task-1"
        ddb.delete_item.assert_called_once_with(
            TableName=ddb.delete_item.call_args.kwargs["TableName"],
            Key={"investigationId": {"S": "health-1"}},
        )


class TestHandleFailedDetailType:
    def test_send_task_failure_for_non_completed_type(self):
        ddb = MagicMock()
        ddb.get_item.return_value = {"Item": {"taskToken": {"S": "token-abc"}}}
        sfn = MagicMock()
        devopsagent = MagicMock()
        devopsagent.list_journal_records.return_value = {
            "records": [{"content": json.dumps(_user_message("[INVESTIGATION_ID:health-1]"))}]
        }
        svc = _service(dynamodb_client=ddb, sfn_client=sfn, devopsagent_client=devopsagent)

        result = svc.handle(
            "Investigation Failed",
            {"metadata": {"agent_space_id": "space-1", "task_id": "task-1", "execution_id": "exec-1"}},
        )

        assert result["status"] == "completed"
        sfn.send_task_failure.assert_called_once()
        call_kwargs = sfn.send_task_failure.call_args.kwargs
        assert call_kwargs["error"] == "InvestigationFailed"
        sfn.send_task_success.assert_not_called()


class TestFindTaskTokenLegacyScan:
    def test_arn_prefixed_key_uses_scan(self):
        ddb = MagicMock()
        ddb.scan.return_value = {
            "Items": [{"taskToken": {"S": "token-abc"}, "investigationId": {"S": "health-legacy-1"}}]
        }
        svc = _service(dynamodb_client=ddb)
        result = svc._find_task_token("arn:arn:aws:health:us-east-1::event/1")
        assert result == {"taskToken": "token-abc", "investigationId": "health-legacy-1", "kind": "incident"}
        ddb.scan.assert_called_once()
        ddb.get_item.assert_not_called()

    def test_scan_result_preserves_readiness_kind(self):
        ddb = MagicMock()
        ddb.scan.return_value = {
            "Items": [
                {
                    "taskToken": {"S": "token-abc"},
                    "investigationId": {"S": "health-legacy-1"},
                    "kind": {"S": "readiness"},
                }
            ]
        }
        svc = _service(dynamodb_client=ddb)
        result = svc._find_task_token("arn:arn:aws:health:us-east-1::event/1")
        assert result["kind"] == "readiness"


class TestFindTaskTokenKindDefaultsToIncident:
    def test_missing_kind_attribute_defaults_to_incident(self):
        ddb = MagicMock()
        ddb.get_item.return_value = {"Item": {"taskToken": {"S": "token-abc"}}}
        svc = _service(dynamodb_client=ddb)
        result = svc._find_task_token("health-1")
        assert result["kind"] == "incident"

    def test_readiness_kind_is_read_from_item(self):
        ddb = MagicMock()
        ddb.get_item.return_value = {
            "Item": {"taskToken": {"S": "token-abc"}, "kind": {"S": "readiness"}}
        }
        svc = _service(dynamodb_client=ddb)
        result = svc._find_task_token("health-1")
        assert result["kind"] == "readiness"


class TestHandleCompletedEnrichmentKind:
    """Task 7, working spec feat-devops-agent-enrichment, design §3.4: one
    parser path for kind='enrichment' — every callback returns
    analysisMarkdown + impact (kept) + readiness (parsed from the SAME
    analysis text), instead of the old two-kind dispatch."""

    def test_send_task_success_with_both_impact_and_readiness(self):
        ddb = MagicMock()
        ddb.get_item.return_value = {
            "Item": {"taskToken": {"S": "token-abc"}, "kind": {"S": "enrichment"}}
        }
        sfn = MagicMock()

        analysis = (
            "## Summary\n\nThe RDS instance is affected.\n\n"
            "## Key Findings\n\n"
            "- **orders-db**: HIGH — extended support charges apply. Affected resources: db-1. Redundancy: no.\n\n"
            "## Readiness Assessment\n\n"
            "FEASIBILITY: READY\n"
            "BLOCKERS: NONE\n"
            "RISK: LOW\n"
            "ROLLBACK_AVAILABLE: YES\n"
        )
        first_msg = _user_message("[INVESTIGATION_ID:health-1]")
        last_msg = _assistant_message(analysis)

        devopsagent = MagicMock()
        devopsagent.list_journal_records.side_effect = [
            {"records": [{"content": json.dumps(first_msg)}]},
            {"records": [{"content": json.dumps(last_msg)}]},
        ]

        svc = _service(dynamodb_client=ddb, sfn_client=sfn, devopsagent_client=devopsagent)
        result = svc.handle(
            "Investigation Completed",
            {
                "metadata": {"agent_space_id": "space-1", "task_id": "task-1", "execution_id": "exec-1"},
                "data": {"priority": "HIGH"},
            },
        )

        assert result["status"] == "completed"
        sfn.send_task_success.assert_called_once()
        output = json.loads(sfn.send_task_success.call_args.kwargs["output"])

        assert output["analysisMarkdown"] == analysis
        assert output["impact"] == "confirmed"
        assert output["readiness"]["feasibility"] == "ready"
        assert output["readiness"]["blockers"] == []
        assert output["readiness"]["risk"] == "low"
        assert output["readiness"]["rollback_available"] is True
        assert output["taskId"] == "task-1"
        assert output["agentSpaceId"] == "space-1"

    def test_readiness_key_present_even_when_no_readiness_section(self):
        """An enrichment investigation for a non-deadline event has no
        readiness question to answer at all — the 'readiness' key must
        still be present (with degraded values), never omitted."""
        ddb = MagicMock()
        ddb.get_item.return_value = {
            "Item": {"taskToken": {"S": "token-abc"}, "kind": {"S": "enrichment"}}
        }
        sfn = MagicMock()

        analysis = "## Summary\n\nNo operational impact detected for this event.\n"
        first_msg = _user_message("[INVESTIGATION_ID:health-1]")
        last_msg = _assistant_message(analysis)

        devopsagent = MagicMock()
        devopsagent.list_journal_records.side_effect = [
            {"records": [{"content": json.dumps(first_msg)}]},
            {"records": [{"content": json.dumps(last_msg)}]},
        ]

        svc = _service(dynamodb_client=ddb, sfn_client=sfn, devopsagent_client=devopsagent)
        svc.handle(
            "Investigation Completed",
            {
                "metadata": {"agent_space_id": "space-1", "task_id": "task-1", "execution_id": "exec-1"},
                "data": {"priority": "MEDIUM"},
            },
        )

        output = json.loads(sfn.send_task_success.call_args.kwargs["output"])
        assert "readiness" in output
        assert output["readiness"]["feasibility"] == "unverifiable"

    def test_no_analysis_at_all_still_returns_both_fields(self):
        """The degraded case (investigation completed, journal read
        failed) must still carry analysisMarkdown: None and both impact
        and readiness in their own degraded shapes — never a KeyError
        downstream."""
        ddb = MagicMock()
        ddb.get_item.return_value = {
            "Item": {"taskToken": {"S": "token-abc"}, "kind": {"S": "enrichment"}}
        }
        sfn = MagicMock()
        first_msg = _user_message("[INVESTIGATION_ID:health-1]")

        devopsagent = MagicMock()
        # First call (ASC, first message) succeeds; second call (DESC,
        # analysis) returns no records at all -- simulates a journal read
        # that finds the correlation tag but not the final assistant reply.
        devopsagent.list_journal_records.side_effect = [
            {"records": [{"content": json.dumps(first_msg)}]},
            {"records": []},
        ]

        svc = _service(dynamodb_client=ddb, sfn_client=sfn, devopsagent_client=devopsagent)
        svc.handle(
            "Investigation Completed",
            {"metadata": {"agent_space_id": "space-1", "task_id": "task-1", "execution_id": "exec-1"}},
        )

        output = json.loads(sfn.send_task_success.call_args.kwargs["output"])
        assert output["analysisMarkdown"] is None
        assert output["impact"] == "unverifiable"
        assert output["readiness"]["feasibility"] == "unverifiable"

    def test_enrichment_kind_still_dispatches_send_task_failure_for_non_completed(self):
        """Non-'Investigation Completed' detail types (timeout, cancelled)
        must still use SendTaskFailure regardless of kind -- unchanged from
        the pre-existing behaviour."""
        ddb = MagicMock()
        ddb.get_item.return_value = {
            "Item": {"taskToken": {"S": "token-abc"}, "kind": {"S": "enrichment"}}
        }
        sfn = MagicMock()
        devopsagent = MagicMock()
        devopsagent.list_journal_records.return_value = {
            "records": [{"content": json.dumps(_user_message("[INVESTIGATION_ID:health-1]"))}]
        }
        svc = _service(dynamodb_client=ddb, sfn_client=sfn, devopsagent_client=devopsagent)

        result = svc.handle(
            "Investigation Failed",
            {"metadata": {"agent_space_id": "space-1", "task_id": "task-1", "execution_id": "exec-1"}},
        )

        assert result["status"] == "completed"
        sfn.send_task_failure.assert_called_once()
        sfn.send_task_success.assert_not_called()


class TestDevOpsAgentClientUnavailable:
    def test_deferred_client_error_is_specific(self):
        svc = CallbackService()
        # Force the property to fail as if boto3 lacks the service model.
        import src.devops_agent.callback_handler as mod

        original_client = mod.boto3.client

        def _raise_unknown_service(*args, **kwargs):
            raise mod.boto3.exceptions.UnknownServiceError(
                service_name="devops-agent", known_service_names="s3, dynamodb"
            )

        mod.boto3.client = _raise_unknown_service
        try:
            with pytest.raises(DevOpsAgentClientUnavailable):
                _ = svc._devopsagent
        finally:
            mod.boto3.client = original_client

    def test_first_journal_message_returns_none_on_client_unavailable(self):
        svc = CallbackService()
        svc._devopsagent_client_error = RuntimeError("no such client")
        result = svc._get_first_journal_message("space-1", "exec-1")
        assert result is None
