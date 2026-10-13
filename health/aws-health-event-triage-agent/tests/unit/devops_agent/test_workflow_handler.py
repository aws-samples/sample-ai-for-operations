# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Unit tests for src.devops_agent.workflow_handler."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from src.devops_agent.workflow_handler import DevOpsAgentWorkflowService, handler


def _service(**kwargs) -> DevOpsAgentWorkflowService:
    return DevOpsAgentWorkflowService(
        dynamodb_client=kwargs.get("dynamodb_client", MagicMock()),
        secrets_client=kwargs.get("secrets_client", MagicMock()),
    )


class TestResolveAgentSpaceStep:
    @patch(
        "src.devops_agent.workflow_handler.resolve_agent_space",
        return_value={"agentSpaceId": "space-1"},
    )
    def test_resolves_from_affected_account(self, mock_resolve):
        svc = _service()
        event = {"event": {"affectedAccount": "111111111111"}, "accountContexts": []}
        result = svc.resolve_agent_space_step(event)
        assert result == {"agentSpaceEntry": {"agentSpaceId": "space-1"}}
        mock_resolve.assert_called_once_with(["111111111111"], [])

    @patch("src.devops_agent.workflow_handler.resolve_agent_space", return_value=None)
    def test_no_match_returns_none_entry(self, mock_resolve):
        svc = _service()
        event = {"event": {"affectedAccounts": ["222222222222"]}}
        result = svc.resolve_agent_space_step(event)
        assert result == {"agentSpaceEntry": None}


class TestResolveAgentSpacesStep:
    """RESOLVE_AGENT_SPACES (plural) — task 11, design §3.0. Distinct from
    RESOLVE_AGENT_SPACE (singular), tested above — that step is completely
    untouched by this addition."""

    @patch(
        "src.devops_agent.workflow_handler.resolve_agent_spaces_by_account",
        return_value=[
            {"agentSpaceEntry": {"agentSpaceId": "space-1"}, "accounts": ["111111111111"]},
            {"agentSpaceEntry": {"agentSpaceId": "space-2"}, "accounts": ["222222222222"]},
        ],
    )
    def test_multi_space_result_returned_as_groups(self, mock_resolve):
        svc = _service()
        event = {
            "event": {"affectedAccounts": ["111111111111", "222222222222"]},
            "accountContexts": [],
        }
        result = svc.resolve_agent_spaces_step(event)
        assert len(result["agentSpaceGroups"]) == 2
        space_ids = {g["agentSpaceEntry"]["agentSpaceId"] for g in result["agentSpaceGroups"]}
        assert space_ids == {"space-1", "space-2"}
        mock_resolve.assert_called_once_with(["111111111111", "222222222222"], [])

    @patch(
        "src.devops_agent.workflow_handler.resolve_agent_spaces_by_account",
        return_value=[{"agentSpaceEntry": None, "accounts": ["999999999999"]}],
    )
    def test_uncovered_accounts_pass_through(self, mock_resolve):
        svc = _service()
        event = {"event": {"affectedAccounts": ["999999999999"]}, "accountContexts": []}
        result = svc.resolve_agent_spaces_step(event)
        assert result["agentSpaceGroups"][0]["agentSpaceEntry"] is None
        assert result["agentSpaceGroups"][0]["accounts"] == ["999999999999"]

    @patch(
        "src.devops_agent.workflow_handler.resolve_agent_spaces_by_account",
        return_value=[],
    )
    def test_singular_affected_account_field_normalised_to_list(self, mock_resolve):
        svc = _service()
        event = {"event": {"affectedAccount": "111111111111"}, "accountContexts": []}
        svc.resolve_agent_spaces_step(event)
        mock_resolve.assert_called_once_with(["111111111111"], [])


class TestDecideInvestigationStep:
    @patch("src.devops_agent.workflow_handler.decide_investigation")
    def test_no_registry_entry_skips_dedupe_and_counters(self, mock_decide):
        mock_decide.return_value = {"trigger": False, "reason": "x", "skip_kind": "no_registry"}
        svc = _service()
        event = {"event": {"eventArn": "arn:1"}, "agentSpaceEntry": None}
        result = svc.decide_investigation_step(event)
        assert result["investigationDecision"]["skip_kind"] == "no_registry"

    @patch("src.devops_agent.workflow_handler.get_incident_counter", return_value={"incident_count_this_month": 0, "cap": 10})
    @patch("src.devops_agent.workflow_handler.dedupe_check", return_value={"duplicate": False, "existing_investigation_id": None})
    @patch("src.devops_agent.workflow_handler.decide_investigation")
    def test_with_registry_entry_calls_dedupe_and_counters(self, mock_decide, mock_dedupe, mock_counter):
        mock_decide.return_value = {"trigger": True, "reason": "eligible", "skip_kind": None}
        svc = _service()
        event = {
            "event": {"eventArn": "arn:1"},
            "agentSpaceEntry": {"agentSpaceId": "space-1", "incidentCapPerMonth": 10, "dedupeWindowMinutes": 60},
        }
        result = svc.decide_investigation_step(event)
        assert result["investigationDecision"]["trigger"] is True
        mock_dedupe.assert_called_once_with("space-1", "arn:1", 60)
        mock_counter.assert_called_once_with("space-1", 10)

    @patch("src.devops_agent.workflow_handler.get_incident_counter", return_value={"incident_count_this_month": 0, "cap": 10})
    @patch("src.devops_agent.workflow_handler.dedupe_check", return_value={"duplicate": False, "existing_investigation_id": None})
    @patch("src.devops_agent.workflow_handler.decide_investigation")
    def test_default_kind_is_incident_no_readiness_fields(self, mock_decide, mock_dedupe, mock_counter):
        """Task 6: a call with no 'kind' field (every pre-task-6 caller)
        must not compute readiness at all — no askReadiness/
        readinessAccounts keys on the result, not just False/[] values."""
        mock_decide.return_value = {"trigger": True, "reason": "eligible", "skip_kind": None}
        svc = _service()
        event = {
            "event": {"eventArn": "arn:1"},
            "agentSpaceEntry": {"agentSpaceId": "space-1", "incidentCapPerMonth": 10, "dedupeWindowMinutes": 60},
        }
        result = svc.decide_investigation_step(event)
        assert "askReadiness" not in result
        assert "readinessAccounts" not in result
        # decide_investigation() called WITHOUT enrichment kind/classification.
        call_kwargs = mock_decide.call_args.kwargs
        assert call_kwargs["kind"] == "incident"

    @patch("src.devops_agent.workflow_handler.decide_readiness")
    @patch("src.devops_agent.workflow_handler.get_incident_counter", return_value={"incident_count_this_month": 0, "cap": 10})
    @patch("src.devops_agent.workflow_handler.dedupe_check", return_value={"duplicate": False, "existing_investigation_id": None})
    @patch("src.devops_agent.workflow_handler.decide_investigation")
    def test_enrichment_kind_also_computes_readiness_in_same_step(
        self, mock_decide, mock_dedupe, mock_counter, mock_decide_readiness
    ):
        """Task 6, design §3.2: kind='enrichment' runs decide_readiness()
        INSIDE this step (not a separate parallel branch) and folds
        askReadiness/readinessAccounts onto the result."""
        mock_decide.return_value = {"trigger": True, "reason": "eligible", "skip_kind": None}
        mock_decide_readiness.return_value = {
            "trigger": True,
            "reason": "eligible",
            "accounts_to_assess": ["111111111111"],
            "skip_kind": None,
        }
        svc = _service()
        event = {
            "event": {"eventArn": "arn:1"},
            "agentSpaceEntry": {
                "agentSpaceId": "space-1",
                "incidentCapPerMonth": 10,
                "dedupeWindowMinutes": 60,
                "readinessCapPerMonth": 5,
            },
            "kind": "enrichment",
            "classification": "BREAKING_CHANGE",
            "deadline": "2027-01-01",
            "impactSummary": {"impact_status": "confirmed", "by_account": {"111111111111": {}}},
        }
        with patch(
            "src.devops_agent.workflow_handler.has_prior_assessment", return_value={"assessed_accounts": []}
        ), patch(
            "src.devops_agent.workflow_handler.get_readiness_counter",
            return_value={"readiness_count_this_month": 0, "cap": 5},
        ):
            result = svc.decide_investigation_step(event)

        assert result["investigationDecision"]["trigger"] is True
        assert result["askReadiness"] is True
        assert result["readinessAccounts"] == ["111111111111"]
        # decide_investigation() called WITH kind="enrichment" and the classification.
        call_kwargs = mock_decide.call_args.kwargs
        assert call_kwargs["kind"] == "enrichment"
        assert call_kwargs["classification"] == "BREAKING_CHANGE"

    @patch("src.devops_agent.workflow_handler.get_incident_counter", return_value={"incident_count_this_month": 0, "cap": 10})
    @patch("src.devops_agent.workflow_handler.dedupe_check", return_value={"duplicate": False, "existing_investigation_id": None})
    @patch("src.devops_agent.workflow_handler.decide_investigation")
    def test_enrichment_kind_decide_readiness_error_degrades_gracefully(
        self, mock_decide, mock_dedupe, mock_counter
    ):
        """decide_readiness() failing must never take down the enrichment
        investigation decision itself — readiness is additive."""
        mock_decide.return_value = {"trigger": True, "reason": "eligible", "skip_kind": None}
        svc = _service()
        event = {
            "event": {"eventArn": "arn:1"},
            "agentSpaceEntry": {"agentSpaceId": "space-1", "incidentCapPerMonth": 10, "dedupeWindowMinutes": 60},
            "kind": "enrichment",
            "classification": "BREAKING_CHANGE",
        }
        with patch(
            "src.devops_agent.workflow_handler.has_prior_assessment", side_effect=Exception("ddb error")
        ):
            result = svc.decide_investigation_step(event)

        assert result["investigationDecision"]["trigger"] is True
        assert result["askReadiness"] is False
        assert result["readinessAccounts"] == []

    @patch("src.devops_agent.workflow_handler.decide_investigation")
    def test_no_registry_entry_with_enrichment_kind_still_returns_readiness_fields(self, mock_decide):
        mock_decide.return_value = {"trigger": False, "reason": "x", "skip_kind": "no_registry"}
        svc = _service()
        event = {
            "event": {"eventArn": "arn:1"},
            "agentSpaceEntry": None,
            "kind": "enrichment",
            "classification": "BREAKING_CHANGE",
        }
        result = svc.decide_investigation_step(event)
        assert result["investigationDecision"]["skip_kind"] == "no_registry"
        assert "askReadiness" in result
        assert result["askReadiness"] is False


class TestTriggerInvestigationStep:
    @patch("src.devops_agent.workflow_handler.record_active_investigation")
    @patch("src.devops_agent.workflow_handler.send_webhook", return_value={"status": "sent", "attempts": 1, "error": None})
    @patch(
        "src.devops_agent.workflow_handler.build_webhook_payload",
        return_value={"incidentId": "health-ec2-1-abcd", "payload": {"a": 1}},
    )
    def test_successful_trigger_saves_task_token(self, mock_build, mock_send, mock_record):
        ddb = MagicMock()
        secrets = MagicMock()
        secrets.get_secret_value.return_value = {"SecretString": "webhook-secret"}
        svc = _service(dynamodb_client=ddb, secrets_client=secrets)

        event = {
            "TaskToken": "token-abc",
            "event": {"eventArn": "arn:1"},
            "agentSpaceEntry": {
                "agentSpaceId": "space-1",
                "triggerMethod": "WEBHOOK",
                "webhookSecretArn": "arn:secret",
                "webhookUrl": "https://example.com/webhook",
            },
        }
        result = svc.trigger_investigation_step(event)

        assert result == {"triggered": True, "incidentId": "health-ec2-1-abcd", "error": None}
        ddb.put_item.assert_called_once()
        mock_record.assert_called_once_with("space-1", "arn:1", "health-ec2-1-abcd")

    @patch(
        "src.devops_agent.workflow_handler.build_webhook_payload",
        return_value={"incidentId": "health-ec2-1-abcd", "payload": {"a": 1}},
    )
    def test_secret_read_failure_sends_task_failure(self, mock_build):
        ddb = MagicMock()
        secrets = MagicMock()
        secrets.get_secret_value.side_effect = Exception("access denied")
        svc = _service(dynamodb_client=ddb, secrets_client=secrets)

        with patch("boto3.client") as mock_boto_client:
            mock_sfn = MagicMock()
            mock_boto_client.return_value = mock_sfn
            event = {
                "TaskToken": "token-abc",
                "event": {"eventArn": "arn:1"},
                "agentSpaceEntry": {
                    "agentSpaceId": "space-1",
                    "triggerMethod": "WEBHOOK",
                    "webhookSecretArn": "arn:secret",
                    "webhookUrl": "https://example.com/webhook",
                },
            }
            result = svc.trigger_investigation_step(event)

        assert result["triggered"] is False
        assert "access denied" in result["error"]
        mock_sfn.send_task_failure.assert_called_once()
        ddb.put_item.assert_not_called()

    def test_assume_role_not_implemented_sends_task_failure(self):
        ddb = MagicMock()
        svc = _service(dynamodb_client=ddb)

        with patch("boto3.client") as mock_boto_client:
            mock_sfn = MagicMock()
            mock_boto_client.return_value = mock_sfn
            event = {
                "TaskToken": "token-abc",
                "event": {"eventArn": "arn:1"},
                "agentSpaceEntry": {"agentSpaceId": "space-1", "triggerMethod": "ASSUME_ROLE"},
            }
            result = svc.trigger_investigation_step(event)

        assert result["triggered"] is False
        assert "ASSUME_ROLE" in result["error"]
        mock_sfn.send_task_failure.assert_called_once()
        call_kwargs = mock_sfn.send_task_failure.call_args.kwargs
        assert call_kwargs["error"] == "NotImplemented"

    @patch(
        "src.devops_agent.workflow_handler.build_webhook_payload",
        return_value={"incidentId": "health-ec2-1-abcd", "payload": {"a": 1}},
    )
    @patch(
        "src.devops_agent.workflow_handler.send_webhook",
        return_value={"status": "failed", "attempts": 3, "error": "network error"},
    )
    def test_webhook_send_failure_sends_task_failure(self, mock_send, mock_build):
        ddb = MagicMock()
        secrets = MagicMock()
        secrets.get_secret_value.return_value = {"SecretString": "webhook-secret"}
        svc = _service(dynamodb_client=ddb, secrets_client=secrets)

        with patch("boto3.client") as mock_boto_client:
            mock_sfn = MagicMock()
            mock_boto_client.return_value = mock_sfn
            event = {
                "TaskToken": "token-abc",
                "event": {"eventArn": "arn:1"},
                "agentSpaceEntry": {
                    "agentSpaceId": "space-1",
                    "triggerMethod": "WEBHOOK",
                    "webhookSecretArn": "arn:secret",
                    "webhookUrl": "https://example.com/webhook",
                },
            }
            result = svc.trigger_investigation_step(event)

        assert result["triggered"] is False
        ddb.put_item.assert_not_called()

    @patch("src.devops_agent.workflow_handler.record_active_investigation")
    @patch("src.devops_agent.workflow_handler.send_webhook", return_value={"status": "sent", "attempts": 1, "error": None})
    @patch(
        "src.devops_agent.workflow_handler.build_webhook_payload",
        return_value={"incidentId": "health-rds-1-abcd", "payload": {"a": 1}},
    )
    def test_enrichment_kind_writes_kind_enrichment_on_task_token(self, mock_build, mock_send, mock_record):
        """Task 6: 'kind': 'enrichment' event field must reach the saved
        task-token record's 'kind' attribute, so callback_handler.py's
        single parser path (task 7) can recognise it."""
        ddb = MagicMock()
        secrets = MagicMock()
        secrets.get_secret_value.return_value = {"SecretString": "webhook-secret"}
        svc = _service(dynamodb_client=ddb, secrets_client=secrets)

        event = {
            "TaskToken": "token-abc",
            "event": {"eventArn": "arn:1"},
            "agentSpaceEntry": {
                "agentSpaceId": "space-1",
                "triggerMethod": "WEBHOOK",
                "webhookSecretArn": "arn:secret",
                "webhookUrl": "https://example.com/webhook",
            },
            "kind": "enrichment",
        }
        svc.trigger_investigation_step(event)

        ddb.put_item.assert_called_once()
        saved_item = ddb.put_item.call_args.kwargs["Item"]
        assert saved_item["kind"]["S"] == "enrichment"

    @patch("src.devops_agent.workflow_handler.record_active_investigation")
    @patch("src.devops_agent.workflow_handler.send_webhook", return_value={"status": "sent", "attempts": 1, "error": None})
    @patch("src.devops_agent.workflow_handler.build_webhook_payload")
    def test_enrichment_fields_passed_through_to_build_webhook_payload(self, mock_build, mock_send, mock_record):
        """Task 6: classification/urgency/deadline/impactLocus/
        s3SnapshotKey on the event must reach build_webhook_payload()'s
        matching keyword arguments (task 5's contract)."""
        mock_build.return_value = {"incidentId": "health-rds-1-abcd", "payload": {"a": 1}}
        ddb = MagicMock()
        secrets = MagicMock()
        secrets.get_secret_value.return_value = {"SecretString": "webhook-secret"}
        svc = _service(dynamodb_client=ddb, secrets_client=secrets)

        event = {
            "TaskToken": "token-abc",
            "event": {"eventArn": "arn:1"},
            "agentSpaceEntry": {
                "agentSpaceId": "space-1",
                "triggerMethod": "WEBHOOK",
                "webhookSecretArn": "arn:secret",
                "webhookUrl": "https://example.com/webhook",
            },
            "kind": "enrichment",
            "classification": "BREAKING_CHANGE",
            "urgency": "high",
            "deadline": "2027-01-01",
            "impactLocus": "dependent",
            "s3SnapshotKey": "events/abc/x.json",
        }
        svc.trigger_investigation_step(event)

        call_kwargs = mock_build.call_args.kwargs
        assert call_kwargs["classification"] == "BREAKING_CHANGE"
        assert call_kwargs["urgency"] == "high"
        assert call_kwargs["deadline"] == "2027-01-01"
        assert call_kwargs["impact_locus"] == "dependent"
        assert call_kwargs["s3_snapshot_key"] == "events/abc/x.json"

    @patch("src.devops_agent.workflow_handler.record_active_investigation")
    @patch("src.devops_agent.workflow_handler.send_webhook", return_value={"status": "sent", "attempts": 1, "error": None})
    @patch(
        "src.devops_agent.workflow_handler.build_webhook_payload",
        return_value={"incidentId": "health-ec2-1-abcd", "payload": {"a": 1}},
    )
    def test_default_kind_still_writes_incident_on_task_token(self, mock_build, mock_send, mock_record):
        """Backward compatibility: a pre-task-6 event with no 'kind' field
        at all still writes 'incident' (byte-identical to before this
        task)."""
        ddb = MagicMock()
        secrets = MagicMock()
        secrets.get_secret_value.return_value = {"SecretString": "webhook-secret"}
        svc = _service(dynamodb_client=ddb, secrets_client=secrets)

        event = {
            "TaskToken": "token-abc",
            "event": {"eventArn": "arn:1"},
            "agentSpaceEntry": {
                "agentSpaceId": "space-1",
                "triggerMethod": "WEBHOOK",
                "webhookSecretArn": "arn:secret",
                "webhookUrl": "https://example.com/webhook",
            },
        }
        svc.trigger_investigation_step(event)

        saved_item = ddb.put_item.call_args.kwargs["Item"]
        assert saved_item["kind"]["S"] == "incident"
        call_kwargs = mock_build.call_args.kwargs
        assert call_kwargs["classification"] == ""
        assert call_kwargs["s3_snapshot_key"] is None


class TestSummarizeOutcomeStep:
    def test_not_triggered_preserves_impact(self):
        svc = _service()
        event = {"investigationDecision": {"trigger": False}, "impact": "unverifiable", "investigationLink": None}
        result = svc.summarize_outcome_step(event)
        assert result == {"impact": "unverifiable", "investigationLink": None}

    def test_triggered_but_no_outcome_defaults_unverifiable(self):
        svc = _service()
        event = {"investigationDecision": {"trigger": True}}
        result = svc.summarize_outcome_step(event)
        assert result == {"impact": "unverifiable", "investigationLink": None}

    def test_triggered_with_outcome_builds_investigation_link(self):
        svc = _service()
        event = {
            "investigationDecision": {"trigger": True},
            "investigationOutcome": {"impact": "confirmed", "taskId": "task-1"},
            "agentSpaceEntry": {"agentSpaceId": "space-1"},
        }
        result = svc.summarize_outcome_step(event)
        assert result["impact"] == "confirmed"
        assert result["investigationLink"] == "https://space-1.aidevops.global.app.aws/investigation/task-1"

    def test_triggered_with_outcome_missing_ids_omits_link(self):
        svc = _service()
        event = {
            "investigationDecision": {"trigger": True},
            "investigationOutcome": {"impact": "confirmed"},
        }
        result = svc.summarize_outcome_step(event)
        assert result["investigationLink"] is None


class TestHandlerDispatch:
    def test_unknown_step_returns_error(self):
        result = handler({"step": "NOT_A_REAL_STEP"}, None)
        assert "error" in result

    @patch("src.devops_agent.workflow_handler._service")
    def test_dispatches_resolve_agent_spaces_plural(self, mock_service):
        """RESOLVE_AGENT_SPACES (plural, task 11) must route to
        resolve_agent_spaces_step -- distinct from RESOLVE_AGENT_SPACE
        (singular) which routes to resolve_agent_space_step."""
        mock_service.resolve_agent_spaces_step.return_value = {"agentSpaceGroups": []}
        result = handler({"step": "RESOLVE_AGENT_SPACES"}, None)
        assert result == {"agentSpaceGroups": []}
        mock_service.resolve_agent_spaces_step.assert_called_once()
        mock_service.resolve_agent_space_step.assert_not_called()
