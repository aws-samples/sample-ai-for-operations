# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Unit tests for src.sinks.jira_sink.JiraSink."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from src.sinks.jira_sink import JiraSink

BASE_URL = "https://example.atlassian.net"
SECRET_ARN = "arn:aws:secretsmanager:us-east-1:123456789012:secret:jira-creds"  # nosec B105 -- placeholder ARN fixture, not a credential


def _sample_payload(**overrides) -> dict:
    base = {
        "eventArn": "arn:aws:health:us-east-1::event/EKS/TEST/001",
        "service": "EKS",
        "eventTypeCode": "AWS_EKS_PLANNED_LIFECYCLE_EVENT",
        "classification": "BREAKING_CHANGE",
        "urgency": "high",
        "deadline": "2026-09-01",
        "classificationReason": "Cluster will be auto-upgraded.",
        "affectedAccountCount": 1,
    }
    base.update(overrides)
    return base


def _make_sink(http_response=None, http_side_effect=None):
    secrets = MagicMock()
    secrets.get_secret_value.return_value = {
        "SecretString": json.dumps({"email": "bot@example.com", "apiToken": "tok"})
    }
    http = MagicMock()
    if http_side_effect:
        http.post.side_effect = http_side_effect
        http.put.side_effect = http_side_effect
    else:
        resp = http_response or MagicMock(json=lambda: {"key": "PLATOPS-123"})
        resp.raise_for_status = MagicMock()
        http.post.return_value = resp
        http.put.return_value = resp
    sink = JiraSink(
        base_url=BASE_URL,
        secrets_client=secrets,
        http_session=http,
        secret_arn=SECRET_ARN,
        default_project="PLATOPS",
    )
    return sink, secrets, http


class TestCreateTicket:
    def test_creates_new_ticket_when_no_ref(self):
        sink, secrets, http = _make_sink()
        result = sink.upsert(_sample_payload(), ticket_ref=None)
        assert result["status"] == "created"
        assert result["ticket_id"] == "PLATOPS-123"
        assert BASE_URL in result["url"]

    def test_calls_post_for_create(self):
        sink, secrets, http = _make_sink()
        sink.upsert(_sample_payload(), ticket_ref=None)
        http.post.assert_called_once()


class TestUpdateTicket:
    def test_updates_existing_ticket_when_ref_provided(self):
        sink, secrets, http = _make_sink()
        result = sink.upsert(_sample_payload(), ticket_ref={"ticket_id": "PLATOPS-123", "url": "x"})
        assert result["status"] == "updated"
        assert result["ticket_id"] == "PLATOPS-123"

    def test_calls_put_for_update(self):
        sink, secrets, http = _make_sink()
        sink.upsert(_sample_payload(), ticket_ref={"ticket_id": "PLATOPS-123", "url": "x"})
        http.put.assert_called_once()


class TestClose:
    def test_close_calls_transitions_endpoint(self):
        sink, secrets, http = _make_sink()
        result = sink.close({"ticket_id": "PLATOPS-123"})
        assert result["status"] == "closed"
        http.post.assert_called_once()
        assert "transitions" in http.post.call_args[0][0]

    def test_close_with_no_ticket_id_skipped(self):
        sink, secrets, http = _make_sink()
        result = sink.close({})
        assert result["status"] == "skipped"


class TestConfigurationErrors:
    def test_no_base_url_skips(self):
        sink = JiraSink(base_url="", secret_arn=SECRET_ARN)
        result = sink.upsert(_sample_payload(), None)
        assert result["status"] == "skipped"

    def test_no_secret_arn_skips(self):
        sink = JiraSink(base_url=BASE_URL, secret_arn="")  # nosec B106 -- deliberately empty to test the skip path
        result = sink.upsert(_sample_payload(), None)
        assert result["status"] == "skipped"

    def test_non_https_base_url_fails(self):
        secrets = MagicMock()
        secrets.get_secret_value.return_value = {
            "SecretString": json.dumps({"email": "a", "apiToken": "b"})
        }
        sink = JiraSink(base_url="http://insecure.example.com", secrets_client=secrets, secret_arn=SECRET_ARN)
        result = sink.upsert(_sample_payload(), None)
        assert result["status"] == "failed"


class TestFailureHandling:
    def test_http_exception_returns_failed(self):
        sink, secrets, http = _make_sink(http_side_effect=Exception("network error"))
        result = sink.upsert(_sample_payload(), None)
        assert result["status"] == "failed"

    def test_secrets_manager_failure_returns_failed(self):
        secrets = MagicMock()
        secrets.get_secret_value.side_effect = Exception("access denied")
        sink = JiraSink(base_url=BASE_URL, secrets_client=secrets, secret_arn=SECRET_ARN)
        result = sink.upsert(_sample_payload(), None)
        assert result["status"] == "failed"


class TestDescriptionContent:
    def test_description_includes_cost_when_present(self):
        sink, secrets, http = _make_sink()
        payload = _sample_payload(costProjection={"unknown": False, "monthly_increment": 365.0})
        sink.upsert(payload, None)
        call_kwargs = http.post.call_args[1]
        description = call_kwargs["json"]["fields"]["description"]
        assert "365" in description

    def test_description_includes_impact_status(self):
        sink, secrets, http = _make_sink()
        payload = _sample_payload(impactSummary={"impact_status": "confirmed"})
        sink.upsert(payload, None)
        call_kwargs = http.post.call_args[1]
        description = call_kwargs["json"]["fields"]["description"]
        assert "confirmed" in description
