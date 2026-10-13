# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Unit tests for src.sinks.teams_sink.TeamsSink."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest
import requests

from src.sinks.teams_sink import TeamsSink

SECRET_ARN = "arn:aws:secretsmanager:us-east-1:123456789012:secret:teams-webhook"  # nosec B105 -- placeholder ARN fixture, not a credential
WEBHOOK_URL = "https://outlook.office.com/webhook/xxx"


def _sample_payload(**overrides) -> dict:
    base = {
        "eventArn": "arn:test",
        "service": "RDS",
        "eventTypeCode": "AWS_RDS_TEST",
        "classification": "COST_IMPLICATION",
        "urgency": "medium",
        "deadline": None,
        "classificationReason": "Extended support pricing begins.",
    }
    base.update(overrides)
    return base


def _make_sink(post_side_effect=None):
    secrets = MagicMock()
    secrets.get_secret_value.return_value = {"SecretString": json.dumps({"webhookUrl": WEBHOOK_URL})}
    http = MagicMock()
    if post_side_effect:
        http.post.side_effect = post_side_effect
    else:
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        http.post.return_value = resp
    sink = TeamsSink(secrets_client=secrets, http_session=http, secret_arn=SECRET_ARN)
    return sink, secrets, http


class TestUpsert:
    def test_posts_card_successfully(self):
        sink, secrets, http = _make_sink()
        result = sink.upsert(_sample_payload(), None)
        assert result["status"] == "sent"
        http.post.assert_called_once()

    def test_card_includes_classification(self):
        sink, secrets, http = _make_sink()
        sink.upsert(_sample_payload(), None)
        call_kwargs = http.post.call_args[1]
        assert "COST_IMPLICATION" in call_kwargs["json"]["title"]


class TestClose:
    def test_close_posts_resolved_card(self):
        sink, secrets, http = _make_sink()
        result = sink.close({"payload": _sample_payload()})
        assert result["status"] == "closed"
        call_kwargs = http.post.call_args[1]
        assert "Resolved" in call_kwargs["json"]["title"]


class TestNoSecretConfigured:
    def test_upsert_skipped_without_secret_arn(self):
        sink = TeamsSink(secret_arn="")  # nosec B106 -- deliberately empty to test the skip path
        result = sink.upsert(_sample_payload(), None)
        assert result["status"] == "skipped"

    def test_close_skipped_without_secret_arn(self):
        sink = TeamsSink(secret_arn="")  # nosec B106 -- deliberately empty to test the skip path
        result = sink.close({})
        assert result["status"] == "skipped"


class TestFailureHandling:
    def test_webhook_exception_returns_failed(self):
        sink, secrets, http = _make_sink(post_side_effect=Exception("timeout"))
        result = sink.upsert(_sample_payload(), None)
        assert result["status"] == "failed"

    def test_secrets_failure_returns_failed(self):
        secrets = MagicMock()
        secrets.get_secret_value.side_effect = Exception("denied")
        sink = TeamsSink(secrets_client=secrets, secret_arn=SECRET_ARN)
        result = sink.upsert(_sample_payload(), None)
        assert result["status"] == "failed"


class TestNoSecretsInLogs:
    """PCSR blocker 4 / ID2: an HTTP error must never leak the webhook URL —
    the incoming-webhook URL is itself the credential."""

    def _make_sink_with_http_error(self, status_code=404, reason="Not Found"):
        secrets = MagicMock()
        secrets.get_secret_value.return_value = {"SecretString": json.dumps({"webhookUrl": WEBHOOK_URL})}
        http = MagicMock()
        resp = MagicMock()
        resp.status_code = status_code
        resp.reason = reason
        # Mirror requests' real behavior: raise_for_status() embeds the URL
        # in its own exception message ("... for url: <url>").
        resp.raise_for_status.side_effect = requests.exceptions.HTTPError(
            f"{status_code} Client Error: {reason} for url: {WEBHOOK_URL}", response=resp
        )
        http.post.return_value = resp
        return TeamsSink(secrets_client=secrets, http_session=http, secret_arn=SECRET_ARN), http

    def test_http_error_result_excludes_webhook_url(self):
        sink, http = self._make_sink_with_http_error()
        result = sink.upsert(_sample_payload(), None)
        assert result["status"] == "failed"
        assert WEBHOOK_URL not in result["error"]
        assert "404" in result["error"]
        assert "Not Found" in result["error"]

    def test_http_error_log_excludes_webhook_url(self, caplog):
        sink, http = self._make_sink_with_http_error(status_code=403, reason="Forbidden")
        with caplog.at_level("ERROR"):
            sink.upsert(_sample_payload(), None)
        log_text = caplog.text
        assert WEBHOOK_URL not in log_text
        assert "403" in log_text
        assert "Forbidden" in log_text

    def test_close_http_error_excludes_webhook_url(self, caplog):
        sink, http = self._make_sink_with_http_error(status_code=500, reason="Internal Server Error")
        with caplog.at_level("ERROR"):
            result = sink.close({"payload": _sample_payload()})
        assert WEBHOOK_URL not in result["error"]
        assert WEBHOOK_URL not in caplog.text

    def test_network_failure_excludes_webhook_url(self, caplog):
        """A connection-level failure (no response at all) must also not
        leak the URL — requests' own ConnectionError/Timeout messages embed
        the full request URL too."""
        secrets = MagicMock()
        secrets.get_secret_value.return_value = {"SecretString": json.dumps({"webhookUrl": WEBHOOK_URL})}
        http = MagicMock()
        http.post.side_effect = requests.exceptions.ConnectionError(
            f"HTTPSConnectionPool(host='outlook.office.com', port=443): Max retries exceeded "
            f"with url: {WEBHOOK_URL}"
        )
        sink = TeamsSink(secrets_client=secrets, http_session=http, secret_arn=SECRET_ARN)
        with caplog.at_level("ERROR"):
            result = sink.upsert(_sample_payload(), None)
        assert result["status"] == "failed"
        assert WEBHOOK_URL not in result["error"]
        assert WEBHOOK_URL not in caplog.text
        assert result["error"] == "ConnectionError"

    def test_validate_https_error_excludes_url(self):
        """A non-HTTPS webhook URL must not appear in the raised message
        either — the URL is a credential regardless of which check rejects it."""
        secrets = MagicMock()
        secrets.get_secret_value.return_value = {
            "SecretString": json.dumps({"webhookUrl": "http://outlook.office.com/webhook/SECRET"})
        }
        sink = TeamsSink(secrets_client=secrets, secret_arn=SECRET_ARN)
        result = sink.upsert(_sample_payload(), None)
        assert result["status"] == "failed"
        assert "SECRET" not in result["error"]
        assert "http://outlook.office.com" not in result["error"]
