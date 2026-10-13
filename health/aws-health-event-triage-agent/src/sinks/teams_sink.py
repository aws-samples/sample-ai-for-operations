# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""TeamsSink — posts notifications to Microsoft Teams for TICKET-disposition events.

Uses a Teams incoming webhook (connector URL sourced from AWS Secrets Manager
by ARN). Like SlackSink, Teams webhooks don't support message editing, so
upsert() and close() each post a new card — close() posts a clearly marked
"resolved" card.

Data-retrieval (external call) tool — no reasoning, no model call.
"""

from __future__ import annotations

import json
import logging

import boto3
import requests

from src import config
from src.sinks.base import Sink

logger = logging.getLogger(__name__)


def _validate_https(url: str) -> None:
    # Message deliberately omits the URL itself — for an incoming webhook,
    # the URL IS the credential (PCSR blocker 4 / ID2), so it must not
    # appear in any exception message that a caller might log.
    if not url.startswith("https://"):
        raise ValueError("Refusing non-HTTPS webhook URL")


def _format_card(payload: dict, closed: bool = False) -> dict:
    title = "✅ Resolved" if closed else f"[{payload.get('classification', 'UNKNOWN')}]"
    text = (
        f"{payload.get('service', 'unknown')} — {payload.get('eventTypeCode', 'unknown')}\n\n"
        f"Urgency: {payload.get('urgency', 'unknown')} | Deadline: {payload.get('deadline') or 'none'}\n\n"
        f"{payload.get('classificationReason', '')}"
    )
    return {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "title": title,
        "text": text,
    }


class TeamsSink(Sink):
    """Posts notifications to Microsoft Teams via a webhook URL from Secrets Manager."""

    def __init__(self, *, secrets_client=None, http_session=None, secret_arn: str = ""):
        self._secrets = secrets_client or boto3.client("secretsmanager", region_name=config.AWS_REGION)
        self._http = http_session or requests
        self._secret_arn = secret_arn or config.TEAMS_SECRET_ARN
        self._webhook_url: str | None = None

    def _get_webhook_url(self) -> str:
        if self._webhook_url is not None:
            return self._webhook_url
        if not self._secret_arn:
            raise ValueError("TEAMS_SECRET_ARN not configured")
        resp = self._secrets.get_secret_value(SecretId=self._secret_arn)
        secret = json.loads(resp["SecretString"])
        self._webhook_url = secret.get("webhookUrl", "")
        return self._webhook_url

    def upsert(self, payload: dict, ticket_ref: dict | None) -> dict:
        if not self._secret_arn:
            return {"status": "skipped", "reason": "TEAMS_SECRET_ARN not configured"}

        try:
            webhook_url = self._get_webhook_url()
            _validate_https(webhook_url)
        except Exception as exc:
            logger.error("TeamsSink configuration error: %s", exc)
            return {"status": "failed", "error": str(exc)}

        card = _format_card(payload)
        resp, exc_status = self._post(webhook_url, card)
        if exc_status is not None:
            logger.error("Teams webhook failed: %s", exc_status)
            return {"status": "failed", "error": exc_status}
        logger.info("Teams notification posted for event %s", payload.get("eventArn"))
        return {"status": "sent", "channel": "teams"}

    def close(self, ticket_ref: dict) -> dict:
        if not self._secret_arn:
            return {"status": "skipped", "reason": "TEAMS_SECRET_ARN not configured"}
        try:
            webhook_url = self._get_webhook_url()
            _validate_https(webhook_url)
        except Exception as exc:
            logger.error("TeamsSink configuration error: %s", exc)
            return {"status": "failed", "error": str(exc)}

        card = _format_card(ticket_ref.get("payload", {}), closed=True)
        resp, exc_status = self._post(webhook_url, card)
        if exc_status is not None:
            logger.error("Teams close notification failed: %s", exc_status)
            return {"status": "failed", "error": exc_status}
        return {"status": "closed", "channel": "teams"}

    def _post(self, webhook_url: str, body: dict) -> tuple[object | None, str | None]:
        """POST to the webhook and return (response, None) on success or
        (None, status_string) on failure.

        The webhook URL is a credential (PCSR blocker 4 / ID2 "no secrets in
        logs") — `requests`' own exception messages embed the full request
        URL (`raise_for_status()`'s message is literally "... for url:
        <url>"; connection/timeout errors embed it too), so this method
        never logs or returns `str(exc)`. On an HTTP error response it
        returns only `status_code`/`reason`; on a network-level failure
        (timeout, DNS, connection refused — no response received) it
        returns only the exception's type name.
        """
        try:
            resp = self._http.post(webhook_url, json=body, timeout=15)
        except Exception as exc:
            return None, type(exc).__name__
        try:
            resp.raise_for_status()
        except requests.exceptions.HTTPError:
            return None, f"{resp.status_code} {resp.reason}"
        return resp, None
