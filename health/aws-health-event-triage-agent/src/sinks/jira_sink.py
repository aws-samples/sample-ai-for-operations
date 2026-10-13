# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""JiraSink — creates and updates Jira tickets for TICKET-disposition events.

Creates exactly one ticket per eventArn (deduplication via the caller-provided
ticket_ref from TicketMap), updates it in place on subsequent upsert() calls,
and transitions it to a closed/resolved status on close().

Credentials (API token) are read from AWS Secrets Manager by ARN reference —
never hardcoded, never logged. All outbound HTTP calls validate the URL
scheme is https:// before calling (Bandit B310 mitigation).

This is a data-retrieval (external call) tool — pure orchestration, no
reasoning. It never calls the LLM.
"""

from __future__ import annotations

import json
import logging

import boto3
import requests

from src import config
from src.sinks.base import Sink

logger = logging.getLogger(__name__)

_PRIORITY_MAP = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}


def _validate_https(url: str) -> None:
    """Raise ValueError if the URL does not use https:// (Bandit B310)."""
    if not url.startswith("https://"):
        raise ValueError(f"Refusing non-HTTPS URL: {url}")


class JiraSink(Sink):
    """Creates and updates Jira tickets via the Jira REST API."""

    def __init__(
        self,
        *,
        base_url: str = "",
        secrets_client=None,
        http_session=None,
        secret_arn: str = "",
        default_project: str = "",
    ):
        self._base_url = base_url or config.JIRA_BASE_URL
        self._secrets = secrets_client or boto3.client("secretsmanager", region_name=config.AWS_REGION)
        self._http = http_session or requests
        self._secret_arn = secret_arn or config.JIRA_SECRET_ARN
        self._default_project = default_project or config.JIRA_DEFAULT_PROJECT
        self._credentials: dict | None = None

    def _get_credentials(self) -> dict:
        """Fetch and cache the Jira API credentials from Secrets Manager."""
        if self._credentials is not None:
            return self._credentials
        if not self._secret_arn:
            raise ValueError("JIRA_SECRET_ARN not configured")
        resp = self._secrets.get_secret_value(SecretId=self._secret_arn)
        self._credentials = json.loads(resp["SecretString"])
        return self._credentials

    def upsert(self, payload: dict, ticket_ref: dict | None) -> dict:
        """Create a new Jira ticket, or update the existing one for this eventArn.

        Args:
            payload: NotificationPayload v1 dict.
            ticket_ref: {"ticket_id": ..., "url": ...} from a prior upsert(),
                or None to create a new ticket.

        Returns:
            Dict with ticket_id, url, status ("created"|"updated"|"failed").
        """
        if not self._base_url or not self._secret_arn:
            return {"status": "skipped", "reason": "JIRA_BASE_URL or JIRA_SECRET_ARN not configured"}

        try:
            _validate_https(self._base_url)
            creds = self._get_credentials()
        except Exception as exc:
            logger.error("JiraSink configuration error: %s", exc)
            return {"status": "failed", "error": str(exc)}

        if ticket_ref and ticket_ref.get("ticket_id"):
            return self._update_ticket(ticket_ref["ticket_id"], payload, creds)
        return self._create_ticket(payload, creds)

    def _create_ticket(self, payload: dict, creds: dict) -> dict:
        summary = f"[{payload.get('service', 'unknown')}] {payload.get('eventTypeCode', 'unknown')} — action required"
        description = self._build_description(payload)
        priority = _PRIORITY_MAP.get(payload.get("urgency", "low"), "Low")

        try:
            url = f"{self._base_url}/rest/api/2/issue"
            _validate_https(url)
            resp = self._http.post(
                url,
                auth=(creds.get("email", ""), creds.get("apiToken", "")),
                json={
                    "fields": {
                        "project": {"key": self._default_project},
                        "summary": summary,
                        "description": description,
                        "issuetype": {"name": "Task"},
                        "priority": {"name": priority},
                        "labels": ["health-triage-auto-created"],
                    }
                },
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
            ticket_id = data.get("key", "")
            ticket_url = f"{self._base_url}/browse/{ticket_id}"
            logger.info("Created Jira ticket %s for event %s", ticket_id, payload.get("eventArn"))
            return {"ticket_id": ticket_id, "url": ticket_url, "status": "created"}
        except Exception as exc:
            logger.error("Jira ticket creation failed: %s", exc)
            return {"status": "failed", "error": str(exc)}

    def _update_ticket(self, ticket_id: str, payload: dict, creds: dict) -> dict:
        description = self._build_description(payload)
        try:
            url = f"{self._base_url}/rest/api/2/issue/{ticket_id}"
            _validate_https(url)
            resp = self._http.put(
                url,
                auth=(creds.get("email", ""), creds.get("apiToken", "")),
                json={"fields": {"description": description}},
                timeout=30,
            )
            resp.raise_for_status()
            ticket_url = f"{self._base_url}/browse/{ticket_id}"
            logger.info("Updated Jira ticket %s for event %s", ticket_id, payload.get("eventArn"))
            return {"ticket_id": ticket_id, "url": ticket_url, "status": "updated"}
        except Exception as exc:
            logger.error("Jira ticket update failed for %s: %s", ticket_id, exc)
            return {"ticket_id": ticket_id, "status": "failed", "error": str(exc)}

    def close(self, ticket_ref: dict) -> dict:
        """Transition the Jira ticket to a resolved status."""
        ticket_id = ticket_ref.get("ticket_id", "")
        if not ticket_id:
            return {"status": "skipped", "reason": "No ticket_id to close"}

        try:
            creds = self._get_credentials()
            url = f"{self._base_url}/rest/api/2/issue/{ticket_id}/transitions"
            _validate_https(url)
            resp = self._http.post(
                url,
                auth=(creds.get("email", ""), creds.get("apiToken", "")),
                json={"transition": {"id": config.JIRA_RESOLVED_TRANSITION_ID}},
                timeout=30,
            )
            resp.raise_for_status()
            logger.info("Closed Jira ticket %s", ticket_id)
            return {"status": "closed", "ticket_id": ticket_id}
        except Exception as exc:
            logger.error("Jira ticket close failed for %s: %s", ticket_id, exc)
            return {"status": "failed", "ticket_id": ticket_id, "error": str(exc)}

    @staticmethod
    def _build_description(payload: dict) -> str:
        lines = [
            f"Event ARN: {payload.get('eventArn', '')}",
            f"Classification: {payload.get('classification', 'unknown')}",
            f"Urgency: {payload.get('urgency', 'unknown')}",
            f"Deadline: {payload.get('deadline') or 'none'}",
            f"Reason: {payload.get('classificationReason', '')}",
            "",
            f"Affected accounts: {payload.get('affectedAccountCount', 0)}",
        ]
        impact = payload.get("impactSummary")
        if impact:
            lines.append(f"Impact status: {impact.get('impact_status', 'unknown')}")
        cost = payload.get("costProjection")
        if cost and not cost.get("unknown"):
            lines.append(f"Monthly cost increment: ${cost.get('monthly_increment', 0):,.2f}")
        return "\n".join(lines)
