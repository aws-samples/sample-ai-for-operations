# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Ticket Creator tool.

Creates Jira tickets via AHA's Jira integration for actionable
BREAKING_CHANGE notifications.  Deduplicates by linking related
notifications to a single ticket per health event.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

from strands import tool

logger = logging.getLogger(__name__)

# In-memory deduplication ledger: event_key → ticket dict.
# A production implementation would persist this (DynamoDB, etc.).
_ticket_ledger: dict[str, dict] = {}

# Pluggable AHA Jira integration callable.
# Default is None — must be set (or mocked) before use.
# Signature: (payload: dict) -> dict  with keys ticket_id, url
aha_jira_create: Callable[[dict], dict] | None = None

# Team assignment mapping: service → team name.
TEAM_ASSIGNMENT: dict[str, str] = {
    "EKS": "Platform-Kubernetes",
    "RDS": "Platform-Database",
    "CASSANDRA": "Platform-Database",
    "LAMBDA": "Platform-Serverless",
    "EC2": "Platform-Compute",
    "ELASTICACHE": "Platform-Database",
    "OPENSEARCH": "Platform-Search",
}

DEFAULT_TEAM = "Platform-Operations"


def _event_key(notification: dict) -> str:
    """Derive a deduplication key from the notification."""
    event_type = notification.get("eventTypeCode", "")
    service = notification.get("service", "")
    return f"{event_type}::{service}" if event_type and service else notification.get("arn", "unknown")


def _build_description(notification: dict, impact_summary: dict) -> str:
    """Build a Jira ticket description from notification and impact data."""
    service = notification.get("service", "unknown")
    event_type = notification.get("eventTypeCode", "unknown")
    desc = notification.get("eventDescription", "")

    accounts = impact_summary.get("affected_accounts", [])
    account_lines = []
    for acct in accounts:
        acct_id = acct.get("account_id", "unknown")
        env = acct.get("environment_type", "unknown")
        action = acct.get("required_action", "Review required")
        resources = acct.get("affected_resources", [])
        res_str = ", ".join(resources) if resources else "none listed"
        account_lines.append(
            f"- {acct_id} ({env}): resources=[{res_str}], action={action}"
        )

    parts = [
        f"Service: {service}",
        f"Event: {event_type}",
        f"Description: {desc}",
        "",
        "Affected Accounts:",
        *account_lines,
        "",
        f"Risk Level: {impact_summary.get('risk_level', 'unknown')}",
        f"Summary: {impact_summary.get('summary', '')}",
    ]
    return "\n".join(parts)


@tool
def create_jira_ticket(notification: dict, impact_summary: dict) -> dict:
    """Create a Jira ticket for an actionable notification via AHA's Jira integration.

    Includes cross-account impact summary in the ticket description.
    Links related notifications to a single ticket (deduplication).
    Returns ticket details or failure information.

    Args:
        notification: A notification dict with at least ``arn``, ``service``,
            ``eventTypeCode``, ``eventDescription``.
        impact_summary: An ImpactAnalysis dict from ``analyze_impact``.

    Returns:
        Dict with ``ticket_id``, ``url``, ``status`` on success, or
        ``status: "failed"`` with ``error`` on failure.
    """
    key = _event_key(notification)

    # Deduplication: return existing ticket if one was already created
    if key in _ticket_ledger:
        existing = _ticket_ledger[key]
        logger.info("Ticket already exists for event %s: %s", key, existing["ticket_id"])
        return {**existing, "deduplicated": True}

    service = notification.get("service", "unknown")
    team = TEAM_ASSIGNMENT.get(service, DEFAULT_TEAM)
    description = _build_description(notification, impact_summary)
    event_type = notification.get("eventTypeCode", "unknown")

    payload = {
        "summary": f"[{service}] {event_type} — action required",
        "description": description,
        "assignee_team": team,
        "priority": "High" if impact_summary.get("risk_level") == "high" else "Medium",
        "labels": ["health-triage-auto-created", service.lower()],
    }

    if aha_jira_create is None:
        error_msg = "AHA Jira integration not configured"
        logger.error(error_msg)
        return {"status": "failed", "error": error_msg}

    try:
        result = aha_jira_create(payload)
        ticket = {
            "ticket_id": result["ticket_id"],
            "url": result["url"],
            "status": "created",
            "team": team,
        }
        _ticket_ledger[key] = ticket
        logger.info("Created Jira ticket %s for event %s", ticket["ticket_id"], key)
        return ticket
    except Exception as exc:
        error_msg = f"AHA Jira integration failed: {exc}"
        logger.error(error_msg)
        return {"status": "failed", "error": error_msg}
