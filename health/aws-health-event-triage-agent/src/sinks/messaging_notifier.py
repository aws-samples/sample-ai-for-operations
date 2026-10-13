# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Messaging Notifier tools.

Sends consolidated impact summaries to Microsoft Teams and Slack
via AHA's webhook integrations.
"""

from __future__ import annotations

import logging
from typing import Callable

from strands import tool

logger = logging.getLogger(__name__)

# Pluggable AHA webhook callables.  Set (or mock) before use.
# Signature: (payload: dict) -> dict
aha_teams_webhook: Callable[[dict], dict] | None = None
aha_slack_webhook: Callable[[dict], dict] | None = None

# Base URL for AWS Health console deep links.
AWS_HEALTH_CONSOLE_BASE = "https://health.aws.amazon.com/health/home#/event/"


def _build_message(summary: dict) -> dict:
    """Build a structured message payload from a classification summary.

    The payload includes classification, affected accounts, required actions,
    and actionable links (Health console + Jira ticket).
    """
    notifications = summary.get("notifications", [])

    if not notifications:
        return {
            "text": "AWS Health Notification Summary: No actionable notifications found. No action required.",
            "actionable": False,
        }

    lines: list[str] = ["AWS Health Notification Summary", ""]
    for notif in notifications:
        classification = notif.get("classification", "UNKNOWN")
        service = notif.get("affected_service", "unknown")
        reason = notif.get("reason", "")
        notif_id = notif.get("notification_id", "")

        lines.append(f"[{classification}] {service}")
        lines.append(f"  Reason: {reason}")

        # Affected accounts
        accounts = notif.get("affected_accounts", [])
        if accounts:
            acct_ids = [a.get("account_id", "?") for a in accounts]
            lines.append(f"  Affected accounts: {', '.join(acct_ids)}")

        # Required actions from impact analysis
        impact = notif.get("impact_analysis")
        if impact and impact.get("action_required"):
            lines.append(f"  Action required: {impact.get('summary', 'Yes')}")

        # AWS Health console link
        if notif_id:
            health_url = AWS_HEALTH_CONSOLE_BASE + notif_id
            lines.append(f"  AWS Health console: {health_url}")

        # Jira ticket link
        jira = notif.get("jira_ticket")
        if jira and jira.get("url"):
            lines.append(f"  Jira ticket: {jira['url']}")

        lines.append("")

    return {
        "text": "\n".join(lines),
        "actionable": True,
        "notification_count": len(notifications),
    }


@tool
def send_teams_notification(summary: dict) -> dict:
    """Send consolidated impact summary to Microsoft Teams via AHA's webhook.

    Includes classification, affected accounts, required actions, and
    actionable links to the AWS Health console and Jira ticket.

    Args:
        summary: The agent's full output dict containing ``notifications``.

    Returns:
        Dict with ``status`` ("sent" or "failed") and optional ``error``.
    """
    message = _build_message(summary)

    if aha_teams_webhook is None:
        error_msg = "AHA Teams webhook not configured"
        logger.error(error_msg)
        return {"status": "failed", "error": error_msg}

    try:
        aha_teams_webhook(message)
        logger.info("Teams notification sent successfully")
        return {"status": "sent", "channel": "teams"}
    except Exception as exc:
        error_msg = f"AHA Teams webhook failed: {exc}"
        logger.error(error_msg)
        return {"status": "failed", "error": error_msg}


@tool
def send_slack_notification(summary: dict) -> dict:
    """Send consolidated impact summary to Slack via AHA's webhook.

    Includes classification, affected accounts, required actions, and
    actionable links to the AWS Health console and Jira ticket.

    Args:
        summary: The agent's full output dict containing ``notifications``.

    Returns:
        Dict with ``status`` ("sent" or "failed") and optional ``error``.
    """
    message = _build_message(summary)

    if aha_slack_webhook is None:
        error_msg = "AHA Slack webhook not configured"
        logger.error(error_msg)
        return {"status": "failed", "error": error_msg}

    try:
        aha_slack_webhook(message)
        logger.info("Slack notification sent successfully")
        return {"status": "sent", "channel": "slack"}
    except Exception as exc:
        error_msg = f"AHA Slack webhook failed: {exc}"
        logger.error(error_msg)
        return {"status": "failed", "error": error_msg}
