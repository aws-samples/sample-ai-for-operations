# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Data retrieval tool: dedupe_check.

Reads this agent's own ActiveInvestigations record to answer "did I already
trigger an investigation for this (Agent Space, event)" — a `dedupe:
local_only` fallback (R12.5) for the ideal-but-unavailable "query the DevOps
Agent API for any active investigation across all triggers". No AWS
DevOps Agent "list active investigations" API was confirmed against the
canonical reference or public docs at Build time (design.md §12), so this
degrades to the agent's own record rather than guessing at that API.

Returns structured data only; decide_investigation() (a precision function)
interprets it. This keeps the gate testable without moto/DynamoDB.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone

import boto3

from src import config

logger = logging.getLogger(__name__)


def dedupe_check(
    agent_space_id: str,
    event_arn: str,
    window_minutes: int = 60,
) -> dict:
    """Checks whether an active investigation already covers this event.

    Args:
        agent_space_id: The target Agent Space ID.
        event_arn: The AWS Health event ARN.
        window_minutes: How recently a trigger for this (space, event) pair
            must have happened to still count as "active" (R12.5 default
            ±60 min; the registry entry's dedupeWindowMinutes overrides it).

    Returns:
        {"duplicate": bool, "existing_investigation_id": str | None}.
        Returns {"duplicate": False, ...} (fail-open on read errors) rather
        than raising — a dedupe-check failure should not block triage
        entirely; decide_investigation()'s cap check remains the backstop
        against runaway triggering.
    """
    table_name = config.ACTIVE_INVESTIGATIONS_TABLE_NAME
    if not table_name:
        return {"duplicate": False, "existing_investigation_id": None}

    try:
        dynamodb = boto3.resource("dynamodb", region_name=config.AWS_REGION)
        table = dynamodb.Table(table_name)
        response = table.get_item(
            Key={"agentSpaceId": agent_space_id, "eventArn": event_arn}
        )
        item = response.get("Item")
        if not item:
            return {"duplicate": False, "existing_investigation_id": None}

        triggered_at_raw = item.get("triggeredAt")
        if triggered_at_raw:
            triggered_at = datetime.fromisoformat(triggered_at_raw)
            if triggered_at.tzinfo is None:
                triggered_at = triggered_at.replace(tzinfo=timezone.utc)
            age = datetime.now(timezone.utc) - triggered_at
            if age > timedelta(minutes=window_minutes):
                return {"duplicate": False, "existing_investigation_id": None}

        return {
            "duplicate": True,
            "existing_investigation_id": item.get("investigationId"),
        }
    except Exception as exc:
        logger.warning(
            json.dumps(
                {
                    "message": "dedupe_check failed, failing open (no duplicate assumed)",
                    "agent_space_id": agent_space_id,
                    "event_arn": event_arn,
                    "error": str(exc),
                }
            )
        )
        return {"duplicate": False, "existing_investigation_id": None}


def record_active_investigation(
    agent_space_id: str,
    event_arn: str,
    investigation_id: str,
) -> None:
    """Records a newly-triggered investigation for future dedupe checks.

    Called immediately after a successful webhook send. TTL on the table
    (24h, per design §5) bounds how long a stale row can block re-triggers
    if the callback never arrives.
    """
    table_name = config.ACTIVE_INVESTIGATIONS_TABLE_NAME
    if not table_name:
        return

    try:
        dynamodb = boto3.resource("dynamodb", region_name=config.AWS_REGION)
        table = dynamodb.Table(table_name)
        now = datetime.now(timezone.utc)
        table.put_item(
            Item={
                "agentSpaceId": agent_space_id,
                "eventArn": event_arn,
                "investigationId": investigation_id,
                "triggeredAt": now.isoformat(),
                "ttl": int((now + timedelta(hours=24)).timestamp()),
            }
        )
    except Exception as exc:
        logger.warning(
            json.dumps(
                {
                    "message": "record_active_investigation failed",
                    "agent_space_id": agent_space_id,
                    "event_arn": event_arn,
                    "investigation_id": investigation_id,
                    "error": str(exc),
                }
            )
        )
