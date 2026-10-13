# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Data retrieval tool: monthly investigation counters (R12.8).

Reads and conditionally increments the AgentSpaceCounters table — an
agent-internal resource (per iam-permission-boundary, writes are scoped to
this table only, tagged agent-managed:true). Pure AWS I/O with graceful
fallback; decide_investigation() (a precision function) interprets the
counts, so read failures here fail closed (returns a full-looking counter,
i.e. cap already reached) rather than fail open, since an inability to read
the budget should not silently allow unlimited triggering.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

from src import config

logger = logging.getLogger(__name__)


def _month_key(now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    return now.strftime("%Y-%m")


def get_incident_counter(agent_space_id: str, cap: int) -> dict:
    """Reads the current month's incident-investigation count for an Agent Space.

    Args:
        agent_space_id: The target Agent Space ID.
        cap: The registry entry's incidentCapPerMonth, returned alongside
            the count so decide_investigation() can compare them without a
            second lookup.

    Returns:
        {"incident_count_this_month": int, "cap": int}. On a read failure,
        returns count == cap (fail closed — see module docstring).
    """
    table_name = config.AGENT_SPACE_COUNTERS_TABLE_NAME
    if not table_name:
        return {"incident_count_this_month": 0, "cap": cap}

    try:
        dynamodb = boto3.resource("dynamodb", region_name=config.AWS_REGION)
        table = dynamodb.Table(table_name)
        key = f"{agent_space_id}#{_month_key()}"
        response = table.get_item(Key={"counterKey": key})
        item = response.get("Item")
        count = int(item.get("incidentCount", 0)) if item else 0
        return {"incident_count_this_month": count, "cap": cap}
    except Exception as exc:
        logger.warning(
            json.dumps(
                {
                    "message": "get_incident_counter failed, failing closed (cap treated as reached)",
                    "agent_space_id": agent_space_id,
                    "error": str(exc),
                }
            )
        )
        return {"incident_count_this_month": cap, "cap": cap}


def increment_incident_counter(agent_space_id: str, cap: int) -> dict:
    """Conditionally increments the current month's incident counter.

    Uses a ConditionExpression so concurrent triggers cannot race past the
    cap (R12.8 — "never trigger more than one investigation per eventArn
    per Agent Space" combined with the monthly cap). Callers should call
    this only after decide_investigation() has already returned trigger:
    True and the webhook send has succeeded, to avoid burning budget on a
    failed trigger attempt.

    Returns:
        {"incremented": bool, "incident_count_this_month": int}.
        incremented is False if the condition failed (cap reached between
        the read and the write) or if the table is not configured.
    """
    table_name = config.AGENT_SPACE_COUNTERS_TABLE_NAME
    if not table_name:
        return {"incremented": False, "incident_count_this_month": 0}

    try:
        dynamodb = boto3.resource("dynamodb", region_name=config.AWS_REGION)
        table = dynamodb.Table(table_name)
        key = f"{agent_space_id}#{_month_key()}"
        try:
            response = table.update_item(
                Key={"counterKey": key},
                UpdateExpression="SET incidentCount = if_not_exists(incidentCount, :zero) + :incr",
                ConditionExpression="attribute_not_exists(incidentCount) OR incidentCount < :cap",
                ExpressionAttributeValues={":zero": 0, ":incr": 1, ":cap": cap},
                ReturnValues="UPDATED_NEW",
            )
            new_count = int(response["Attributes"]["incidentCount"])
            return {"incremented": True, "incident_count_this_month": new_count}
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                return {"incremented": False, "incident_count_this_month": cap}
            raise
    except Exception as exc:
        logger.warning(
            json.dumps(
                {
                    "message": "increment_incident_counter failed",
                    "agent_space_id": agent_space_id,
                    "error": str(exc),
                }
            )
        )
        return {"incremented": False, "incident_count_this_month": 0}


# ---------------------------------------------------------------------------
# Phase 5b: readiness assessment counters (R12.8's "separate monthly cap"
# for readiness assessments). Same AgentSpaceCounters table, partition key
# shape, and conditional-update pattern as the incident counters above,
# but a distinct 'readinessCount' attribute so the two budgets never share
# state.
# ---------------------------------------------------------------------------


def get_readiness_counter(agent_space_id: str, cap: int) -> dict:
    """Reads the current month's readiness-assessment count for an Agent Space.

    Args:
        agent_space_id: The target Agent Space ID.
        cap: The registry entry's readinessCapPerMonth.

    Returns:
        {"readiness_count_this_month": int, "cap": int}. On a read failure,
        returns count == cap (fail closed — see module docstring).
    """
    table_name = config.AGENT_SPACE_COUNTERS_TABLE_NAME
    if not table_name:
        return {"readiness_count_this_month": 0, "cap": cap}

    try:
        dynamodb = boto3.resource("dynamodb", region_name=config.AWS_REGION)
        table = dynamodb.Table(table_name)
        key = f"{agent_space_id}#{_month_key()}"
        response = table.get_item(Key={"counterKey": key})
        item = response.get("Item")
        count = int(item.get("readinessCount", 0)) if item else 0
        return {"readiness_count_this_month": count, "cap": cap}
    except Exception as exc:
        logger.warning(
            json.dumps(
                {
                    "message": "get_readiness_counter failed, failing closed (cap treated as reached)",
                    "agent_space_id": agent_space_id,
                    "error": str(exc),
                }
            )
        )
        return {"readiness_count_this_month": cap, "cap": cap}
