# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Data retrieval tool: readiness assessment tracking.

Reads/writes the ReadinessAssessments table — this agent's per-(event,
account) record of whether a readiness assessment has already been
requested (R12.3: "no assessment exists for that (event, account)";
"a grown affected set MAY [trigger for the newly-added accounts]").

Keyed by (eventArn, accountId) rather than the incident gate's
(agentSpaceId, eventArn) ActiveInvestigations table, because R12.3's
tracking unit is per-account, not per-Agent-Space — see design.md §4.

Never raises. decide_readiness() (a precision function) interprets the
structured data this module returns.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

import boto3
from boto3.dynamodb.conditions import Key

from src import config

logger = logging.getLogger(__name__)


def has_prior_assessment(event_arn: str) -> dict:
    """Returns which accounts already have a readiness assessment for this event.

    Args:
        event_arn: The AWS Health event ARN.

    Returns:
        {"assessed_accounts": list[str]}. Returns an empty list (fail open —
        assume nothing assessed yet) on a read error, since the monthly cap
        remains the backstop against runaway re-triggering even if this
        check is temporarily unavailable.
    """
    table_name = config.READINESS_ASSESSMENTS_TABLE_NAME
    if not table_name:
        return {"assessed_accounts": []}

    try:
        dynamodb = boto3.resource("dynamodb", region_name=config.AWS_REGION)
        table = dynamodb.Table(table_name)
        response = table.query(
            KeyConditionExpression=Key("eventArn").eq(event_arn)
        )
        items = response.get("Items", [])
        return {"assessed_accounts": [item["accountId"] for item in items if "accountId" in item]}
    except Exception as exc:
        logger.warning(
            json.dumps(
                {
                    "message": "has_prior_assessment failed, failing open (no prior assessment assumed)",
                    "event_arn": event_arn,
                    "error": str(exc),
                }
            )
        )
        return {"assessed_accounts": []}


def record_assessment(
    event_arn: str,
    account_id: str,
    agent_space_id: str,
    incident_id: str,
) -> None:
    """Records that a readiness assessment was requested for (event, account).

    Called immediately after a successful readiness webhook send, once per
    account in decide_readiness()'s accounts_to_assess list. No TTL — this
    is a durable record for the lifetime of the ticket (design.md §4), not
    a short-lived in-flight marker.
    """
    table_name = config.READINESS_ASSESSMENTS_TABLE_NAME
    if not table_name:
        return

    try:
        dynamodb = boto3.resource("dynamodb", region_name=config.AWS_REGION)
        table = dynamodb.Table(table_name)
        table.put_item(
            Item={
                "eventArn": event_arn,
                "accountId": account_id,
                "agentSpaceId": agent_space_id,
                "incidentId": incident_id,
                "assessedAt": datetime.now(timezone.utc).isoformat(),
                "status": "triggered",
            }
        )
    except Exception as exc:
        logger.warning(
            json.dumps(
                {
                    "message": "record_assessment failed",
                    "event_arn": event_arn,
                    "account_id": account_id,
                    "error": str(exc),
                }
            )
        )
