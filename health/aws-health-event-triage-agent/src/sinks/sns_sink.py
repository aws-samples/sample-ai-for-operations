# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""SNS sink — publishes NotificationPayload v1 for the triage workflow.

Publishes on every create (first notification) and on every update
(subsequent event updates). Closed events publish a 'closed' status payload.

The TicketMap table records the SNS message ID so subsequent publishes
carry the 'updateOf' correlation field.

Phase 3: also carries impactSummary (from build_impact_inventory) and
costProjection (from project_cost) when present on the workflow's merged
record. Both are null for classes that skip Inventory/ProjectCost
(SERVICE_DISRUPTION, INFORMATIONAL, UNCLASSIFIED).

Environment variables (via src.config):
    SNS_TOPIC_ARN   — classification result SNS topic ARN
"""

from __future__ import annotations

import json
import logging

import boto3

from src import config
from src.sinks.base import Sink

logger = logging.getLogger(__name__)


def _build_payload(record: dict, update_of: str | None) -> dict:
    """Build a NotificationPayload v1 dict from a consolidated event record.

    Phase 2 extension: includes classification, urgency, deadline,
    disposition, and related fields when present on the record.
    """
    return {
        "version": "1",
        "eventArn": record.get("eventArn", ""),
        "service": record.get("service", ""),
        "eventTypeCode": record.get("eventTypeCode", ""),
        "eventTypeCategory": record.get("eventTypeCategory", ""),
        "statusCode": record.get("statusCode", ""),
        "lastUpdatedTime": record.get("lastUpdatedTime", ""),
        "region": record.get("region", ""),
        "updateOf": update_of,
        "affectedAccountCount": len(record.get("affectedAccounts", [])),
        # Phase 2 classification fields
        "classification": record.get("classification"),
        "classificationReason": record.get("classificationReason"),
        "urgency": record.get("urgency"),
        "deadline": record.get("deadline"),
        "deadline_basis": record.get("deadline_basis"),
        "disposition": record.get("disposition"),
        "precheck": record.get("precheck"),
        "verificationSteps": record.get("verificationSteps"),
        # Phase 3 fields
        "impactSummary": record.get("impactSummary"),
        "costProjection": record.get("costProjection"),
        # Phase 6+ field
        "assignedTeam": record.get("assignedTeam"),
    }


def _message_attributes(record: dict, is_update: bool) -> dict:
    """Build SNS message attributes for filtering.

    SNS rejects a String-type message attribute with an empty StringValue
    (ParameterValueInvalid) — confirmed via a real Publish call during a
    live deploy validation. 'eventArn' and 'updateType' are always
    non-empty by construction (eventArn is required upstream; updateType
    is a literal), so they stay unconditional. Every other field is only
    included when actually present and non-empty, matching the pattern
    already used for classification/urgency/disposition below.
    """
    attrs: dict = {
        "eventArn": {"DataType": "String", "StringValue": record.get("eventArn", "")},
        "updateType": {
            "DataType": "String",
            "StringValue": "update" if is_update else "create",
        },
    }
    if record.get("statusCode"):
        attrs["statusCode"] = {"DataType": "String", "StringValue": record["statusCode"]}
    if record.get("eventTypeCategory"):
        attrs["eventTypeCategory"] = {
            "DataType": "String",
            "StringValue": record["eventTypeCategory"],
        }
    # Phase 2: add classification and urgency when available
    if record.get("classification"):
        attrs["classification"] = {"DataType": "String", "StringValue": record["classification"]}
    if record.get("urgency"):
        attrs["urgency"] = {"DataType": "String", "StringValue": record["urgency"]}
    if record.get("disposition"):
        attrs["disposition"] = {"DataType": "String", "StringValue": record["disposition"]}
    return attrs


class SnsSink(Sink):
    """Publishes NotificationPayload v1 to the classification SNS topic."""

    def __init__(
        self,
        *,
        sns_client=None,
        dynamodb_client=None,
        topic_arn: str = "",
        ticket_map_table_name: str = "",
    ):
        self._sns = sns_client or boto3.client("sns", region_name=config.AWS_REGION)
        self._ddb = dynamodb_client or boto3.client("dynamodb", region_name=config.AWS_REGION)
        self._topic_arn = topic_arn or config.SNS_TOPIC_ARN
        self._ticket_map_table = ticket_map_table_name or "health-triage-ticket-map"

    def publish(self, record: dict) -> dict:
        """Publish a NotificationPayload v1 for the given consolidated record.

        Looks up the previous SNS message ID from TicketMap (if any) to set
        the 'updateOf' correlation field. Saves the new message ID back to
        TicketMap so subsequent updates can chain.

        Args:
            record: The consolidated event record from DynamoDB.

        Returns:
            Dict with 'status', 'message_id', and 'update_of'.
        """
        if not self._topic_arn:
            logger.warning("SNS_TOPIC_ARN not configured — skipping notification")
            return {"status": "skipped", "reason": "SNS_TOPIC_ARN not configured"}

        event_arn = record.get("eventArn", "")

        # Check TicketMap for prior message ID
        update_of = self._get_prior_message_id(event_arn)
        is_update = update_of is not None

        payload = _build_payload(record, update_of)
        attributes = _message_attributes(record, is_update)

        try:
            region = self._topic_arn.split(":")[3]
            client = boto3.client("sns", region_name=region)
            resp = client.publish(
                TopicArn=self._topic_arn,
                Message=json.dumps(payload),
                Subject=f"AWS Health Triage: {event_arn[:80]}",
                MessageAttributes=attributes,
            )
            message_id = resp.get("MessageId", "")
        except Exception as exc:
            logger.error(
                json.dumps({
                    "message": "Failed to publish to SNS",
                    "event_arn": event_arn,
                    "error": str(exc),
                })
            )
            return {"status": "failed", "error": str(exc)}

        # Update TicketMap with new message ID
        self._save_message_id(event_arn, message_id)

        logger.info(
            json.dumps({
                "message": "NotificationPayload v1 published",
                "event_arn": event_arn,
                "message_id": message_id,
                "update_type": "update" if is_update else "create",
            })
        )
        return {
            "status": "sent",
            "message_id": message_id,
            "update_of": update_of,
        }

    # -----------------------------------------------------------------------
    # Phase 5: Sink interface adapter (wraps publish() without changing it)
    # -----------------------------------------------------------------------

    def upsert(self, payload: dict, ticket_ref: dict | None) -> dict:
        """Adapter for the common Sink interface — delegates to publish().

        SNS has no update-in-place ticket concept; every upsert() call
        publishes a new message, correlated to the prior one via 'updateOf'
        (handled internally by publish() through TicketMap).
        """
        result = self.publish(payload)
        return {
            **result,
            "message_id": result.get("message_id"),
        }

    def close(self, ticket_ref: dict) -> dict:
        """Publish a final 'closed' notification. SNS has no ticket to close —
        the caller is expected to have already set statusCode/disposition
        appropriately on the payload passed to a subsequent upsert() call.
        This method exists only for Sink interface conformance and is a
        no-op that reports success, since SNS notifications are stateless.
        """
        return {"status": "skipped", "reason": "SNS has no stateful ticket to close"}

    def _get_prior_message_id(self, event_arn: str) -> str | None:
        try:
            resp = self._ddb.get_item(
                TableName=self._ticket_map_table,
                Key={"eventArn": {"S": event_arn}},
                ConsistentRead=True,
            )
            item = resp.get("Item", {})
            msg_id = item.get("snsMessageId", {}).get("S")
            return msg_id if msg_id else None
        except Exception as exc:
            logger.warning(
                json.dumps({
                    "message": "Failed to read TicketMap — treating as first notification",
                    "event_arn": event_arn,
                    "error": str(exc),
                })
            )
            return None

    def _save_message_id(self, event_arn: str, message_id: str) -> None:
        try:
            self._ddb.put_item(
                TableName=self._ticket_map_table,
                Item={
                    "eventArn": {"S": event_arn},
                    "snsMessageId": {"S": message_id},
                },
            )
        except Exception as exc:
            logger.warning(
                json.dumps({
                    "message": "Failed to update TicketMap",
                    "event_arn": event_arn,
                    "error": str(exc),
                })
            )
