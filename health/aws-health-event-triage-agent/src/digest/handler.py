# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Digest Lambda handler — scheduled entry point.

Triggered by an EventBridge Scheduler rule (default: daily cron). Flow:
  1. Read the DigestWatermark item (last run timestamp).
  2. Query ConsolidatedEvents (via the byDispositionUpdatedAt GSI) for
     disposition == DIGEST events updated since the watermark.
  3. format_digest(events, since=watermark) → text + JSON.
  4. Publish to the digest SNS topic.
  5. Advance the watermark to now.
  6. Write an AuditLog record listing every included event ARN (R6.6).

Never raises past the handler — a failure at any step is logged and the
watermark is NOT advanced, so the next scheduled run retries the same window
rather than silently skipping events.
"""

from __future__ import annotations

import json
import logging
import os
import time

import boto3

from src import config
from src.digest.format_digest import format_digest

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

_WATERMARK_KEY = "digest-watermark"


class DigestService:
    """Orchestrates one digest run. Injectable clients for testability."""

    def __init__(
        self,
        *,
        dynamodb_client=None,
        sns_client=None,
        consolidated_table_name: str = "",
        watermark_table_name: str = "",
        audit_log_table_name: str = "",
        digest_topic_arn: str = "",
    ):
        self._ddb = dynamodb_client or boto3.client("dynamodb", region_name=config.AWS_REGION)
        self._sns = sns_client or boto3.client("sns", region_name=config.AWS_REGION)
        self._consolidated_table = consolidated_table_name or config.CONSOLIDATED_TABLE_NAME
        self._watermark_table = watermark_table_name or config.DIGEST_WATERMARK_TABLE_NAME
        self._audit_log_table = audit_log_table_name or config.AUDIT_LOG_TABLE_NAME
        self._digest_topic_arn = digest_topic_arn or config.DIGEST_TOPIC_ARN

    def run(self) -> dict:
        """Execute one digest run. Returns a summary dict."""
        watermark = self._get_watermark()

        try:
            events = self._query_digest_events(since=watermark)
        except Exception as exc:
            logger.error(json.dumps({"message": "Failed to query digest events", "error": str(exc)}))
            return {"status": "error", "reason": f"query_failed: {exc}"}

        digest = format_digest(events, since=watermark)

        if digest["generated_at_event_count"] == 0:
            logger.info(json.dumps({"message": "No digest events — advancing watermark without publishing"}))
            self._advance_watermark()
            return {"status": "empty", "event_count": 0}

        publish_result = self._publish(digest)
        if publish_result.get("status") != "sent":
            # Do NOT advance the watermark on publish failure — retry next run.
            logger.error(json.dumps({"message": "Digest publish failed — watermark not advanced", "error": publish_result.get("error")}))
            return {"status": "publish_failed", "event_count": digest["generated_at_event_count"]}

        self._advance_watermark()
        self._write_audit(digest["included_event_arns"])

        logger.info(json.dumps({
            "message": "Digest published",
            "event_count": digest["generated_at_event_count"],
            "family_count": len(digest["families"]),
        }))
        return {
            "status": "sent",
            "event_count": digest["generated_at_event_count"],
            "included_event_arns": digest["included_event_arns"],
        }

    def _get_watermark(self) -> str | None:
        try:
            resp = self._ddb.get_item(
                TableName=self._watermark_table,
                Key={"pk": {"S": _WATERMARK_KEY}},
                ConsistentRead=True,
            )
            item = resp.get("Item", {})
            return item.get("timestamp", {}).get("S")
        except Exception as exc:
            logger.warning(json.dumps({"message": "Failed to read digest watermark — defaulting to None", "error": str(exc)}))
            return None

    def _advance_watermark(self) -> None:
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        try:
            self._ddb.put_item(
                TableName=self._watermark_table,
                Item={"pk": {"S": _WATERMARK_KEY}, "timestamp": {"S": now}},
            )
        except Exception as exc:
            logger.warning(json.dumps({"message": "Failed to advance digest watermark", "error": str(exc)}))

    def _query_digest_events(self, since: str | None) -> list[dict]:
        """Query ConsolidatedEvents for disposition=DIGEST since the watermark.

        Uses the byDispositionUpdatedAt GSI (master design §4). Returns an
        empty list if the query fails for a reason other than 'no results'.
        """
        try:
            query_kwargs: dict = {
                "TableName": self._consolidated_table,
                "IndexName": "byDispositionUpdatedAt",
                "KeyConditionExpression": "disposition = :d" + (" AND dispositionUpdatedAt > :s" if since else ""),
                "ExpressionAttributeValues": {
                    ":d": {"S": "DIGEST"},
                    **({":s": {"S": since}} if since else {}),
                },
            }
            resp = self._ddb.query(**query_kwargs)
            items = resp.get("Items", [])
            return [self._deserialize_event(item) for item in items]
        except Exception as exc:
            logger.warning(json.dumps({"message": "Digest query failed", "error": str(exc)}))
            raise

    @staticmethod
    def _deserialize_event(item: dict) -> dict:
        """Minimal DynamoDB deserializer for the digest query results."""
        result: dict = {}
        for k, v in item.items():
            if "S" in v:
                try:
                    result[k] = json.loads(v["S"])
                except (json.JSONDecodeError, TypeError):
                    result[k] = v["S"]
            elif "N" in v:
                result[k] = float(v["N"]) if "." in v["N"] else int(v["N"])
            elif "BOOL" in v:
                result[k] = v["BOOL"]
        return result

    def _publish(self, digest: dict) -> dict:
        if not self._digest_topic_arn:
            return {"status": "skipped", "reason": "DIGEST_TOPIC_ARN not configured"}
        try:
            resp = self._sns.publish(
                TopicArn=self._digest_topic_arn,
                Subject="AWS Health Daily Digest",
                Message=digest["text"],
                MessageAttributes={
                    "eventCount": {"DataType": "Number", "StringValue": str(digest["generated_at_event_count"])},
                },
            )
            return {"status": "sent", "message_id": resp.get("MessageId", "")}
        except Exception as exc:
            return {"status": "failed", "error": str(exc)}

    def _write_audit(self, event_arns: list[str]) -> None:
        try:
            ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            self._ddb.put_item(
                TableName=self._audit_log_table,
                Item={
                    "executionId": {"S": f"digest#{ts}"},
                    "timestamp": {"S": ts},
                    "step": {"S": "DIGEST"},
                    "includedEventArns": {"S": json.dumps(event_arns)},
                    "eventCount": {"N": str(len(event_arns))},
                },
            )
        except Exception as exc:
            logger.warning(json.dumps({"message": "Failed to write digest audit record", "error": str(exc)}))


_service = DigestService()


def handler(event: dict, context) -> dict:
    """Lambda handler for the scheduled digest run."""
    return _service.run()
