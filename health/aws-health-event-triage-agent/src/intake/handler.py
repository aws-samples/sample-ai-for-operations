# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Intake Lambda handler — SQS batch consumer for AWS Health EventBridge events.

Batch size: 10. ReportBatchItemFailures enabled: failed items are retried
without re-processing successful ones.

Environment variables (via src.config):
    CONSOLIDATED_TABLE_NAME  — DynamoDB ConsolidatedEvents table
    IDEMPOTENCY_TABLE_NAME   — DynamoDB Idempotency table
    ACCOUNT_CACHE_TABLE_NAME — DynamoDB AccountContextCache table
    TICKET_MAP_TABLE_NAME    — DynamoDB TicketMap table
    AUDIT_LOG_TABLE_NAME     — DynamoDB AuditLog table
    TRIAGE_WORKFLOW_ARN      — Step Functions state machine ARN
    AWS_REGION               — AWS Region (injected by Lambda runtime)
"""

from __future__ import annotations

import json
import logging
import os

from src.intake.service import IntakeService

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

# Instantiate the service once per Lambda container (warm start optimisation)
_service = IntakeService(
    consolidated_table_name=os.environ.get("CONSOLIDATED_TABLE_NAME", "health-triage-consolidated-events"),
    idempotency_table_name=os.environ.get("IDEMPOTENCY_TABLE_NAME", "health-triage-idempotency"),
    account_cache_table_name=os.environ.get("ACCOUNT_CACHE_TABLE_NAME", "health-triage-account-context-cache"),
    ticket_map_table_name=os.environ.get("TICKET_MAP_TABLE_NAME", "health-triage-ticket-map"),
    audit_log_table_name=os.environ.get("AUDIT_LOG_TABLE_NAME", "health-triage-audit-log"),
    workflow_arn=os.environ.get("TRIAGE_WORKFLOW_ARN", ""),
)


def handler(event: dict, context) -> dict:
    """Lambda handler for SQS batch messages.

    Returns a 'batchItemFailures' response so failed items are retried
    individually without blocking the rest of the batch.

    Args:
        event: SQS event with 'Records' list.
        context: Lambda context object (unused).

    Returns:
        Dict with 'batchItemFailures' list of {'itemIdentifier': messageId}.
    """
    records = event.get("Records", [])
    batch_item_failures: list[dict] = []

    for record in records:
        message_id = record.get("messageId", "(unknown)")
        try:
            body = record.get("body", "{}")
            if isinstance(body, str):
                raw_message = json.loads(body)
            else:
                raw_message = body

            result = _service.process_message(raw_message)

            if result.get("status") == "parse_error":
                # Parse errors go straight to DLQ via batch item failure
                logger.error(
                    json.dumps({
                        "message": "Parse error — sending to DLQ",
                        "message_id": message_id,
                        "error": result.get("error"),
                    })
                )
                batch_item_failures.append({"itemIdentifier": message_id})

        except Exception as exc:
            logger.exception(
                json.dumps({
                    "message": "Unhandled error processing SQS record",
                    "message_id": message_id,
                    "error": str(exc),
                })
            )
            batch_item_failures.append({"itemIdentifier": message_id})

    return {"batchItemFailures": batch_item_failures}
