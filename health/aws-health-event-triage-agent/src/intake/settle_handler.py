# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Settle consumer Lambda handler — SQS batch consumer for the settle queue.

Working spec feat-devops-agent-enrichment, req §1b / design §3.0 (task -1b).

The Intake Lambda (src/intake/handler.py) merges every AWS Health message
into ConsolidatedEvents immediately, but no longer starts the TriageWorkflow
execution itself. Instead it enqueues a delayed message here (delay =
INTAKE_SETTLE_SECONDS). By the time this consumer receives that message, the
settle window has elapsed and every message for that (eventArn,
lastUpdatedTime) — one per affected account/page in AWS Health's
organizational-view fan-out — has had time to merge. This handler is the
ONLY caller of Step Functions StartExecution.

N settle messages for one AWS update (one per intake message) all resolve
to the SAME fixed execution name (sha256(eventArn + lastUpdatedTime)[:64]),
so N-1 of the N StartExecution calls fail on ExecutionAlreadyExists and are
caught and ignored by IntakeService._start_workflow — exactly the pre-
existing collapsing behaviour, now finally reached with a settled record
instead of racing the fan-out.

Batch size and reportBatchItemFailures mirror the Intake Lambda's SQS
consumer pattern.

Environment variables (via src.config):
    CONSOLIDATED_TABLE_NAME  — DynamoDB ConsolidatedEvents table (unused by
                               this handler directly; LoadEvent reads it)
    TRIAGE_WORKFLOW_ARN      — Step Functions state machine ARN
    SETTLE_QUEUE_URL         — this Lambda's own trigger queue (informational)
    AWS_REGION               — AWS Region (injected by Lambda runtime)
"""

from __future__ import annotations

import json
import logging
import os

from src.intake.service import IntakeService

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

# Instantiate the service once per Lambda container (warm start optimisation).
# Only the fields start_settled_workflow() actually touches need to be real;
# the rest default from src.config the same way the Intake Lambda's instance
# does, so both handlers stay consistent if config changes.
_service = IntakeService(
    workflow_arn=os.environ.get("TRIAGE_WORKFLOW_ARN", ""),
)


def handler(event: dict, context) -> dict:
    """Lambda handler for the settle queue's SQS batch messages.

    Returns a 'batchItemFailures' response so failed items are retried
    individually without blocking the rest of the batch — the same pattern
    as src/intake/handler.py's SQS batch consumer.

    Args:
        event: SQS event with 'Records' list. Each record's body is
            {"eventArn": str, "lastUpdatedTime": str}.
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
            payload = json.loads(body) if isinstance(body, str) else body
            event_arn = payload.get("eventArn", "")
            last_updated_time = payload.get("lastUpdatedTime", "")

            if not event_arn:
                logger.error(
                    json.dumps({
                        "message": "Settle message missing eventArn — sending to DLQ",
                        "message_id": message_id,
                    })
                )
                batch_item_failures.append({"itemIdentifier": message_id})
                continue

            result = _service.start_settled_workflow(event_arn, last_updated_time)
            logger.info(
                json.dumps({
                    "message": "Settled workflow execution requested",
                    "event_arn": result["event_arn"],
                    "execution_name": result["execution_name"],
                })
            )

        except Exception as exc:
            logger.exception(
                json.dumps({
                    "message": "Unhandled error processing settle record",
                    "message_id": message_id,
                    "error": str(exc),
                })
            )
            batch_item_failures.append({"itemIdentifier": message_id})

    return {"batchItemFailures": batch_item_failures}
