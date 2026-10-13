# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Worker Lambda handler — implements the LOAD_EVENT, COMPUTE_URGENCY,
DECIDE_DISPOSITION, NOTIFY, and AUDIT steps referenced by
infra/lib/triage-workflow.ts as `workerFunction`.

CLASSIFY is handled separately by src/classifier/handler.py (kept isolated
because it invokes the Strands classification agent and carries the Bedrock
Guardrail wiring). INVENTORY/PROJECT_COST/PRECHECK are handled by
src/inventory/handler.py (kept isolated because of the sts:AssumeRole and
pricing:GetProducts permissions).

This module dispatches by the 'step' field, matching the pattern the other
two handlers use, so all three can share the CDK step-name contract.

Step Functions never calls the LLM through this handler — every step here is
pure precision code or external I/O (DynamoDB, SNS/Jira/Slack/Teams).
"""

from __future__ import annotations

import json
import logging
import os
import time

import boto3

from src import config
from src.triage.urgency import compute_urgency
from src.triage.disposition import decide_disposition
from src.sinks.sns_sink import SnsSink
from src.sinks.jira_sink import JiraSink
from src.sinks.slack_sink import SlackSink
from src.sinks.teams_sink import TeamsSink
from src.sinks.dispatcher import dispatch as dispatch_sinks

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))


def _ddb_deserialize(item: dict) -> dict:
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
        else:
            result[k] = v
    return result


def _ddb_serialize(obj: dict) -> dict:
    result: dict = {}
    for k, v in obj.items():
        if isinstance(v, str):
            result[k] = {"S": v}
        elif isinstance(v, bool):
            result[k] = {"BOOL": v}
        elif isinstance(v, (int, float)):
            result[k] = {"N": str(v)}
        elif isinstance(v, (list, dict)):
            result[k] = {"S": json.dumps(v)}
        elif v is None:
            result[k] = {"NULL": True}
        else:
            result[k] = {"S": str(v)}
    return result


class WorkerService:
    """Implements the non-classification, non-inventory workflow steps."""

    def __init__(
        self,
        *,
        dynamodb_client=None,
        sns_sink=None,
        jira_sink=None,
        slack_sink=None,
        teams_sink=None,
    ):
        self._ddb = dynamodb_client or boto3.client("dynamodb", region_name=config.AWS_REGION)
        self._sns_sink = sns_sink or SnsSink()
        self._jira_sink = jira_sink if jira_sink is not None else (
            JiraSink() if config.JIRA_SECRET_ARN else None
        )
        self._slack_sink = slack_sink if slack_sink is not None else (
            SlackSink() if config.SLACK_SECRET_ARN else None
        )
        self._teams_sink = teams_sink if teams_sink is not None else (
            TeamsSink() if config.TEAMS_SECRET_ARN else None
        )

    # ------------------------------------------------------------------
    # LOAD_EVENT
    # ------------------------------------------------------------------

    def load_event(self, event_arn: str) -> dict:
        try:
            resp = self._ddb.get_item(
                TableName=config.CONSOLIDATED_TABLE_NAME,
                Key={"eventArn": {"S": event_arn}},
                ConsistentRead=True,
            )
            item = resp.get("Item")
            if not item:
                logger.warning("LoadEvent: no record found for %s", event_arn)
                return {"event": {}}
            return {"event": _ddb_deserialize(item)}
        except Exception as exc:
            logger.error("LoadEvent failed for %s: %s", event_arn, exc)
            return {"event": {}}

    # ------------------------------------------------------------------
    # COMPUTE_URGENCY / DECIDE_DISPOSITION (exposed for direct invocation;
    # normally computed inline by src/classifier/handler.py, but available
    # here for workflow states that call the worker function directly)
    # ------------------------------------------------------------------

    def compute_urgency_step(self, classification: str, deadline: str | None) -> dict:
        return {"urgency": compute_urgency(deadline, classification)}

    def decide_disposition_step(self, classification: str, event_type_code: str) -> dict:
        return decide_disposition(classification, event_type_code)

    # ------------------------------------------------------------------
    # NOTIFY
    # ------------------------------------------------------------------

    def notify(self, payload: dict) -> dict:
        """Resolve team, dispatch to sinks, persist TicketMap, return result.

        Args:
            payload: Merged workflow state with eventArn, classification,
                urgency, deadline, disposition, reason, impactSummary,
                costProjection, precheckResult.

        Returns:
            Dict with dispatch results and the resolved team.
        """
        event_arn = payload.get("eventArn", "")
        # 'service'/'eventTypeCode'/'statusCode'/'affectedEntities' live on
        # the consolidated event, not flat on the workflow payload — a real
        # deploy + test event confirmed reading these flat (payload.get(
        # "service", "")) always returned "", so resolve_team()'s SERVICE
        # rule and should_close() could never fire against real event data,
        # even after PrepareNotifyInput was fixed to carry 'event' through.
        consolidated_event = payload.get("event") or {}

        record = {
            "eventArn": event_arn,
            "service": consolidated_event.get("service", ""),
            "statusCode": consolidated_event.get("statusCode", "open"),
            "affectedEntities": consolidated_event.get("affectedEntities", {}),
            "accountContexts": payload.get("accountContexts", []),
        }

        notification_payload = {
            "version": "1",
            "eventArn": event_arn,
            "service": consolidated_event.get("service", ""),
            "eventTypeCode": consolidated_event.get("eventTypeCode", ""),
            "eventTypeCategory": consolidated_event.get("eventTypeCategory", ""),
            "statusCode": consolidated_event.get("statusCode", ""),
            "classification": payload.get("classification"),
            "classificationReason": payload.get("reason"),
            "urgency": payload.get("urgency"),
            "deadline": payload.get("deadline"),
            "disposition": payload.get("disposition"),
            "precheck": payload.get("precheck"),
            "impactSummary": payload.get("impactSummary"),
            "costProjection": payload.get("costProjection"),
        }

        ticket_refs = self._load_ticket_refs(event_arn)

        result = dispatch_sinks(
            record,
            notification_payload,
            ticket_refs,
            sns_sink=self._sns_sink,
            jira_sink=self._jira_sink,
            slack_sink=self._slack_sink,
            teams_sink=self._teams_sink,
        )

        self._save_ticket_refs(event_arn, result["new_ticket_refs"])
        self._save_disposition(event_arn, payload)

        logger.info(json.dumps({
            "message": "Notify dispatch complete",
            "event_arn": event_arn,
            "team": result["team"]["team"],
            "closed": result["closed"],
            "sink_statuses": {k: v.get("status") for k, v in result["results"].items()},
        }))

        return result

    def _save_disposition(self, event_arn: str, payload: dict) -> None:
        """Persist the workflow's disposition decision back onto the
        ConsolidatedEvents record.

        The master spec's design.md documents ConsolidatedEvents as carrying
        disposition, precheck result, and timestamps (queried via the
        byDispositionUpdatedAt GSI for the scheduled digest) — but nothing
        in the pipeline ever wrote these fields back; only the intake-time
        snapshot (service, eventTypeCode, statusCode, etc.) was ever
        persisted. Confirmed via a real deployed digest Lambda invocation
        returning {"status": "empty", "event_count": 0} despite a real
        DIGEST-disposition event existing, and a direct DynamoDB get_item
        showing no 'disposition'/'dispositionUpdatedAt' attribute on the
        stored item at all. Without this write, the digest's GSI query can
        never match any item, regardless of how many DIGEST events flow
        through the system. Never raises — a failure here must not block
        the NOTIFY step's actual notification dispatch, which has already
        completed by the time this runs.
        """
        try:
            now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            self._ddb.update_item(
                TableName=config.CONSOLIDATED_TABLE_NAME,
                Key={"eventArn": {"S": event_arn}},
                UpdateExpression=(
                    "SET disposition = :disposition, "
                    "dispositionUpdatedAt = :ts, "
                    "classification = :classification, "
                    "urgency = :urgency, "
                    "deadline = :deadline, "
                    "precheckResult = :precheck_result"
                ),
                ExpressionAttributeValues={
                    ":disposition": {"S": payload.get("disposition") or "UNKNOWN"},
                    ":ts": {"S": now},
                    ":classification": {"S": payload.get("classification") or ""},
                    ":urgency": {"S": payload.get("urgency") or ""},
                    ":deadline": {"S": payload.get("deadline") or ""},
                    ":precheck_result": {"S": json.dumps(payload.get("precheckResult") or {})},
                },
            )
        except Exception as exc:
            logger.warning(
                json.dumps({
                    "message": "Failed to persist disposition to ConsolidatedEvents",
                    "event_arn": event_arn,
                    "error": str(exc),
                })
            )

    def _load_ticket_refs(self, event_arn: str) -> dict:
        try:
            resp = self._ddb.get_item(
                TableName=config.TICKET_MAP_TABLE_NAME,
                Key={"eventArn": {"S": event_arn}},
                ConsistentRead=True,
            )
            item = resp.get("Item", {})
            refs_json = item.get("sinkRefs", {}).get("S")
            return json.loads(refs_json) if refs_json else {}
        except Exception as exc:
            logger.warning("Failed to load ticket refs for %s: %s", event_arn, exc)
            return {}

    def _save_ticket_refs(self, event_arn: str, refs: dict) -> None:
        try:
            self._ddb.put_item(
                TableName=config.TICKET_MAP_TABLE_NAME,
                Item={
                    "eventArn": {"S": event_arn},
                    "sinkRefs": {"S": json.dumps(refs)},
                },
            )
        except Exception as exc:
            logger.warning("Failed to save ticket refs for %s: %s", event_arn, exc)

    # ------------------------------------------------------------------
    # AUDIT
    # ------------------------------------------------------------------

    def audit(self, event_arn: str, execution_id: str, status: str, error: str | None) -> dict:
        try:
            ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            self._ddb.put_item(
                TableName=config.AUDIT_LOG_TABLE_NAME,
                Item={
                    "executionId": {"S": execution_id or event_arn},
                    "timestamp": {"S": ts},
                    "eventArn": {"S": event_arn},
                    "status": {"S": status},
                    "error": {"S": error} if error else {"NULL": True},
                },
            )
            return {"status": "written"}
        except Exception as exc:
            logger.warning("Audit write failed for %s: %s", event_arn, exc)
            return {"status": "failed", "error": str(exc)}


_service = WorkerService()


def handler(event: dict, context) -> dict:
    """Lambda handler for LOAD_EVENT, COMPUTE_URGENCY, DECIDE_DISPOSITION,
    NOTIFY, and AUDIT steps."""
    step = event.get("step", "")
    event_arn = event.get("eventArn", "")

    if step == "LOAD_EVENT":
        return _service.load_event(event_arn)
    if step == "COMPUTE_URGENCY":
        return _service.compute_urgency_step(event.get("classification", "UNCLASSIFIED"), event.get("deadline"))
    if step == "DECIDE_DISPOSITION":
        return _service.decide_disposition_step(event.get("classification", "UNCLASSIFIED"), event.get("eventTypeCode", ""))
    if step == "NOTIFY":
        return _service.notify(event)
    if step == "AUDIT":
        return _service.audit(event_arn, event.get("executionId", ""), event.get("status", "UNKNOWN"), event.get("error"))

    logger.warning("Unknown step '%s' in worker handler", step)
    return {"eventArn": event_arn, "error": f"Unknown step: {step}"}
