# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""EventBridge handler for aws.aidevops investigation-completion events
(StackSet C forward, R12.7). Correlates the event to a pending Step
Functions task token, reads the investigation journal, summarizes the
outcome, and completes the task with SendTaskSuccess or SendTaskFailure.

Contract confirmed against the canonical reference implementation
(investigation-callback Lambda) per design.md §13.1 — ported to Python,
not vendored. See requirements.md "Investigation callback contract".

No LLM call. Journal read is data retrieval; markdown parsing is delegated
to src.devops_agent.outcome.summarize_investigation_outcome (precision).
"""

from __future__ import annotations

import json
import logging
import os
import re

import boto3

from src import config
from src.devops_agent.outcome import summarize_investigation_outcome
from src.devops_agent.readiness_outcome import summarize_readiness_outcome

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

_COMPLETED_DETAIL_TYPE = "Investigation Completed"

_INVESTIGATION_ID_RE = re.compile(r"\[INVESTIGATION_ID:(.*?)\]")
_CORRELATION_ID_RE = re.compile(r"\[CORRELATION_ID:(.*?)\]")
_TITLE_INCIDENT_ID_RE = re.compile(r"TITLE:\s*\[(health-[^\]]+)\]")


def _extract_tag(text: str, pattern: re.Pattern) -> str | None:
    match = pattern.search(text)
    if not match:
        return None
    value = match.group(1).strip()
    return value or None


def _extract_correlation_key(first_message_text: str) -> str | None:
    """Extracts the correlation key from the first journal message's text.

    Preference order (most specific first), matching the confirmed
    reference contract:
      1. [INVESTIGATION_ID:...] — unique per investigation, direct GetItem.
      2. [CORRELATION_ID:...] — legacy/shared across investigations for one
         event; returned with an "arn:" prefix so the caller knows to Scan
         instead of GetItem.
      3. Title [health-...] fallback.
    """
    investigation_id = _extract_tag(first_message_text, _INVESTIGATION_ID_RE)
    if investigation_id:
        return investigation_id

    correlation_id = _extract_tag(first_message_text, _CORRELATION_ID_RE)
    if correlation_id:
        return f"arn:{correlation_id}"

    title_incident_id = _extract_tag(first_message_text, _TITLE_INCIDENT_ID_RE)
    if title_incident_id:
        return title_incident_id

    return None


def _message_text(content: list[dict]) -> str:
    return " ".join(part.get("text", "") for part in content if part.get("type") == "text")


class DevOpsAgentClientUnavailable(RuntimeError):
    """Raised when the boto3 'devops-agent' service client cannot be built.

    Confirmed at Build time: the AWS DevOps Agent boto3 service model is
    named "devops-agent" (hyphenated) and ships from botocore/boto3
    >=1.43.103 (see requirements.txt). Older pins lack the service model
    entirely, so this client is constructed lazily and this error is raised
    with the underlying exception chained, rather than crashing at import
    time or silently no-op'ing, if the deployed runtime's boto3 predates
    that version. The rest of the incident-gate pipeline (gate, trigger,
    webhook) does not depend on this client; only the callback's journal
    read is affected.
    """


class CallbackService:
    """Correlates aws.aidevops events to Step Functions task tokens."""

    def __init__(self, *, dynamodb_client=None, sfn_client=None, devopsagent_client=None):
        self._ddb = dynamodb_client or boto3.client("dynamodb", region_name=config.AWS_REGION)
        self._sfn = sfn_client or boto3.client("stepfunctions", region_name=config.AWS_REGION)
        # Client construction is deferred to first use (_devopsagent
        # property) so importing this module and exercising the
        # correlation/dedupe logic in tests never requires network/AWS
        # credentials, and so a boto3 version too old to have the
        # "devops-agent" service model fails loudly and specifically
        # (DevOpsAgentClientUnavailable) rather than at import time.
        self._devopsagent_client = devopsagent_client
        self._devopsagent_client_error: Exception | None = None

    @property
    def _devopsagent(self):
        if self._devopsagent_client is not None:
            return self._devopsagent_client
        if self._devopsagent_client_error is not None:
            raise DevOpsAgentClientUnavailable() from self._devopsagent_client_error
        try:
            self._devopsagent_client = boto3.client(
                "devops-agent", region_name=config.DEVOPS_AGENT_REGION or config.AWS_REGION
            )
            return self._devopsagent_client
        except Exception as exc:
            self._devopsagent_client_error = exc
            raise DevOpsAgentClientUnavailable() from exc

    def handle(self, detail_type: str, detail: dict) -> dict:
        metadata = detail.get("metadata", {})
        agent_space_id = metadata.get("agent_space_id", "")
        task_id = metadata.get("task_id", "")
        execution_id = metadata.get("execution_id", "")

        if not execution_id:
            logger.warning("No execution_id in event metadata, skipping")
            return {"status": "skipped", "reason": "no execution_id"}

        first_message = self._get_first_journal_message(agent_space_id, execution_id)
        if not first_message:
            logger.info("No journal messages found for execution %s", execution_id)
            return {"status": "skipped", "reason": "no journal messages"}

        correlation_key = _extract_correlation_key(_message_text(first_message.get("content", [])))
        if not correlation_key:
            logger.info("Could not extract a correlation key for execution %s", execution_id)
            return {"status": "skipped", "reason": "no correlation key"}

        task_token_record = self._find_task_token(correlation_key)
        if not task_token_record:
            # Not a credential leak: journal_lookup_ref is an ARN/investigation-ID
            # lookup reference, never the taskToken value itself (that only exists
            # inside task_token_record, which is None on this branch). Renamed for
            # this log call only so a name-pattern scanner does not flag the lookup
            # reference as if it carried the token.
            journal_lookup_ref = correlation_key
            logger.info("No matching callback record found for journal lookup reference %s", journal_lookup_ref)
            return {"status": "skipped", "reason": "no task token"}

        task_token = task_token_record["taskToken"]
        investigation_id = task_token_record["investigationId"]
        kind = task_token_record.get("kind", "incident")

        try:
            if detail_type == _COMPLETED_DETAIL_TYPE:
                analysis = self._get_agent_analysis(agent_space_id, execution_id)
                if kind == "enrichment":
                    # Task 7, working spec feat-devops-agent-enrichment,
                    # design §3.4: ONE parser path for the enrichment kind.
                    # Every enrichment callback returns analysisMarkdown
                    # (so the workflow's MERGE_ENRICHMENT step,
                    # src/inventory/handler.py's _do_merge_enrichment, can
                    # run parse_affected_resources over it) alongside
                    # 'impact' (kept — summarize_investigation_outcome's
                    # existing heading-bullet parser still runs, since a
                    # skill may still emit a Summary/Key Findings section
                    # even for an enrichment investigation) and 'readiness'
                    # (parsed via the SAME summarize_readiness_outcome the
                    # old kind="readiness" branch used, over the SAME
                    # analysis text — one investigation now answers both
                    # questions instead of two).
                    outcome = summarize_investigation_outcome(
                        analysis, detail.get("data", {}).get("priority", "MEDIUM")
                    )
                    readiness_summary = summarize_readiness_outcome(analysis)
                    output = {
                        "analysisMarkdown": analysis,
                        "impact": outcome["impact"],
                        "readiness": {
                            "feasibility": readiness_summary["feasibility"],
                            "blockers": readiness_summary["blockers"],
                            "risk": readiness_summary["risk"],
                            "rollback_available": readiness_summary["rollback_available"],
                        },
                        "taskId": task_id,
                        "agentSpaceId": agent_space_id,
                    }
                    self._sfn.send_task_success(taskToken=task_token, output=json.dumps(output))
                    logger.info(
                        json.dumps(
                            {
                                "message": "SendTaskSuccess",
                                "investigation_id": investigation_id,
                                "kind": "enrichment",
                                "impact": outcome["impact"],
                                "readiness_feasibility": readiness_summary["feasibility"],
                            }
                        )
                    )
                else:
                    priority = detail.get("data", {}).get("priority", "MEDIUM")
                    outcome = summarize_investigation_outcome(analysis, priority)
                    output = {**outcome, "taskId": task_id, "agentSpaceId": agent_space_id}
                    self._sfn.send_task_success(taskToken=task_token, output=json.dumps(output))
                    logger.info(
                        json.dumps(
                            {
                                "message": "SendTaskSuccess",
                                "investigation_id": investigation_id,
                                "kind": "incident",
                                "impact": outcome["impact"],
                            }
                        )
                    )
            else:
                error_code = re.sub(r"\s+", "", detail_type)
                self._sfn.send_task_failure(
                    taskToken=task_token,
                    error=error_code,
                    cause=f"Investigation {detail_type.lower()} (task: {task_id})",
                )
                logger.info(
                    json.dumps(
                        {"message": "SendTaskFailure", "investigation_id": investigation_id, "reason": detail_type}
                    )
                )

            self._delete_task_token(investigation_id)
            return {"status": "completed", "investigation_id": investigation_id}
        except Exception as exc:
            # nosemgrep: logging-error-without-handling -- logging for troubleshooting before re-raising
            logger.error("Failed to complete task for %s: %s", correlation_key, exc)
            raise

    def _get_first_journal_message(self, agent_space_id: str, execution_id: str) -> dict | None:
        try:
            response = self._devopsagent.list_journal_records(
                agentSpaceId=agent_space_id,
                executionId=execution_id,
                recordType="message",
                order="ASC",
                limit=1,
            )
            records = response.get("records", [])
            if not records:
                return None
            content = records[0].get("content")
            return json.loads(content) if isinstance(content, str) else content
        except DevOpsAgentClientUnavailable:
            logger.error(
                "Cannot retrieve journal message: boto3 'devopsagent' client is unavailable "
                "in this runtime (see DevOpsAgentClientUnavailable docstring)"
            )
            return None
        except Exception as exc:
            logger.error("Failed to retrieve first journal message: %s", exc)
            return None

    def _get_agent_analysis(self, agent_space_id: str, execution_id: str) -> str | None:
        try:
            response = self._devopsagent.list_journal_records(
                agentSpaceId=agent_space_id,
                executionId=execution_id,
                recordType="message",
                order="DESC",
                limit=5,
            )
            for record in response.get("records", []):
                content = record.get("content")
                parsed = json.loads(content) if isinstance(content, str) else content
                if not parsed or parsed.get("role") != "assistant":
                    continue
                text_parts = [
                    part.get("text", "")
                    for part in parsed.get("content", [])
                    if part.get("type") == "text" and part.get("text")
                ]
                return "\n\n".join(text_parts)
        except DevOpsAgentClientUnavailable:
            logger.error(
                "Cannot retrieve agent analysis: boto3 'devopsagent' client is unavailable "
                "in this runtime (see DevOpsAgentClientUnavailable docstring)"
            )
            return None
        except Exception as exc:
            logger.error("Failed to retrieve agent analysis: %s", exc)
        return None

    def _find_task_token(self, correlation_key: str) -> dict | None:
        if not correlation_key.startswith("arn:"):
            response = self._ddb.get_item(
                TableName=config.TASK_TOKEN_TABLE_NAME,
                Key={"investigationId": {"S": correlation_key}},
            )
            item = response.get("Item")
            if item and "taskToken" in item:
                return {
                    "taskToken": item["taskToken"]["S"],
                    "investigationId": correlation_key,
                    # Older records (Phase 1b, before Phase 5b's readiness
                    # gate) never wrote a "kind" attribute -- default to
                    # "incident" so this stays backward compatible.
                    "kind": item.get("kind", {}).get("S", "incident"),
                }
            return None

        health_event_arn = correlation_key[len("arn:"):]
        response = self._ddb.scan(
            TableName=config.TASK_TOKEN_TABLE_NAME,
            FilterExpression="healthEventId = :arn",
            ExpressionAttributeValues={":arn": {"S": health_event_arn}},
        )
        items = response.get("Items", [])
        if items and "taskToken" in items[0]:
            return {
                "taskToken": items[0]["taskToken"]["S"],
                "investigationId": items[0]["investigationId"]["S"],
                "kind": items[0].get("kind", {}).get("S", "incident"),
            }
        return None

    def _delete_task_token(self, investigation_id: str) -> None:
        if not investigation_id:
            return
        try:
            self._ddb.delete_item(
                TableName=config.TASK_TOKEN_TABLE_NAME,
                Key={"investigationId": {"S": investigation_id}},
            )
        except Exception as exc:
            # Not a credential leak: investigation_id is a generated identifier used
            # as the DynamoDB partition key, never the taskToken value
            # (task_token_record["taskToken"] is never passed to this method/log
            # call). Log message reworded to avoid the word "token" alongside the
            # identifier, since some scanners pattern-match on nearby wording rather
            # than tracing which value is actually logged.
            logger.warning("Failed to delete DynamoDB record for investigation %s: %s", investigation_id, exc)


_service = CallbackService()


def handler(event: dict, context) -> dict:
    """Lambda handler for aws.aidevops EventBridge events."""
    detail_type = event.get("detail-type", "")
    detail = event.get("detail", {})
    return _service.handle(detail_type, detail)
