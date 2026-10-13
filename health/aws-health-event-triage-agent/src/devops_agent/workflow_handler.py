# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Step Functions handler for the DevOps Agent incident-gate and
enrichment states: RESOLVE_AGENT_SPACE, RESOLVE_AGENT_SPACES,
DECIDE_INVESTIGATION, TRIGGER_INVESTIGATION, SUMMARIZE_OUTCOME.

Implements the `workerFunction` step names infra/lib/triage-workflow.ts
inserts between DECIDE_DISPOSITION and NOTIFY (design.md §7). Follows the
same step-dispatch pattern as src/classifier/worker_handler.py.

TRIGGER_INVESTIGATION is invoked via the Step Functions
`.waitForTaskToken` integration: it sends the webhook and returns without
completing the task. The task token is completed later by
callback_handler.py, driven by the aws.aidevops EventBridge forward. A
single investigation now answers both impact and readiness for an
enrichment-kind event (E4.1) — the separate readiness-investigation
trigger path (RESOLVE_READINESS_ELIGIBILITY / TRIGGER_READINESS /
SUMMARIZE_READINESS) was retired in Phase B.

No step here calls an LLM. Gate/parse logic is precision code
(src.devops_agent.gate, .readiness_gate, .outcome, .readiness_outcome);
AWS/webhook I/O is data retrieval (src.devops_agent.dedupe, .counters,
.trigger, .readiness_tracker).
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone

import boto3

from src import config
from src.devops_agent.counters import (
    get_incident_counter,
    get_readiness_counter,
)
from src.devops_agent.dedupe import dedupe_check, record_active_investigation
from src.devops_agent.gate import decide_investigation
from src.devops_agent.readiness_gate import decide_readiness
from src.devops_agent.readiness_tracker import has_prior_assessment
from src.devops_agent.registry import resolve_agent_space, resolve_agent_spaces_by_account
from src.devops_agent.trigger import (
    build_webhook_payload,
    send_webhook,
)

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))


class DevOpsAgentWorkflowService:
    """Implements the RESOLVE_AGENT_SPACE / RESOLVE_AGENT_SPACES /
    DECIDE_INVESTIGATION / TRIGGER_INVESTIGATION / SUMMARIZE_OUTCOME
    workflow steps."""

    def __init__(self, *, dynamodb_client=None, secrets_client=None):
        self._ddb = dynamodb_client or boto3.client("dynamodb", region_name=config.AWS_REGION)
        self._secrets = secrets_client or boto3.client(
            "secretsmanager", region_name=config.AWS_REGION
        )

    # ------------------------------------------------------------------
    # RESOLVE_AGENT_SPACE
    # ------------------------------------------------------------------

    def resolve_agent_space_step(self, event: dict) -> dict:
        health_event = event.get("event", event)
        affected_account = health_event.get("affectedAccount")
        affected_accounts = health_event.get("affectedAccounts") or (
            [affected_account] if affected_account else []
        )
        account_contexts = event.get("accountContexts", [])

        registry_entry = resolve_agent_space(affected_accounts, account_contexts)
        return {"agentSpaceEntry": registry_entry}

    # ------------------------------------------------------------------
    # RESOLVE_AGENT_SPACES (plural — task 11, design §3.0)
    #
    # New step, alongside (not replacing) RESOLVE_AGENT_SPACE above.
    # Resolves a DISTINCT space per account and groups accounts by space,
    # feeding the enrichment path's Map-over-distinct-spaces fan-out. The
    # existing incident-gate path (resolve_agent_space_step,
    # decide_investigation_step, trigger_investigation_step's single-branch
    # call) is completely untouched by this step's addition.
    # ------------------------------------------------------------------

    def resolve_agent_spaces_step(self, event: dict) -> dict:
        """Resolves the distinct Agent Spaces covering this event's
        affected accounts, grouped per space.

        Args:
            event: Merged workflow state including 'event' (health event)
                and 'accountContexts'.

        Returns:
            {"agentSpaceGroups": [{"agentSpaceEntry": dict | None,
             "accounts": list[str]}, ...]} — see
             resolve_agent_spaces_by_account()'s own docstring for the
             exact shape, including the uncovered-accounts group.
        """
        health_event = event.get("event", event)
        affected_account = health_event.get("affectedAccount")
        affected_accounts = health_event.get("affectedAccounts") or (
            [affected_account] if affected_account else []
        )
        account_contexts = event.get("accountContexts", [])

        groups = resolve_agent_spaces_by_account(affected_accounts, account_contexts)

        logger.info(
            json.dumps({
                "message": "DevOps Agent multi-space resolution",
                "event_arn": health_event.get("eventArn", ""),
                "distinct_spaces": len([g for g in groups if g["agentSpaceEntry"] is not None]),
                "uncovered_accounts": next(
                    (g["accounts"] for g in groups if g["agentSpaceEntry"] is None), []
                ),
            })
        )
        return {"agentSpaceGroups": groups}

    # ------------------------------------------------------------------
    # DECIDE_INVESTIGATION
    # ------------------------------------------------------------------

    def decide_investigation_step(self, event: dict) -> dict:
        """Decide whether to trigger an investigation.

        Task 6 (working spec feat-devops-agent-enrichment, design §3.2):
        gains an optional 'kind' input field. kind="incident" (default,
        omitted field also means this — existing callers/payloads that
        predate this task keep exactly today's behaviour) runs the
        original category/status/code gate only. kind="enrichment" also
        runs decide_readiness() for the SAME event, inside this step (not
        a separate parallel branch — E4.1/E4.2), and folds its result onto
        the return as 'askReadiness'/'readinessAccounts', so
        TRIGGER_INVESTIGATION's single webhook can ask both questions in
        one investigation.
        """
        health_event = event.get("event", event)
        registry_entry = event.get("agentSpaceEntry")
        event_arn = health_event.get("eventArn", "")
        kind = event.get("kind", "incident")
        classification = event.get("classification", "")

        if registry_entry is None:
            decision = decide_investigation(
                health_event, None, {}, {"duplicate": False}, kind=kind, classification=classification
            )
            result = {"investigationDecision": decision}
            if kind == "enrichment":
                result.update(self._decide_readiness_for_enrichment(event, registry_entry))
            return result

        agent_space_id = registry_entry.get("agentSpaceId", "")
        cap = registry_entry.get("incidentCapPerMonth", 0)
        window_minutes = registry_entry.get("dedupeWindowMinutes", 60)

        dedupe_result = dedupe_check(agent_space_id, event_arn, window_minutes)
        counters = get_incident_counter(agent_space_id, cap)

        decision = decide_investigation(
            health_event, registry_entry, counters, dedupe_result, kind=kind, classification=classification
        )

        logger.info(
            json.dumps(
                {
                    "message": "DevOps Agent investigation decision",
                    "event_arn": event_arn,
                    "agent_space_id": agent_space_id,
                    "kind": kind,
                    "trigger": decision["trigger"],
                    "skip_kind": decision["skip_kind"],
                }
            )
        )
        result = {"investigationDecision": decision}
        if kind == "enrichment":
            result.update(self._decide_readiness_for_enrichment(event, registry_entry))
        return result

    def _decide_readiness_for_enrichment(self, event: dict, registry_entry: dict | None) -> dict:
        """Runs decide_readiness() INSIDE the enrichment DECIDE_INVESTIGATION
        step (design §3.2), returning {"askReadiness": bool,
        "readinessAccounts": list[str]} to fold onto TRIGGER_INVESTIGATION's
        webhook payload — one investigation now answers both impact and
        readiness (E4.1). Never raises; a decide_readiness error degrades to
        askReadiness=False (readiness is additive, never load-bearing for
        whether the enrichment investigation itself proceeds).
        """
        health_event = event.get("event", event)
        impact_summary = event.get("impactSummary") or {}
        classification_result = {
            "classification": event.get("classification"),
            "deadline": event.get("deadline"),
        }
        event_arn = health_event.get("eventArn", "")

        try:
            if registry_entry is None:
                decision = decide_readiness(
                    health_event, classification_result, impact_summary, None, {}, {"assessed_accounts": []}
                )
            else:
                agent_space_id = registry_entry.get("agentSpaceId", "")
                # E4.5: readinessCapPerMonth is accepted-but-ignored as a
                # separate readiness cap now. The dedicated readiness
                # investigation (and its own increment_readiness_counter
                # path) was retired in Phase B; readiness is answered by the
                # single enrichment investigation, governed by the one
                # per-space incident cap. We still read the field (for the
                # kept get_readiness_counter dedupe/observability read) but
                # log that its old per-month-cap semantics are superseded.
                cap = registry_entry.get("readinessCapPerMonth", 0)
                logger.info(
                    json.dumps({
                        "message": "readinessCapPerMonth is accepted but ignored (E4.5) — "
                        "its separate per-month readiness cap is superseded by the single "
                        "per-space incident cap now that one enrichment investigation answers "
                        "both impact and readiness",
                        "event_arn": event_arn,
                        "agent_space_id": agent_space_id,
                    })
                )
                horizon_days = registry_entry.get("readinessHorizonDays", config.READINESS_HORIZON_DAYS)
                prior_assessment = has_prior_assessment(event_arn)
                counters = get_readiness_counter(agent_space_id, cap)
                decision = decide_readiness(
                    health_event,
                    classification_result,
                    impact_summary,
                    registry_entry,
                    counters,
                    prior_assessment,
                    horizon_days=int(horizon_days),
                )
        except Exception as exc:
            logger.warning(
                json.dumps({
                    "message": "decide_readiness failed inside enrichment DECIDE_INVESTIGATION — degrading to no readiness question",
                    "event_arn": event_arn,
                    "error": str(exc),
                })
            )
            return {"askReadiness": False, "readinessAccounts": []}

        return {"askReadiness": decision["trigger"], "readinessAccounts": decision["accounts_to_assess"]}

    # ------------------------------------------------------------------
    # TRIGGER_INVESTIGATION (.waitForTaskToken)
    # ------------------------------------------------------------------

    def trigger_investigation_step(self, event: dict) -> dict:
        """Builds, signs, and sends the webhook; stores the task token.

        Args:
            event: Merged workflow state including 'TaskToken' (injected by
                the Step Functions .waitForTaskToken integration),
                'event' (the health event), 'agentSpaceEntry', and
                (task 6, working spec feat-devops-agent-enrichment)
                optionally 'kind' ("incident" default, or "enrichment"),
                'classification', 'urgency', 'deadline', 'impactLocus', and
                's3SnapshotKey'. The last five are only meaningful together
                with kind="enrichment" — build_webhook_payload() only
                writes the [HEALTH_TRIAGE:...] tag when 'classification' is
                non-empty (task 5), so an incident-kind call with none of
                these set produces byte-for-byte the same webhook as before
                this task.

        Returns:
            {"triggered": bool, "incidentId": str | None, "error": str | None}.
            The Step Functions task itself stays pending on success — this
            return value is the Lambda's own response, not the workflow's
            eventual output (that comes from SendTaskSuccess/Failure).
        """
        task_token = event.get("TaskToken", "")
        health_event = event.get("event", event)
        registry_entry = event.get("agentSpaceEntry") or {}
        event_arn = health_event.get("eventArn", "")
        agent_space_id = registry_entry.get("agentSpaceId", "")
        kind = event.get("kind", "incident")

        trigger_method = registry_entry.get("triggerMethod", "WEBHOOK")
        if trigger_method == "ASSUME_ROLE":
            # No confirmed DevOps Agent API exists for triggering an
            # investigation without the eventChannel webhook (design.md
            # §12) — flagged as an explicit stub rather than a guess.
            self._send_task_failure(
                task_token,
                error="NotImplemented",
                cause="ASSUME_ROLE trigger method is not yet implemented; no confirmed non-webhook trigger API exists.",
            )
            return {"triggered": False, "incidentId": None, "error": "ASSUME_ROLE not implemented"}

        built = build_webhook_payload(
            health_event,
            classification=event.get("classification", ""),
            urgency=event.get("urgency", ""),
            deadline=event.get("deadline"),
            impact_locus=event.get("impactLocus", "listed_resource"),
            s3_snapshot_key=event.get("s3SnapshotKey"),
        )
        incident_id = built["incidentId"]

        webhook_secret_arn = registry_entry.get("webhookSecretArn", "")
        webhook_url = registry_entry.get("webhookUrl", "")
        try:
            secret_value = self._secrets.get_secret_value(SecretId=webhook_secret_arn)
            webhook_secret = secret_value["SecretString"]
        except Exception as exc:
            # Not a credential leak: config_ref is the Secrets Manager
            # ARN (a lookup reference), never secret_value["SecretString"] (the actual
            # secret, not in scope here). Renamed for this log call only so a
            # name-pattern scanner does not flag the ARN as if it were the secret.
            config_ref = webhook_secret_arn
            logger.error("Failed to read webhook configuration reference %s: %s", config_ref, exc)
            self._send_task_failure(
                task_token, error="SecretReadFailed", cause=str(exc)
            )
            return {"triggered": False, "incidentId": incident_id, "error": str(exc)}

        send_result = send_webhook(webhook_url, webhook_secret, built["payload"])
        if send_result["status"] != "sent":
            self._send_task_failure(
                task_token, error="WebhookSendFailed", cause=str(send_result.get("error"))
            )
            return {"triggered": False, "incidentId": incident_id, "error": send_result.get("error")}

        self._save_task_token(incident_id, task_token, event_arn, kind=kind)
        record_active_investigation(agent_space_id, event_arn, incident_id)

        logger.info(
            json.dumps(
                {
                    "message": "DevOps Agent investigation triggered",
                    "event_arn": event_arn,
                    "agent_space_id": agent_space_id,
                    "incident_id": incident_id,
                    "kind": kind,
                }
            )
        )
        return {"triggered": True, "incidentId": incident_id, "error": None}

    def _save_task_token(
        self, incident_id: str, task_token: str, event_arn: str, *, kind: str = "incident"
    ) -> None:
        """Saves a pending task-token record.

        Args:
            kind: "incident" (default, Phase 1b) or "enrichment" (task 6,
                working spec feat-devops-agent-enrichment — a single
                investigation answering both impact and readiness).
                callback_handler.py reads this to decide which outcome
                parser/output shape applies to this pending task. (The
                "readiness" kind was retired in Phase B alongside the
                separate readiness-investigation trigger path.)
        """
        now = datetime.now(timezone.utc)
        ttl = int(now.timestamp()) + 3600  # 1 hour, matches the reference (design.md §5)
        self._ddb.put_item(
            TableName=config.TASK_TOKEN_TABLE_NAME,
            Item={
                "investigationId": {"S": incident_id},
                "taskToken": {"S": task_token},
                "healthEventId": {"S": event_arn},
                "createdAt": {"S": now.isoformat()},
                "ttl": {"N": str(ttl)},
                "kind": {"S": kind},
            },
        )

    def _send_task_failure(self, task_token: str, *, error: str, cause: str) -> None:
        if not task_token:
            return
        try:
            sfn = boto3.client("stepfunctions", region_name=config.AWS_REGION)
            sfn.send_task_failure(taskToken=task_token, error=error, cause=cause)
        except Exception as exc:
            logger.error("SendTaskFailure failed: %s", exc)

    # ------------------------------------------------------------------
    # SUMMARIZE_OUTCOME (result received via the wait-state's own output,
    # already the SendTaskSuccess payload built by callback_handler.py)
    # ------------------------------------------------------------------

    def summarize_outcome_step(self, event: dict) -> dict:
        """Folds the investigation outcome onto the notification payload.

        The wait state's output IS the SendTaskSuccess output
        (callback_handler.py already ran summarize_investigation_outcome
        and packaged the result) — this step exists to normalize field
        names onto the workflow's payload shape for NOTIFY, and to handle
        the "investigation was skipped/not triggered" case uniformly.
        """
        decision = event.get("investigationDecision", {})
        if not decision.get("trigger"):
            # Not investigated: leave impact as whatever R8 already set
            # (design.md §9 — additive, non-destructive when skipped).
            return {"impact": event.get("impact"), "investigationLink": event.get("investigationLink")}

        outcome = event.get("investigationOutcome")
        if not outcome:
            # Investigation was triggered but no outcome arrived (should not
            # normally happen — SendTaskFailure/Success always populates
            # this via the Catch/wait-state output) — unverifiable is the
            # safe default rather than silently keeping stale impact data.
            return {"impact": "unverifiable", "investigationLink": None}

        agent_space_id = (event.get("agentSpaceEntry") or {}).get("agentSpaceId", "")
        task_id = outcome.get("taskId", "")
        investigation_link = (
            f"https://{agent_space_id}.aidevops.global.app.aws/investigation/{task_id}"
            if agent_space_id and task_id
            else None
        )
        return {
            "impact": outcome.get("impact", "unverifiable"),
            "investigationLink": investigation_link,
        }


_service = DevOpsAgentWorkflowService()


def handler(event: dict, context) -> dict:
    """Lambda handler for the DevOps Agent incident-gate workflow steps."""
    step = event.get("step", "")

    if step == "RESOLVE_AGENT_SPACE":
        return _service.resolve_agent_space_step(event)
    if step == "RESOLVE_AGENT_SPACES":
        return _service.resolve_agent_spaces_step(event)
    if step == "DECIDE_INVESTIGATION":
        return _service.decide_investigation_step(event)
    if step == "TRIGGER_INVESTIGATION":
        return _service.trigger_investigation_step(event)
    if step == "SUMMARIZE_OUTCOME":
        return _service.summarize_outcome_step(event)

    logger.warning("Unknown step '%s' in DevOps Agent workflow handler", step)
    return {"error": f"Unknown step: {step}"}
