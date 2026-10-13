# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Webhook trigger for AWS DevOps Agent investigations.

Contract confirmed against the canonical reference implementation
(aws-samples/sample-aws-genai-ops-demos, observability/
proactive-health-event-impact-analyzer, investigation-trigger Lambda) per
the master design's confirmation gate (design.md §13.1). Ported to Python,
not vendored.

build_webhook_payload() and sign_webhook() are precision tools: pure
functions, no I/O, unit-testable without network or AWS access.

send_webhook() is a data-retrieval/action tool: performs the signed HTTPS
POST with retry/backoff and returns a structured result. Never raises past
its own retry loop; exhausted retries surface as a "failed" status so the
caller (the Lambda's .waitForTaskToken invoke) can fail the Step Functions
task cleanly rather than crash the Lambda.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_PRIORITY_MAP = {
    "issue": "CRITICAL",
    "scheduledChange": "HIGH",
    "accountNotification": "MEDIUM",
}
_DEFAULT_PRIORITY = "MEDIUM"

_MAX_ATTEMPTS = 3
_BASE_DELAY_SECONDS = 1
_MAX_DELAY_SECONDS = 4
_REQUEST_TIMEOUT_SECONDS = 10
_RETRYABLE_STATUSES = {429}


def _map_priority(event_category: str) -> str:
    return _PRIORITY_MAP.get(event_category, _DEFAULT_PRIORITY)


def _build_incident_id(service: str) -> str:
    """Builds a health-<service>-<epoch_ms>-<8 hex chars> incident ID.

    The random suffix (matching the reference's crypto.randomBytes(4))
    prevents DynamoDB task-token partition-key collisions when EventBridge
    redelivers the same AWS Health event.
    """
    epoch_ms = int(time.time() * 1000)
    suffix = secrets.token_hex(4)
    safe_service = (service or "unknown").replace(" ", "-")
    return f"health-{safe_service}-{epoch_ms}-{suffix}"


def _build_health_triage_tag(
    event_arn: str,
    classification: str,
    urgency: str,
    deadline: str | None,
    accounts: list[str],
    region: str,
    impact_locus: str,
) -> str:
    """Builds the code-written '[HEALTH_TRIAGE:...]' tag (req E1.2, design
    §3.2, task 5).

    Every value here comes from code — the classifier's already-computed
    classification/urgency/deadline, the event's own account list and
    region, and the config-driven impact locus — never derived from event
    text by the tag-building step itself. This is master hard boundary #7
    restated for the DevOps Agent side: the investigating agent is GIVEN
    the classification and urgency and never re-derives them, so a prompt-
    injection attempt inside the event's own description text cannot
    change what the agent is told to investigate. The
    `devops-agent-skill/agents-md/AGENTS-incident-triage.md` instructions
    (task 10) tell the agent to read this tag and never recompute its
    contents — defence in depth, not the enforcement point (the enforcement
    point is that code wrote this string, not the agent).
    """
    accounts_str = ",".join(accounts) if accounts else ""
    return (
        f"[HEALTH_TRIAGE:eventArn={event_arn},class={classification},"
        f"urgency={urgency},deadline={deadline or 'unspecified'},"
        f"accounts={accounts_str},region={region},impactLocus={impact_locus}]"
    )


def _build_description(
    event_arn: str,
    incident_id: str,
    jira_config: dict | None,
    *,
    health_triage_tag: str | None = None,
    s3_snapshot_key: str | None = None,
) -> str:
    """Builds the investigation prompt with correlation tags.

    Tag order matches the reference: CORRELATION_ID (event-level, shared
    across investigations for one event), INVESTIGATION_ID (this specific
    investigation, unique), then optional JIRA_CONFIG. This agent's own
    JiraSink already owns ticket creation (see requirements.md "what this
    agent does NOT port"), so JIRA_CONFIG is normally omitted; the
    parameter exists only for parity with the confirmed contract and future
    use, and is not populated by this agent's own trigger construction.

    health_triage_tag (task 5, req E1.2): when supplied, added after
    INVESTIGATION_ID/JIRA_CONFIG. Carries the classification, urgency,
    deadline, accounts, region, and impact locus the code already computed
    — the agent is GIVEN these, never asked to re-derive them.

    s3_snapshot_key (task 5, req E7.2): when supplied, added as an
    'EVENT_SNAPSHOT:' line so the investigating agent can read the full
    consolidated event (all pages, all entities, full description) beyond
    what this description's own text carries. Verified (req §6): a generic
    webhook only delivers title/description/priority to the agent — 'data'
    does not reach it — so the S3 key rides here, in description, not in
    the payload's 'data' object.
    """
    lines = [
        f"[CORRELATION_ID:{event_arn}]",
        f"[INVESTIGATION_ID:{incident_id}]",
    ]
    if jira_config:
        lines.append(f"[JIRA_CONFIG:{json.dumps(jira_config)}]")
    if health_triage_tag:
        lines.append(health_triage_tag)
    if s3_snapshot_key:
        lines.append(f"[EVENT_SNAPSHOT:{s3_snapshot_key}]")
    lines.append("")
    lines.append(
        "An AWS Health event may affect your workloads. Using the application "
        "topology, please answer: (1) which workloads use the affected "
        "resources, directly or transitively; (2) what is the blast radius; "
        "(3) do redundancy mechanisms (Multi-AZ, Auto Scaling, read replicas, "
        "cross-region failover) mitigate the impact; (4) what pre-event "
        "actions, if any, are recommended before the maintenance window or "
        "deadline."
    )
    return "\n".join(lines)


def build_webhook_payload(
    health_event: dict,
    jira_config: dict | None = None,
    *,
    classification: str = "",
    urgency: str = "",
    deadline: str | None = None,
    impact_locus: str = "listed_resource",
    s3_snapshot_key: str | None = None,
) -> dict:
    """Builds the DevOps Agent eventChannel webhook payload for a health event.

    Args:
        health_event: A health_event_v1-shaped dict (native AWS Health
            EventBridge fields): eventArn, service, eventTypeCode,
            eventTypeCategory, region, affectedAccount/affectedAccounts,
            affectedEntities (list of {entityValue, tags, entityStatus}).
        jira_config: Optional {"projectKey", "issueType", "siteUrl"} — see
            _build_description docstring; normally omitted by this agent.
        classification: The classifier's already-computed classification
            (e.g. "BREAKING_CHANGE"). Written into the code-built
            '[HEALTH_TRIAGE:...]' tag (task 5, req E1.2) when non-empty —
            omitted entirely (no tag at all) when empty, so pre-task-5
            callers that don't pass this keep getting the exact same
            description text as before.
        urgency: The already-computed urgency tier (e.g. "critical").
        deadline: The classifier's already-computed deadline (ISO 8601
            date), or None.
        impact_locus: The event type's impact locus ("listed_resource" or
            "dependent", from get_impact_locus()). Defaults to
            "listed_resource" (the common case) when the caller doesn't
            pass one — only written into the tag when classification is
            also non-empty, so this default never silently activates the
            tag on its own.
        s3_snapshot_key: The S3 key of the full event snapshot (task 8/E7),
            written as an '[EVENT_SNAPSHOT:...]' line when supplied.

    Returns:
        {"incidentId": str, "payload": dict} — the incident ID is returned
        alongside the payload because the caller needs it as the
        TaskTokenTable partition key before the webhook is even sent.
    """
    event_arn = health_event.get("eventArn", "")
    service = health_event.get("service", "unknown")
    event_type_code = health_event.get("eventTypeCode", "")
    category = health_event.get("eventTypeCategory", "")
    region = health_event.get("region", "")

    incident_id = _build_incident_id(service)
    priority = _map_priority(category)
    title = f"[{incident_id}] AWS Health: {service} {event_type_code} in {region}"

    health_triage_tag = None
    if classification:
        single_account = health_event.get("affectedAccount")
        accounts = health_event.get("affectedAccounts") or (
            [single_account] if single_account else []
        )
        health_triage_tag = _build_health_triage_tag(
            event_arn, classification, urgency, deadline, accounts, region, impact_locus
        )

    description = _build_description(
        event_arn,
        incident_id,
        jira_config,
        health_triage_tag=health_triage_tag,
        s3_snapshot_key=s3_snapshot_key,
    )

    affected_resources = [
        {
            "resourceId": entity.get("entityValue", ""),
            "tags": entity.get("tags", {}) or {},
            "status": entity.get("entityStatus", "unknown"),
        }
        for entity in (health_event.get("affectedEntities") or [])
    ]

    payload = {
        "eventType": "incident",
        "incidentId": incident_id,
        "action": "created",
        "priority": priority,
        "title": title,
        "description": description,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": service,
        "data": {
            "metadata": {
                "region": region,
                "availabilityZone": health_event.get("availabilityZone"),
                "environment": health_event.get("environment"),
                "sourceAccountId": health_event.get("affectedAccount"),
            },
            "healthEvent": {
                "eventId": event_arn,
                "category": category,
                "maintenanceWindow": {
                    "startTime": health_event.get("startTime"),
                    "endTime": health_event.get("endTime"),
                },
                "affectedResources": affected_resources,
                "status": health_event.get("statusCode", "unknown"),
            },
        },
    }
    return {"incidentId": incident_id, "payload": payload}


def sign_webhook(webhook_secret: str, timestamp: str, body: str) -> str:
    """Computes the HMAC-SHA256 signature for a webhook request body.

    Signature = base64(HMAC-SHA256(webhook_secret, f"{timestamp}:{body}")),
    matching the confirmed reference contract exactly.

    Args:
        webhook_secret: The Agent Space webhook's HMAC secret (read from
            Secrets Manager by the caller — never hardcoded).
        timestamp: ISO 8601 timestamp, sent as the x-amzn-event-timestamp
            header and included in the signed material.
        body: The exact JSON-encoded request body string being sent.

    Returns:
        Base64-encoded HMAC-SHA256 signature.
    """
    message = f"{timestamp}:{body}".encode("utf-8")
    digest = hmac.new(webhook_secret.encode("utf-8"), message, hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")


def send_webhook(webhook_url: str, webhook_secret: str, payload: dict) -> dict:
    """Sends the signed webhook to the Agent Space, with retry/backoff.

    Retries up to 3 total attempts on 5xx responses, 429, and network
    errors, with exponential backoff (1s, 2s, capped at 4s). Other 4xx
    responses are not retried. 10s timeout per attempt.

    Only https:// URLs are accepted (Bandit B310 / URL scheme validation
    per security-compliance) — a webhook URL is always AWS-issued and
    HTTPS, so a non-HTTPS URL indicates a misconfiguration, not a case to
    silently downgrade.

    Args:
        webhook_url: The Agent Space eventChannel webhook URL.
        webhook_secret: The HMAC secret for signing.
        payload: The dict from build_webhook_payload()["payload"].

    Returns:
        {"status": "sent"|"failed", "attempts": int, "error": str | None}
    """
    if not webhook_url.startswith("https://"):
        return {
            "status": "failed",
            "attempts": 0,
            "error": f"refusing to send webhook to non-HTTPS URL: {webhook_url!r}",
        }

    body = json.dumps(payload)
    timestamp = datetime.now(timezone.utc).isoformat()
    signature = sign_webhook(webhook_secret, timestamp, body)

    headers = {
        "Content-Type": "application/json",
        "x-amzn-event-timestamp": timestamp,
        "x-amzn-event-signature": signature,
    }

    last_error: str | None = None
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        try:
            request = urllib.request.Request(
                webhook_url, data=body.encode("utf-8"), headers=headers, method="POST"
            )
            # nosemgrep: dynamic-urllib-use-detected -- webhook_url is guarded by the
            # startswith("https://") check above (returns "failed" otherwise); it also
            # never reaches this call as raw external input, only via registry_entry
            # (see workflow_handler.py), so a file:// scheme cannot be smuggled in.
            with urllib.request.urlopen(request, timeout=_REQUEST_TIMEOUT_SECONDS) as response:  # nosemgrep: dynamic-urllib-use-detected  # nosec B310
                if response.status in (200, 202):
                    return {"status": "sent", "attempts": attempt, "error": None}
                last_error = f"webhook returned status {response.status}"
        except urllib.error.HTTPError as exc:
            last_error = f"HTTPError {exc.code}: {exc.reason}"
            if exc.code not in _RETRYABLE_STATUSES and not (500 <= exc.code < 600):
                # Non-retryable 4xx (except 429) — stop immediately.
                return {"status": "failed", "attempts": attempt, "error": last_error}
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = f"network error: {exc}"

        if attempt < _MAX_ATTEMPTS:
            delay = min(_BASE_DELAY_SECONDS * (2 ** (attempt - 1)), _MAX_DELAY_SECONDS)
            logger.warning(
                "Webhook attempt %d failed (%s), retrying in %ds", attempt, last_error, delay
            )
            time.sleep(delay)

    return {"status": "failed", "attempts": _MAX_ATTEMPTS, "error": last_error}


def _build_readiness_description(
    event_arn: str,
    incident_id: str,
    deadline: str | None,
) -> str:
    """Builds the readiness-assessment investigation prompt.

    Same [CORRELATION_ID:...]/[INVESTIGATION_ID:...] tag convention as
    _build_description (Phase 1b's incident gate) so callback_handler.py's
    existing correlation logic needs zero changes to also correlate
    readiness assessments — it matches by tag content, not by which skill
    answered (design.md §5).
    """
    lines = [
        f"[CORRELATION_ID:{event_arn}]",
        f"[INVESTIGATION_ID:{incident_id}]",
        "",
        "An AWS Health event describes a forced or deadline-bound change " +
        f"(deadline: {deadline or 'unspecified'}). Using the application " +
        "topology and the affected resources listed below, please assess: " +
        "(1) is this change ready to make — FEASIBILITY: READY, BLOCKED, or " +
        "NEEDS_REMEDIATION; (2) what specifically blocks it, if anything — " +
        "BLOCKERS; (3) how risky is making this change — RISK: LOW, MEDIUM, " +
        "or HIGH; (4) is a rollback path available if the change causes " +
        "problems — ROLLBACK_AVAILABLE: YES or NO.",
    ]
    return "\n".join(lines)


def build_readiness_webhook_payload(
    health_event: dict,
    accounts_to_assess: list[str],
    deadline: str | None = None,
) -> dict:
    """Builds the DevOps Agent webhook payload for a readiness assessment.

    Reuses build_webhook_payload()'s exact shape (incident ID format, HMAC
    signing via the same sign_webhook/send_webhook) — no separate
    "readiness" eventType exists in the confirmed webhook contract
    (design.md §5); eventType stays "incident" for every trigger regardless
    of which skill answers it. Distinguished from the incident gate's
    payload only by description content and the added assessmentAccounts
    field.

    Args:
        health_event: A health_event_v1-shaped dict, same shape
            build_webhook_payload() expects.
        accounts_to_assess: The accounts (from decide_readiness()'s
            accounts_to_assess) this assessment should evaluate — may be a
            subset of the event's full affected-account set when some
            accounts were already assessed in a prior run.
        deadline: The classification result's deadline (ISO 8601
            YYYY-MM-DD), included in the prompt for context.

    Returns:
        {"incidentId": str, "payload": dict} — same shape as
        build_webhook_payload()'s return value.
    """
    event_arn = health_event.get("eventArn", "")
    service = health_event.get("service", "unknown")
    event_type_code = health_event.get("eventTypeCode", "")
    category = health_event.get("eventTypeCategory", "")
    region = health_event.get("region", "")

    incident_id = _build_incident_id(service)
    title = f"[{incident_id}] AWS Health Readiness Assessment: {service} {event_type_code} in {region}"
    description = _build_readiness_description(event_arn, incident_id, deadline)

    affected_resources = [
        {
            "resourceId": entity.get("entityValue", ""),
            "tags": entity.get("tags", {}) or {},
            "status": entity.get("entityStatus", "unknown"),
        }
        for entity in (health_event.get("affectedEntities") or [])
    ]

    payload = {
        "eventType": "incident",
        "incidentId": incident_id,
        "action": "created",
        "priority": "HIGH",
        "title": title,
        "description": description,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": service,
        "data": {
            "metadata": {
                "region": region,
                "availabilityZone": health_event.get("availabilityZone"),
                "environment": health_event.get("environment"),
                "sourceAccountId": health_event.get("affectedAccount"),
            },
            "healthEvent": {
                "eventId": event_arn,
                "category": category,
                "maintenanceWindow": {
                    "startTime": health_event.get("startTime"),
                    "endTime": health_event.get("endTime"),
                },
                "affectedResources": affected_resources,
                "status": health_event.get("statusCode", "unknown"),
                "assessmentAccounts": accounts_to_assess,
                "deadline": deadline,
            },
        },
    }
    return {"incidentId": incident_id, "payload": payload}
