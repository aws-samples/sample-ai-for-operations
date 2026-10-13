# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Centralised configuration for the AWS Health Event Triage Agent.

This is the ONLY module in src/ that reads environment variables directly.
All other modules import from here.

Environment variables:
    BEDROCK_MODEL_ID            Amazon Bedrock model ID for the classifier
    BEDROCK_REGION              AWS region for Bedrock API calls
    AWS_REGION                  AWS region (general-purpose; default eu-west-1)
    SYSTEM_PROMPT_S3_BUCKET     S3 bucket holding the externalized system prompt
    SYSTEM_PROMPT_S3_KEY        S3 key for the system prompt object
    SNS_TOPIC_ARN               SNS topic ARN for classification result publish
    APP_CONTEXT_TABLE_NAME      DynamoDB table name for application trust-store data
    APP_CONTEXT_JSON            Static JSON config fallback for trust-store data
    EKS_MCP_ENABLED             Set "true" to enable the local EKS MCP server
    AGENT_RUNTIME_ENDPOINT_ARN  Amazon Bedrock AgentCore Runtime endpoint ARN
    GUARDRAIL_ID                Amazon Bedrock Guardrail ID (required in prod)
    GUARDRAIL_VERSION           Amazon Bedrock Guardrail version (default DRAFT)
    KMS_KEY_ARN                 Customer-managed KMS key ARN for encryption
    SESSION_TABLE_NAME          DynamoDB table name for agent session state
    LOG_LEVEL                   Python logging level (default INFO)
"""

from __future__ import annotations

import os

# ---------------------------------------------------------------------------
# Amazon Bedrock
# ---------------------------------------------------------------------------
BEDROCK_MODEL_ID: str = os.environ.get(
    "BEDROCK_MODEL_ID", "eu.anthropic.claude-sonnet-5"
)
BEDROCK_REGION: str = os.environ.get("BEDROCK_REGION", "eu-west-1")

# ---------------------------------------------------------------------------
# General AWS
# ---------------------------------------------------------------------------
AWS_REGION: str = os.environ.get("AWS_REGION", "eu-west-1")

# ---------------------------------------------------------------------------
# System prompt (externalized)
# ---------------------------------------------------------------------------
SYSTEM_PROMPT_S3_BUCKET: str = os.environ.get("SYSTEM_PROMPT_S3_BUCKET", "")
SYSTEM_PROMPT_S3_KEY: str = os.environ.get(
    "SYSTEM_PROMPT_S3_KEY", "prompts/system_prompt.txt"
)

# ---------------------------------------------------------------------------
# Sinks
# ---------------------------------------------------------------------------
SNS_TOPIC_ARN: str = os.environ.get("SNS_TOPIC_ARN", "")

# ---------------------------------------------------------------------------
# Application context / trust-store data
# ---------------------------------------------------------------------------
APP_CONTEXT_TABLE_NAME: str = os.environ.get("APP_CONTEXT_TABLE_NAME", "")
APP_CONTEXT_JSON: str = os.environ.get("APP_CONTEXT_JSON", "")

# ---------------------------------------------------------------------------
# MCP integrations
# ---------------------------------------------------------------------------
EKS_MCP_ENABLED: bool = os.environ.get("EKS_MCP_ENABLED", "").lower() == "true"

# ---------------------------------------------------------------------------
# Amazon Bedrock AgentCore Runtime
# ---------------------------------------------------------------------------
AGENT_RUNTIME_ENDPOINT_ARN: str = os.environ.get(
    "AGENT_RUNTIME_ENDPOINT_ARN", ""
)

# ---------------------------------------------------------------------------
# Amazon Bedrock Guardrails
# ---------------------------------------------------------------------------
GUARDRAIL_ID: str = os.environ.get("GUARDRAIL_ID", "")
GUARDRAIL_VERSION: str = os.environ.get("GUARDRAIL_VERSION", "DRAFT")

# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------
KMS_KEY_ARN: str = os.environ.get("KMS_KEY_ARN", "")

# ---------------------------------------------------------------------------
# Session / state
# ---------------------------------------------------------------------------
SESSION_TABLE_NAME: str = os.environ.get(
    "SESSION_TABLE_NAME", "health-triage-sessions"
)

# Phase 1: intake pipeline table names
CONSOLIDATED_TABLE_NAME: str = os.environ.get(
    "CONSOLIDATED_TABLE_NAME", "health-triage-consolidated-events"
)
IDEMPOTENCY_TABLE_NAME: str = os.environ.get(
    "IDEMPOTENCY_TABLE_NAME", "health-triage-idempotency"
)
ACCOUNT_CACHE_TABLE_NAME: str = os.environ.get(
    "ACCOUNT_CACHE_TABLE_NAME", "health-triage-account-context-cache"
)
TICKET_MAP_TABLE_NAME: str = os.environ.get(
    "TICKET_MAP_TABLE_NAME", "health-triage-ticket-map"
)
AUDIT_LOG_TABLE_NAME: str = os.environ.get(
    "AUDIT_LOG_TABLE_NAME", "health-triage-audit-log"
)
ACCOUNT_CONTEXT_TTL_HOURS: int = int(os.environ.get("ACCOUNT_CONTEXT_TTL_HOURS", "24"))

# Phase 1: Step Functions workflow ARN
TRIAGE_WORKFLOW_ARN: str = os.environ.get("TRIAGE_WORKFLOW_ARN", "")

# Phase -1 (working spec feat-devops-agent-enrichment, req §1b / design §3.0):
# settle window. AWS Health's organizational-view feed delivers one message
# per (affectedAccount, page) for a single AWS update, all within seconds of
# each other. The Intake Lambda merges every message into ConsolidatedEvents
# immediately, but defers starting the TriageWorkflow execution until
# INTAKE_SETTLE_SECONDS have elapsed since the last message for that
# (eventArn, lastUpdatedTime) — via a delay SQS queue (SETTLE_QUEUE_URL) and
# a tiny settle-consumer Lambda — so the workflow always reads a settled
# record with every account already merged in, rather than racing the
# fan-out. Default 60s: AWS fan-out for one update completes in seconds.
INTAKE_SETTLE_SECONDS: int = int(os.environ.get("INTAKE_SETTLE_SECONDS", "60"))
SETTLE_QUEUE_URL: str = os.environ.get("SETTLE_QUEUE_URL", "")

# Phase A (working spec feat-devops-agent-enrichment, req E7 / design §3.6,
# task 8/task 12): the S3 event-snapshot bucket. The Intake Lambda writes
# the full consolidated event (all pages, all entities, full description)
# here on every create/update, keyed by a hash of eventArn (never the raw
# ARN — it contains ':'/'/' characters unsafe in an S3 key) plus
# lastUpdatedTime. The investigating Agent Space's role is granted
# s3:GetObject on this bucket only (infra/lib/constructs/devops-agent-
# space.ts, task 9) so it can read beyond what the webhook's title/
# description fields carry.
EVENT_SNAPSHOT_BUCKET: str = os.environ.get("EVENT_SNAPSHOT_BUCKET", "")
# R14.1's 400-day retention, enforced via the bucket's own S3 lifecycle
# policy (task 8) — this config value documents that policy's duration for
# any code that needs to reason about it, but the CDK-provisioned lifecycle
# rule is the actual enforcement mechanism, not this Python constant.
EVENT_HISTORY_RETENTION_DAYS: int = int(os.environ.get("EVENT_HISTORY_RETENTION_DAYS", "400"))
# E1.1: which classifications are eligible for a deadline-class enrichment
# investigation. Comma-separated in the environment variable; parsed into a
# tuple here so callers get a ready-to-use collection. Mirrors
# src/devops_agent/gate.py's _ENRICHMENT_ELIGIBLE_CLASSIFICATIONS module
# constant (kept separate and not read from this config value, per that
# module's own docstring — decide_investigation() stays pure/config-free;
# this value is for callers, such as the Step Functions workflow's Choice
# conditions, that DO want the configurable set).
ENRICHMENT_CLASSES: tuple[str, ...] = tuple(
    c.strip()
    for c in os.environ.get(
        "ENRICHMENT_CLASSES", "BREAKING_CHANGE,SECURITY_RELATED,COST_IMPLICATION"
    ).split(",")
    if c.strip()
)

# ---------------------------------------------------------------------------
# Observability
# ---------------------------------------------------------------------------
LOG_LEVEL: str = os.environ.get("LOG_LEVEL", "INFO")

# ---------------------------------------------------------------------------
# Phase 2: Classification Lambda + triage precision tools
# ---------------------------------------------------------------------------
CLASSIFIER_FUNCTION_NAME: str = os.environ.get(
    "CLASSIFIER_FUNCTION_NAME", "health-triage-classifier"
)
EVENT_TYPE_GUIDANCE_PATH: str = os.environ.get("EVENT_TYPE_GUIDANCE_PATH", "")
DISPOSITION_OVERRIDES_PATH: str = os.environ.get("DISPOSITION_OVERRIDES_PATH", "")

# Urgency thresholds (days)
URGENCY_CRITICAL_DAYS: int = int(os.environ.get("URGENCY_CRITICAL_DAYS", "7"))
URGENCY_HIGH_DAYS: int = int(os.environ.get("URGENCY_HIGH_DAYS", "30"))
URGENCY_MEDIUM_DAYS: int = int(os.environ.get("URGENCY_MEDIUM_DAYS", "90"))

# ---------------------------------------------------------------------------
# Phase 3: Impact inventory + cost projection
# ---------------------------------------------------------------------------
PRICE_LIST_API_REGION: str = os.environ.get("PRICE_LIST_API_REGION", "us-east-1")
PRICING_CACHE_TTL_SECONDS: int = int(os.environ.get("PRICING_CACHE_TTL_SECONDS", str(7 * 24 * 60 * 60)))
PRICING_OVERRIDES_PATH: str = os.environ.get("PRICING_OVERRIDES_PATH", "")
VCPU_MAP_PATH: str = os.environ.get("VCPU_MAP_PATH", "")
READINESS_HORIZON_DAYS: int = int(os.environ.get("READINESS_HORIZON_DAYS", "90"))

# ---------------------------------------------------------------------------
# Phase 4: digest + prechecks
# ---------------------------------------------------------------------------
DIGEST_WATERMARK_TABLE_NAME: str = os.environ.get(
    "DIGEST_WATERMARK_TABLE_NAME", "health-triage-digest-watermark"
)
DIGEST_TOPIC_ARN: str = os.environ.get("DIGEST_TOPIC_ARN", "")
DIGEST_SCHEDULE: str = os.environ.get("DIGEST_SCHEDULE", "cron(0 8 * * ? *)")  # 08:00 UTC daily

# ---------------------------------------------------------------------------
# Phase 5: routing + ticket sinks
# ---------------------------------------------------------------------------
ROUTING_TABLE_PATH: str = os.environ.get("ROUTING_TABLE_PATH", "")

# JiraSink
JIRA_BASE_URL: str = os.environ.get("JIRA_BASE_URL", "")
JIRA_SECRET_ARN: str = os.environ.get("JIRA_SECRET_ARN", "")
JIRA_DEFAULT_PROJECT: str = os.environ.get("JIRA_DEFAULT_PROJECT", "PLATOPS")
JIRA_RESOLVED_TRANSITION_ID: str = os.environ.get("JIRA_RESOLVED_TRANSITION_ID", "31")

# SlackSink
SLACK_SECRET_ARN: str = os.environ.get("SLACK_SECRET_ARN", "")

# TeamsSink
TEAMS_SECRET_ARN: str = os.environ.get("TEAMS_SECRET_ARN", "")

# ---------------------------------------------------------------------------
# Phase 1b: AWS DevOps Agent incident gate
# ---------------------------------------------------------------------------
AGENT_SPACE_REGISTRY_PATH: str = os.environ.get("AGENT_SPACE_REGISTRY_PATH", "")
TASK_TOKEN_TABLE_NAME: str = os.environ.get(
    "TASK_TOKEN_TABLE_NAME", "health-triage-devops-agent-task-tokens"
)
AGENT_SPACE_COUNTERS_TABLE_NAME: str = os.environ.get(
    "AGENT_SPACE_COUNTERS_TABLE_NAME", "health-triage-devops-agent-counters"
)
ACTIVE_INVESTIGATIONS_TABLE_NAME: str = os.environ.get(
    "ACTIVE_INVESTIGATIONS_TABLE_NAME", "health-triage-devops-agent-active-investigations"
)
DEVOPS_AGENT_WAIT_TIMEOUT_MINUTES: int = int(
    os.environ.get("DEVOPS_AGENT_WAIT_TIMEOUT_MINUTES", "55")
)
DEVOPS_AGENT_DEDUPE_WINDOW_MINUTES: int = int(
    os.environ.get("DEVOPS_AGENT_DEDUPE_WINDOW_MINUTES", "60")
)
JOURNAL_POLL_FALLBACK_ENABLED: bool = (
    os.environ.get("JOURNAL_POLL_FALLBACK_ENABLED", "false").lower() == "true"
)
# The Agent Space (and therefore the aidevops endpoint queried for journal
# records) may live in a different Region than this Lambda. Empty string
# means "use AWS_REGION" (same-region deployment).
DEVOPS_AGENT_REGION: str = os.environ.get("DEVOPS_AGENT_REGION", "")

# ---------------------------------------------------------------------------
# Phase 5b: AWS DevOps Agent readiness gate
# ---------------------------------------------------------------------------
DEVOPS_AGENT_READINESS_WAIT_TIMEOUT_HOURS: int = int(
    os.environ.get("DEVOPS_AGENT_READINESS_WAIT_TIMEOUT_HOURS", "24")
)
READINESS_ASSESSMENTS_TABLE_NAME: str = os.environ.get(
    "READINESS_ASSESSMENTS_TABLE_NAME", "health-triage-devops-agent-readiness-assessments"
)
