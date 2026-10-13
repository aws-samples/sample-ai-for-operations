# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Application context enrichment tool.

Retrieves application-level context (trust store, deployment info) for
affected accounts. Reads from a DynamoDB table (APP_CONTEXT_TABLE_NAME)
or falls back to a JSON config in the APP_CONTEXT_JSON environment variable.

If neither is configured, returns an empty context indicating the data
source is not available (impact_status will be "unconfirmed").
"""

from __future__ import annotations

import json
import logging

from strands import tool

from src import config

logger = logging.getLogger(__name__)


def _load_from_dynamodb(account_id: str) -> dict | None:
    """Attempt to load application context from DynamoDB.

    Table schema: partition key = "account_id" (string).
    Returns the item dict or None if table is not configured or item not found.
    """
    table_name = config.APP_CONTEXT_TABLE_NAME
    if not table_name:
        return None

    try:
        import boto3
        dynamodb = boto3.resource("dynamodb", region_name=config.AWS_REGION)
        table = dynamodb.Table(table_name)
        response = table.get_item(Key={"account_id": account_id})
        item = response.get("Item")
        if item:
            logger.info(json.dumps({
                "message": "Application context loaded from DynamoDB",
                "account_id": account_id,
                "table_name": table_name,
            }))
            return item
    except Exception as exc:
        logger.warning(json.dumps({
            "message": "Failed to load application context from DynamoDB",
            "account_id": account_id,
            "error": str(exc),
        }))
    return None


def _load_from_env(account_id: str) -> dict | None:
    """Attempt to load application context from APP_CONTEXT_JSON env var.

    The env var should contain a JSON object keyed by account_id.
    """
    raw = config.APP_CONTEXT_JSON
    if not raw:
        return None

    try:
        all_contexts = json.loads(raw)
        if account_id in all_contexts:
            logger.info(json.dumps({
                "message": "Application context loaded from APP_CONTEXT_JSON",
                "account_id": account_id,
            }))
            return all_contexts[account_id]
    except (json.JSONDecodeError, TypeError) as exc:
        logger.warning(json.dumps({
            "message": "Failed to parse APP_CONTEXT_JSON",
            "error": str(exc),
        }))
    return None


@tool
def get_account_application_trust_store(account_id: str) -> dict:
    """Retrieve application trust store and deployment context for a given account.

    Returns application-level details including trust store contents, trust store
    type/path, and deployment information so the agent can generate exact
    deployable remediation commands.

    Data sources (checked in order):
    1. DynamoDB table (APP_CONTEXT_TABLE_NAME env var)
    2. Static JSON config (APP_CONTEXT_JSON env var)
    3. Empty response (indicates data source not configured)

    Args:
        account_id: The AWS account ID to look up.

    Returns:
        A dict with account_id, trust_store (list of CAs), and applications
        (list of application details with trust store and deployment info).
        Returns empty trust_store and applications if no data source is configured.
    """
    # Try DynamoDB first
    context = _load_from_dynamodb(account_id)
    if context:
        return context

    # Try static JSON config
    context = _load_from_env(account_id)
    if context:
        return context

    # No data source configured — return empty context
    logger.info(json.dumps({
        "message": "No application context data source configured",
        "account_id": account_id,
        "hint": "Set APP_CONTEXT_TABLE_NAME or APP_CONTEXT_JSON to enable trust store lookups",
    }))
    return {
        "account_id": account_id,
        "trust_store": [],
        "applications": [],
    }
