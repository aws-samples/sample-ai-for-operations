# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""AWS Health notification merge / consolidation — pure functions.

Two APIs:
  1. merge_event_message(existing, message) -> dict
     Pure function. Merges a single parsed health event message into the
     current consolidated record.  Both ``existing`` (the current DB item
     or None for first write) and ``message`` (a parsed event dict) must
     be plain dicts.

  2. merge_event_message_tool(notifications) -> list (Strands @tool)
     Groups a list of notification dicts into ConsolidatedView objects.
     Kept for backward compatibility with the Phase 0 agent.

Design properties:
  - Idempotent: merge(merge(e, m), m) == merge(e, m)
  - Order-independent (for distinct accounts/entities from different pages):
    merge(merge(None, m1), m2) accounts ≅ merge(merge(None, m2), m1) accounts
"""

from __future__ import annotations

import copy
from strands import tool


# ---------------------------------------------------------------------------
# Pure merge function (Phase 1 — Intake Lambda)
# ---------------------------------------------------------------------------

def merge_event_message(existing: dict | None, message: dict) -> dict:
    """Merge a parsed health event message into the consolidated record.

    Args:
        existing: The current ConsolidatedEvents DynamoDB item, or None
            for the first message for this eventArn.
        message: A parsed health event dict from event_parser.parse_health_event().

    Returns:
        An updated ConsolidatedEvents dict. Does NOT write to DynamoDB —
        the caller is responsible for persistence.
    """
    if existing is None:
        # First message: bootstrap the record
        record: dict = {
            "eventArn": message["eventArn"],
            "service": message["service"],
            "eventTypeCode": message["eventTypeCode"],
            "eventTypeCategory": message["eventTypeCategory"],
            "eventScopeCode": message.get("eventScopeCode", "PUBLIC"),
            "statusCode": message["statusCode"],
            "region": message.get("region", ""),
            "startTime": message.get("startTime", ""),
            "endTime": message.get("endTime", ""),
            "lastUpdatedTime": message.get("lastUpdatedTime", ""),
            "communicationId": message.get("communicationId", ""),
            "actionability": message.get("actionability", ""),
            "personas": list(message.get("personas", [])),
            "eventDescription": message.get("eventDescription", ""),
            "affectedAccounts": [],
            "affectedEntities": {},  # keyed by entityValue
            "pagesReceived": set(),
            "totalPages": message.get("totalPages", 1),
            "raw": dict(message.get("raw", {})),
        }
    else:
        record = copy.deepcopy(existing)
        # Convert pagesReceived back to a set if it was serialised as list
        if isinstance(record.get("pagesReceived"), list):
            record["pagesReceived"] = set(record["pagesReceived"])
        if not isinstance(record.get("pagesReceived"), set):
            record["pagesReceived"] = set()

    # Status, description, times: latest wins (by lastUpdatedTime string compare)
    msg_ts = message.get("lastUpdatedTime", "")
    rec_ts = record.get("lastUpdatedTime", "")
    if msg_ts >= rec_ts:
        record["statusCode"] = message["statusCode"]
        if message.get("eventDescription"):
            record["eventDescription"] = message["eventDescription"]
        if message.get("endTime"):
            record["endTime"] = message["endTime"]
        record["lastUpdatedTime"] = msg_ts
        if message.get("totalPages", 1) > record.get("totalPages", 1):
            record["totalPages"] = message["totalPages"]

    # Merge affected accounts (deduplicate, order-independent)
    current_accounts: set[str] = set(record.get("affectedAccounts", []))
    for acct in message.get("affectedAccounts", []):
        current_accounts.add(acct)
    record["affectedAccounts"] = sorted(current_accounts)

    # Merge affected entities (keyed by entityValue; latest entity wins)
    entities: dict[str, dict] = dict(record.get("affectedEntities", {}))
    for entity in message.get("affectedEntities", []):
        ev = entity.get("entityValue", "")
        if not ev:
            continue
        existing_entity = entities.get(ev, {})
        existing_ts = existing_entity.get("lastUpdatedTime", "")
        if entity.get("lastUpdatedTime", "") >= existing_ts:
            entities[ev] = entity
    record["affectedEntities"] = entities

    # Track pages received
    page = message.get("page", 1)
    record["pagesReceived"].add(page)

    return record


def consolidated_to_db(record: dict) -> dict:
    """Prepare a consolidated record for DynamoDB persistence.

    Converts sets to lists (DynamoDB cannot store Python sets directly;
    use StringSet or list depending on your table design).
    """
    db_item = copy.deepcopy(record)
    if isinstance(db_item.get("pagesReceived"), set):
        db_item["pagesReceived"] = sorted(db_item["pagesReceived"])
    # affectedEntities dict → list for consistent serialisation
    if isinstance(db_item.get("affectedEntities"), dict):
        db_item["affectedEntities"] = list(db_item["affectedEntities"].values())
    return db_item


# ---------------------------------------------------------------------------
# Legacy @tool wrapper (Phase 0 backward compatibility)
# ---------------------------------------------------------------------------

def _event_key(notification: dict) -> str:
    event_type = notification.get("eventTypeCode", "")
    service = notification.get("service", "")
    if event_type and service:
        return f"{event_type}::{service}"
    return notification.get("arn", "")


def _normalize_account(acct) -> dict:
    if isinstance(acct, dict):
        return {
            "account_id": acct.get("account_id", ""),
            "account_name": acct.get("account_name", acct.get("account_id", "")),
            "environment_type": acct.get("environment_type", "unknown"),
            "affected_resources": acct.get("affected_resources", []),
        }
    return {
        "account_id": str(acct),
        "account_name": str(acct),
        "environment_type": "unknown",
        "affected_resources": [],
    }


def _build_org_impact_summary(view: dict) -> str:
    prod = view["environment_breakdown"]["production_count"]
    non_prod = view["environment_breakdown"]["non_production_count"]
    total = prod + non_prod
    service = view.get("service", "unknown service")
    event_type = view.get("eventTypeCode", "unknown event")
    return f"{event_type} affects {total} account(s) using {service} ({prod} production, {non_prod} non-production)."


@tool
def merge_event_message_tool(notifications: list) -> list:
    """Consolidate related AWS Health notifications across accounts into unified views.

    Groups notifications by the same health event (matching event type code
    and service).  Produces a ConsolidatedView per unique event with
    account-level detail, production/non-production environment breakdown,
    and an organization-wide impact summary.

    Notifications should have enriched affectedAccounts entries (dicts with
    account_id, account_name, environment_type from get_account_context).
    Plain string account IDs are also accepted as a fallback.

    Args:
        notifications: List of notification dicts, each with affectedAccounts
            enriched with account context.

    Returns:
        List of ConsolidatedView dicts.
    """
    views: dict[str, dict] = {}

    for notif in notifications:
        key = _event_key(notif)
        arn = notif.get("arn", "")
        accounts = notif.get("affectedAccounts", [])

        if key not in views:
            views[key] = {
                "event_key": key,
                "event_arns": [],
                "service": notif.get("service", ""),
                "eventTypeCode": notif.get("eventTypeCode", ""),
                "eventDescription": notif.get("eventDescription", ""),
                "affected_accounts": [],
                "environment_breakdown": {
                    "production_count": 0,
                    "non_production_count": 0,
                },
                "org_impact_summary": "",
            }

        view = views[key]
        if arn and arn not in view["event_arns"]:
            view["event_arns"].append(arn)

        desc = notif.get("eventDescription", "")
        if len(desc) > len(view["eventDescription"]):
            view["eventDescription"] = desc

        existing_ids = {a["account_id"] for a in view["affected_accounts"]}
        for acct in accounts:
            normalized = _normalize_account(acct)
            acct_id = normalized["account_id"]
            if acct_id not in existing_ids:
                view["affected_accounts"].append(normalized)
                existing_ids.add(acct_id)
                env = normalized["environment_type"]
                if env == "production":
                    view["environment_breakdown"]["production_count"] += 1
                else:
                    view["environment_breakdown"]["non_production_count"] += 1

    result = list(views.values())
    for view in result:
        view["org_impact_summary"] = _build_org_impact_summary(view)

    return result
