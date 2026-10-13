# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""AWS Health EventBridge event parser.

Parses the 'detail' field of a native aws.health EventBridge event into a
normalised dict. Unknown fields are preserved in a 'raw' key so no information
is ever silently dropped.

Schema reference: src/schemas/health_event_v1.json
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Required top-level fields per health_event_v1.json
REQUIRED_FIELDS = {"eventArn", "service", "eventTypeCode", "eventTypeCategory", "statusCode"}


class HealthEventParseError(ValueError):
    """Raised when a required field is missing or malformed."""


def _extract_description(event_description: list[dict] | None) -> str:
    """Extract the latest English description or any first description.

    Prefers the English (en) entry. Falls back to the first entry found.
    Returns empty string if the list is absent or empty.
    """
    if not event_description:
        return ""
    for entry in event_description:
        if isinstance(entry, dict) and entry.get("language", "").lower().startswith("en"):
            return entry.get("latestDescription", "")
    # Fallback: first entry regardless of language
    first = event_description[0]
    if isinstance(first, dict):
        return first.get("latestDescription", "")
    return ""


def _normalise_entities(raw_entities: list | None) -> list[dict]:
    """Normalise affectedEntities to a list of dicts keyed by entityValue."""
    if not raw_entities:
        return []
    normalised: list[dict] = []
    for e in raw_entities:
        if not isinstance(e, dict):
            continue
        normalised.append({
            "entityValue": e.get("entityValue", ""),
            "entityArn": e.get("entityArn", ""),
            "entityUrl": e.get("entityUrl", ""),
            "entityStatus": e.get("entityStatus", "UNKNOWN"),
            "lastUpdatedTime": e.get("lastUpdatedTime", ""),
            "tags": e.get("tags", {}),
        })
    return normalised


def _collect_accounts(detail: dict) -> list[str]:
    """Return a deduplicated list of affected account IDs from the event."""
    accounts: list[str] = []
    seen: set[str] = set()

    # Single org-view account (affectedAccount)
    single = detail.get("affectedAccount")
    if single and isinstance(single, str) and single not in seen:
        accounts.append(single)
        seen.add(single)

    # Legacy list field (affectedAccounts)
    for acct in detail.get("affectedAccounts", []):
        if isinstance(acct, str) and acct not in seen:
            accounts.append(acct)
            seen.add(acct)

    return accounts


def parse_health_event(event_bridge_event: dict) -> dict:
    """Parse a raw aws.health EventBridge event into a normalised health event dict.

    Accepts the full EventBridge envelope (with 'source', 'detail-type', 'detail'
    keys) OR just the 'detail' object directly. Unknown fields in 'detail' are
    preserved in a 'raw' key.

    Args:
        event_bridge_event: The raw EventBridge event dict (or just its 'detail').

    Returns:
        Normalised health event dict with keys: eventArn, service, eventTypeCode,
        eventTypeCategory, eventScopeCode, statusCode, region, startTime, endTime,
        lastUpdatedTime, communicationId, page, totalPages, affectedAccounts,
        affectedEntities, eventDescription, actionability, personas, raw.

    Raises:
        HealthEventParseError: If a required field is missing or if the input is
        not a dict.
    """
    if not isinstance(event_bridge_event, dict):
        raise HealthEventParseError(
            f"Expected a dict, got {type(event_bridge_event).__name__}"
        )

    # Accept both envelope and bare detail
    detail = event_bridge_event.get("detail", event_bridge_event)
    if not isinstance(detail, dict):
        raise HealthEventParseError(
            f"Event 'detail' must be a dict, got {type(detail).__name__}"
        )

    # Validate required fields
    missing = REQUIRED_FIELDS - detail.keys()
    if missing:
        raise HealthEventParseError(
            f"Missing required fields in health event: {sorted(missing)}"
        )

    # Known fields
    event_arn: str = detail["eventArn"]
    service: str = detail["service"]
    event_type_code: str = detail["eventTypeCode"]
    event_type_category: str = detail["eventTypeCategory"]
    event_scope_code: str = detail.get("eventScopeCode", "PUBLIC")
    status_code: str = detail["statusCode"]
    region: str = (
        detail.get("region")
        or event_bridge_event.get("region")
        or ""
    )
    start_time: str = detail.get("startTime", "")
    end_time: str = detail.get("endTime", "")
    last_updated_time: str = detail.get("lastUpdatedTime", "")
    communication_id: str = detail.get("communicationId", "")
    page: int = int(detail.get("page", 1))
    total_pages: int = int(detail.get("totalPages", 1))
    actionability: str = detail.get("actionability", "")
    personas: list[str] = detail.get("personas", [])

    affected_accounts = _collect_accounts(detail)
    affected_entities = _normalise_entities(detail.get("affectedEntities"))
    event_description = _extract_description(detail.get("eventDescription"))

    # Preserve unknown fields in 'raw'
    known_keys = {
        "eventArn", "service", "eventTypeCode", "eventTypeCategory",
        "eventScopeCode", "statusCode", "region", "startTime", "endTime",
        "lastUpdatedTime", "communicationId", "page", "totalPages",
        "affectedAccount", "affectedAccounts", "affectedEntities",
        "eventDescription", "actionability", "personas",
    }
    raw: dict = {k: v for k, v in detail.items() if k not in known_keys}

    return {
        "eventArn": event_arn,
        "service": service,
        "eventTypeCode": event_type_code,
        "eventTypeCategory": event_type_category,
        "eventScopeCode": event_scope_code,
        "statusCode": status_code,
        "region": region,
        "startTime": start_time,
        "endTime": end_time,
        "lastUpdatedTime": last_updated_time,
        "communicationId": communication_id,
        "page": page,
        "totalPages": total_pages,
        "affectedAccounts": affected_accounts,
        "affectedEntities": affected_entities,
        "eventDescription": event_description,
        "actionability": actionability,
        "personas": personas,
        "raw": raw,
    }


def is_closed(parsed_event: dict) -> bool:
    """Return True when the event has statusCode 'closed'."""
    return parsed_event.get("statusCode", "").lower() == "closed"


def idempotency_key(parsed_event: dict) -> str:
    """Return the idempotency key: eventArn#affectedAccount#lastUpdatedTime#page.

    Per-account, per-page — matching the granularity at which AWS Health's
    organizational-view feed actually delivers messages: one message per
    (affectedAccount, page) for a single AWS update, all sharing eventArn
    and lastUpdatedTime.

    The previous key, eventArn#lastUpdatedTime, was at event granularity
    only. It collapsed every account and page of one AWS update onto the
    same key, so message B for a second account (or page 2 of the same
    account's entity list) looked like a duplicate of message A and was
    silently dropped before ever reaching the merge step — see
    src/intake/service.py's _is_duplicate() check, which runs before
    merge_event_message(). This is req §1b of working spec
    feat-devops-agent-enrichment (also a master R2.1 wording correction):
    "(eventArn, lastUpdatedTime) as the idempotency key" was written at
    event granularity; the feed is at account-page granularity.

    Falls back to the first entry of affectedAccounts (the legacy list
    field) when the singular affectedAccount field is absent, so the key
    stays deterministic per message rather than collapsing to empty.
    """
    arn = parsed_event.get("eventArn", "")
    ts = parsed_event.get("lastUpdatedTime", "")
    page = parsed_event.get("page", 1)
    accounts = parsed_event.get("affectedAccounts") or []
    account = accounts[0] if accounts else ""
    return f"{arn}#{account}#{ts}#{page}"
