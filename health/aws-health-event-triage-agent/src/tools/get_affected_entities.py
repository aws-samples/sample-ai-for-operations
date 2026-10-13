# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Agent tool: get_affected_entities.

Returns the list of affected entities from the consolidated event dict passed
to the classifier. This is a pure-code data-retrieval tool — it reads from the
in-memory event dict, not from DynamoDB.

The event dict is injected at classifier invocation time so the agent does not
need a DynamoDB call during classification.
"""

from __future__ import annotations

import logging

from strands import tool

logger = logging.getLogger(__name__)

# Module-level registry: set by the classifier service before invoking the agent
_current_event: dict = {}


def set_current_event(event: dict) -> None:
    """Inject the current consolidated event for the agent to read from.

    Called by the classifier service before each agent invocation.
    """
    global _current_event
    _current_event = event


@tool
def get_affected_entities(event_arn: str) -> list:
    """Return the affected entities for the current health event.

    Reads from the consolidated event injected by the classifier service
    before this invocation. Does NOT call DynamoDB.

    Args:
        event_arn: The AWS Health event ARN (used to verify the request is
            for the current event; ignored if the in-memory event matches).

    Returns:
        List of entity dicts with keys: entityValue, entityStatus,
        lastUpdatedTime, tags. Empty list if no entities are available.
    """
    event = _current_event
    if not event:
        logger.warning("get_affected_entities: no current event injected")
        return []

    # Accept the call if the ARN matches OR if the caller omits an ARN check
    stored_arn = event.get("eventArn", "")
    if event_arn and event_arn != stored_arn:
        logger.warning(
            "get_affected_entities: requested ARN %s does not match current event %s",
            event_arn,
            stored_arn,
        )
        return []

    raw_entities = event.get("affectedEntities", {})
    # affectedEntities may be a dict (keyed by entityValue) or list
    if isinstance(raw_entities, dict):
        entities = list(raw_entities.values())
    elif isinstance(raw_entities, list):
        entities = raw_entities
    else:
        entities = []

    return [
        {
            "entityValue": e.get("entityValue", ""),
            "entityStatus": e.get("entityStatus", "UNKNOWN"),
            "lastUpdatedTime": e.get("lastUpdatedTime", ""),
            "tags": e.get("tags", {}),
        }
        for e in entities
        if isinstance(e, dict)
    ]
