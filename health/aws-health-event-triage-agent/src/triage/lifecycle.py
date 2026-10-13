# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Precision tool: should_close.

Determines whether a Consolidated_Event's ticket/notification should be
closed (R8.5, R11.2). Pure code — no model call, never raises.

Close conditions (either is sufficient):
  1. The event's statusCode is 'closed' (AWS reported the event itself closed).
  2. Every affected entity has entityStatus == 'RESOLVED' (AWS reports
     per-entity resolution for some eventTypeCodes, e.g. planned lifecycle
     events where customers complete actions on individual resources).

When there are no affected entities at all, condition 2 cannot be evaluated
meaningfully — closure then relies solely on statusCode (R8.5's intent is to
close when AWS explicitly reports resolution; an empty entity list is not
itself resolution evidence).
"""

from __future__ import annotations

_RESOLVED = "RESOLVED"
_CLOSED = "closed"


def should_close(record: dict) -> bool:
    """Return True if the Consolidated_Event should be closed.

    Args:
        record: A consolidated event record with 'statusCode' and
            'affectedEntities' (dict keyed by entityValue, or list — both
            accepted for compatibility with different call sites).

    Returns:
        True when statusCode == 'closed' OR every affected entity has
        entityStatus == 'RESOLVED'. False otherwise, including when there
        are no affected entities (statusCode is the only signal in that
        case).
    """
    if record.get("statusCode", "").lower() == _CLOSED:
        return True

    raw_entities = record.get("affectedEntities", {})
    if isinstance(raw_entities, dict):
        entities = list(raw_entities.values())
    elif isinstance(raw_entities, list):
        entities = raw_entities
    else:
        entities = []

    if not entities:
        return False

    return all(
        isinstance(e, dict) and e.get("entityStatus", "").upper() == _RESOLVED
        for e in entities
    )
