# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Agent tool: get_event_type_guidance.

Returns known-semantics hints for a given AWS Health eventTypeCode loaded from
the EventTypeGuidance config JSON. Pure code — no AWS calls, no model call.

The guidance JSON is loaded once at module init from the path in
EVENT_TYPE_GUIDANCE_PATH (default: config/event-type-guidance.json). The
classifier agent uses the result as a prior; it may override it.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from strands import tool

logger = logging.getLogger(__name__)

# Config: path to the event-type guidance JSON file
_DEFAULT_GUIDANCE_PATH = Path(__file__).parents[2] / "config" / "event-type-guidance.json"

_guidance_cache: dict[str, dict] | None = None


def _load_guidance() -> dict[str, dict]:
    global _guidance_cache
    if _guidance_cache is not None:
        return _guidance_cache
    path = Path(os.environ.get("EVENT_TYPE_GUIDANCE_PATH", str(_DEFAULT_GUIDANCE_PATH)))
    try:
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
        if isinstance(data, list):
            _guidance_cache = {item["eventTypeCode"]: item for item in data if "eventTypeCode" in item}
        else:
            _guidance_cache = data
        logger.info("Loaded %d event-type guidance entries from %s", len(_guidance_cache), path)
    except Exception as exc:
        logger.warning("Could not load event-type guidance from %s: %s", path, exc)
        _guidance_cache = {}
    return _guidance_cache


@tool
def get_event_type_guidance(event_type_code: str) -> dict:
    """Return known-semantics hints for an AWS Health eventTypeCode.

    Looks up the event type code in the EventTypeGuidance config and returns
    a dict with classification hints and deadline cues. Returns an empty dict
    when no guidance entry exists for the code.

    Args:
        event_type_code: The AWS Health eventTypeCode (e.g.
            "AWS_EKS_PLANNED_LIFECYCLE_EVENT").

    Returns:
        A dict with keys: eventTypeCode, knownSemantics, defaultClassHint,
        deadlineHints, notes. Empty dict when not found.
    """
    guidance = _load_guidance()
    entry = guidance.get(event_type_code)
    if entry is None:
        return {}
    return {
        "eventTypeCode": event_type_code,
        "knownSemantics": entry.get("knownSemantics", ""),
        "defaultClassHint": entry.get("defaultClassHint", ""),
        "deadlineHints": entry.get("deadlineHints", []),
        "notes": entry.get("notes", ""),
    }


_LISTED_RESOURCE = "listed_resource"
_DEPENDENT = "dependent"
_VALID_IMPACT_LOCI = {_LISTED_RESOURCE, _DEPENDENT}


def get_impact_locus(event_type_code: str) -> str:
    """Return the impact locus for an AWS Health eventTypeCode.

    Precision config lookup (not an agent @tool — consumed by
    build_impact_inventory, a pure precision function with no LLM
    involvement, per working spec feat-devops-agent-enrichment req §1a /
    design §3.1). Reads the same config/event-type-guidance.json entries
    and cache as get_event_type_guidance() above.

    Two values are possible:
      - "listed_resource": the entity AWS lists IS the thing that breaks /
        costs / gets retired. Entity presence is itself confirmation of
        impact (e.g. Lambda runtime deprecation, RDS/EKS end-of-support).
      - "dependent": the entity AWS lists is in scope, but whether a given
        account is actually impacted depends on something AWS cannot see —
        a client's trust store, negotiated TLS version, or SDK version
        (e.g. a CA rotation, a TLS-version deprecation). Entity presence
        means "in scope, impact unverified," never "confirmed" on its own.

    Args:
        event_type_code: The AWS Health eventTypeCode.

    Returns:
        "listed_resource" or "dependent". Defaults to "listed_resource"
        when the code has no guidance entry, or when an entry exists but
        its impactLocus field is absent, empty, or not one of the two
        valid values — "listed_resource" is deliberately the safe default
        (it is the common case, and it is also the MORE cautious of the
        two failure directions: treating a genuinely-dependent event as
        listed_resource can only make impact status look more confirmed
        than warranted for a status the entity list already supports as
        evidence, never invent evidence that isn't there).
    """
    guidance = _load_guidance()
    entry = guidance.get(event_type_code)
    if entry is None:
        return _LISTED_RESOURCE
    locus = entry.get("impactLocus", "")
    if locus in _VALID_IMPACT_LOCI:
        return locus
    return _LISTED_RESOURCE
