# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Precision tool: decide_investigation.

Deterministically decides whether a health event is eligible for an AWS
DevOps Agent investigation (R12.2, R12.4, R12.5, R12.8). Pure code — no
model call, no AWS call, never raises. Callers supply the registry entry,
counters, and dedupe result already resolved/read; this function only
applies the gate logic.

Gate order (first matching skip wins):
  1. No matching Agent Space in the registry              -> skip: no_registry
  2. Category/status/code not eligible (R12.2, or the      -> skip: not_eligible
     enrichment classification rule for kind="enrichment",
     design §3.2 — added 2026-09-28, working spec
     feat-devops-agent-enrichment task 3)
  3. Event scope not allowed for this Agent Space (R12.4)   -> skip: not_eligible
  4. An active investigation already covers this event      -> skip: duplicate
     (R12.5, dedupe: local_only)
  5. Monthly incident cap reached for this Agent Space      -> skip: cap_exceeded
     (R12.8)
  6. Otherwise                                              -> trigger

kind (added task 3): "incident" (default, Phase 1b's original eligibility —
issue/open events and allow-listed accountNotification codes) or
"enrichment" (deadline-class events: BREAKING_CHANGE, SECURITY_RELATED,
COST_IMPLICATION classifications, per design §3.2). The scope/dedupe/cap
rules (steps 3-5) are identical for both kinds — deadline-class enrichment
shares the same single per-space cap and dedupe record as incident
investigations (req E4.5), not a separate one.
"""

from __future__ import annotations

_ELIGIBLE_ISSUE_CATEGORY = "issue"
_ELIGIBLE_ISSUE_STATUS = "open"
_ACCOUNT_NOTIFICATION_CATEGORY = "accountNotification"

_DEFAULT_ALLOWED_SCOPES = ("ACCOUNT_SPECIFIC", "PUBLIC")

# design §3.2: classifications eligible for an "enrichment" kind
# investigation (deadline-class events). Matches config.ENRICHMENT_CLASSES'
# default (src/config.py, task 12) — kept as a plain module constant here,
# not read from config, so this precision function stays pure and testable
# without needing config.py's environment-variable state; callers that want
# the configurable set pass their own classification check upstream (the
# same "callers resolve config, this function only applies gate logic"
# pattern the rest of this module already follows for cap/dedupe).
_ENRICHMENT_ELIGIBLE_CLASSIFICATIONS = ("BREAKING_CHANGE", "SECURITY_RELATED", "COST_IMPLICATION")


def decide_investigation(
    event: dict,
    registry_entry: dict | None,
    counters: dict,
    dedupe_result: dict,
    *,
    kind: str = "incident",
    classification: str = "",
) -> dict:
    """Decide whether to trigger an AWS DevOps Agent investigation.

    Args:
        event: A health_event_v1-shaped dict. Only native fields are read:
            eventTypeCategory, statusCode, eventScopeCode, eventTypeCode.
        registry_entry: The AgentSpaceRegistry entry resolved by
            resolve_agent_space(), or None if unmatched.
        counters: {"incident_count_this_month": int, "cap": int}. The cap
            SHOULD come from registry_entry["incidentCapPerMonth"]; callers
            pass it explicitly so this function stays pure and testable
            without re-deriving it.
        dedupe_result: {"duplicate": bool, "existing_investigation_id":
            str | None} from the dedupe_check data-retrieval tool.
        kind: "incident" (default) or "enrichment" (task 3, design §3.2).
            Selects which category/status/code (or classification) rule
            gates eligibility; scope/dedupe/cap logic is identical for both.
        classification: The event's classification result (e.g.
            "BREAKING_CHANGE"), only consulted when kind="enrichment".
            Ignored for kind="incident".

    Returns:
        {"trigger": bool, "reason": str,
         "skip_kind": "no_registry"|"not_eligible"|"duplicate"|
                      "cap_exceeded"|None}
    """
    if registry_entry is None:
        return {
            "trigger": False,
            "reason": "no matching Agent Space in registry",
            "skip_kind": "no_registry",
        }

    category = event.get("eventTypeCategory", "")
    status = event.get("statusCode", "")
    scope = event.get("eventScopeCode", "")
    code = event.get("eventTypeCode", "")

    if kind == "enrichment":
        is_eligible = classification in _ENRICHMENT_ELIGIBLE_CLASSIFICATIONS
        if not is_eligible:
            return {
                "trigger": False,
                "reason": (
                    f"classification={classification!r} is not eligible for an "
                    f"enrichment investigation (eligible: {list(_ENRICHMENT_ELIGIBLE_CLASSIFICATIONS)})"
                ),
                "skip_kind": "not_eligible",
            }
    else:
        is_issue_eligible = category == _ELIGIBLE_ISSUE_CATEGORY and status == _ELIGIBLE_ISSUE_STATUS
        allowed_codes = registry_entry.get("allowedAccountNotificationCodes", []) or []
        is_notification_eligible = category == _ACCOUNT_NOTIFICATION_CATEGORY and code in allowed_codes

        if not (is_issue_eligible or is_notification_eligible):
            return {
                "trigger": False,
                "reason": (
                    f"category={category!r} status={status!r} code={code!r} "
                    "is not eligible for investigation"
                ),
                "skip_kind": "not_eligible",
            }

    allowed_scopes = registry_entry.get("allowedScopes") or list(_DEFAULT_ALLOWED_SCOPES)
    if scope not in allowed_scopes:
        return {
            "trigger": False,
            "reason": f"scope={scope!r} not in allowed scopes {allowed_scopes!r} for this Agent Space",
            "skip_kind": "not_eligible",
        }

    if dedupe_result.get("duplicate"):
        existing_id = dedupe_result.get("existing_investigation_id")
        return {
            "trigger": False,
            "reason": f"active investigation {existing_id!r} already covers this event",
            "skip_kind": "duplicate",
        }

    count = counters.get("incident_count_this_month", 0)
    cap = counters.get("cap", 0)
    if count >= cap:
        return {
            "trigger": False,
            "reason": f"monthly incident cap reached ({count}/{cap})",
            "skip_kind": "cap_exceeded",
        }

    return {"trigger": True, "reason": "eligible", "skip_kind": None}
