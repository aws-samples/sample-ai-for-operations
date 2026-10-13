# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Precision tool: decide_readiness.

Deterministically decides whether a deadline-class health event is eligible
for an AWS DevOps Agent readiness assessment (R12.3, R12.4, R12.8). Pure
code — no model call, no AWS call, never raises. Callers supply the
registry entry, counters, and prior-assessment record already
resolved/read; this function only applies the gate logic.

Kept separate from src.devops_agent.gate.decide_investigation (the incident
gate): R12.3's criteria have no incident-gate analogue (per-account
tracking, "status-only update never re-triggers, grown affected set may"),
and merging the two would complicate the already-tested incident gate's
order for a feature not every deployment enables.

"Forced change" interpretation: this codebase has no forced/advisory
classifier signal (confirmed against classification_result_v1.json, which
carries only classification/reason/deadline/deadline_basis/
verification_steps/notes_for_operator). "Forced" is read as "carries a
deadline" for BREAKING_CHANGE, mirroring SECURITY_RELATED's own
deadline-gated clause in the same R12.3 sentence — see the master spec's
requirements.md R12.3 for the full rationale. A future change adding a
genuine forced/advisory classifier signal should replace this
deadline-presence proxy.

Gate order (first matching skip wins):
  1. No matching Agent Space in the registry                 -> skip: no_registry
  2. Registry entry has readinessEnabled=false                 -> skip: disabled
  3. Classification/deadline ineligible, or deadline            -> skip: not_eligible
     outside READINESS_HORIZON_DAYS
  4. No un-assessed accounts remain (already covered)            -> skip: already_assessed
  5. Monthly readiness cap reached for this Agent Space           -> skip: cap_exceeded
  6. Otherwise                                                    -> trigger

(Corrected 2026-09-28, working spec feat-devops-agent-enrichment E4.2 /
design §3.2, task 4: step 3's "impact confirmed" precondition is REMOVED.
Under Stage 1's enrichment redesign, impact is discovered BY the same
investigation this decision is about triggering — not known before it, the
way the old two-investigation design's readiness gate assumed. Requiring
`impact_status == "confirmed"` before even asking the readiness question
would make it unreachable for any event whose account has no covered Agent
Space, or whose impact locus is `dependent` (never `confirmed` from the
entity list alone) — cases the old design never had to consider, because
impact was always resolved via a role-assumed lookup before readiness ever
ran. Eligibility is unchanged otherwise: classification, deadline, deadline
horizon, prior-assessment set-difference, and the monthly cap all apply
exactly as before.)
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

_ELIGIBLE_CLASSIFICATIONS = ("BREAKING_CHANGE", "SECURITY_RELATED")


def _parse_deadline(deadline_str: str) -> date | None:
    """Parses an ISO 8601 YYYY-MM-DD deadline string. Returns None on failure."""
    try:
        return datetime.strptime(deadline_str, "%Y-%m-%d").date()
    except (ValueError, TypeError):
        return None


def decide_readiness(
    event: dict,
    classification_result: dict,
    impact_summary: dict,
    registry_entry: dict | None,
    counters: dict,
    prior_assessment: dict,
    *,
    horizon_days: int = 90,
    today: date | None = None,
) -> dict:
    """Decide whether to trigger an AWS DevOps Agent readiness assessment.

    Args:
        event: A health_event_v1-shaped dict (used only for logging context;
            no native field drives eligibility here — classification_result
            and impact_summary do).
        classification_result: The Phase 2 ClassificationResult v1 dict
            ({"classification": str, "deadline": str | None, ...}).
        impact_summary: R8's build_impact_inventory() output
            ({"impact_status": str, "by_account": dict[str, dict], ...}).
            Only "by_account" is consulted (for the per-account
            set-difference against prior_assessment) — "impact_status" is
            NOT gated on since the 2026-09-28 correction above; impact is
            discovered by the same investigation this decision triggers,
            not known before it.
        registry_entry: The AgentSpaceRegistry entry resolved by
            resolve_agent_space(), or None if unmatched.
        counters: {"readiness_count_this_month": int, "cap": int}.
        prior_assessment: {"assessed_accounts": list[str]} — account IDs
            that already have a readiness assessment for this event, from
            readiness_tracker.has_prior_assessment().
        horizon_days: READINESS_HORIZON_DAYS (default 90, config-driven by
            the caller — this function stays pure and doesn't read config).
        today: Injectable "now" date for deterministic tests. Defaults to
            the real current UTC date.

    Returns:
        {"trigger": bool, "reason": str, "accounts_to_assess": list[str],
         "skip_kind": "no_registry"|"disabled"|"not_eligible"|
                      "already_assessed"|"cap_exceeded"|None}
    """
    today = today or datetime.now(timezone.utc).date()

    if registry_entry is None:
        return {
            "trigger": False,
            "reason": "no matching Agent Space in registry",
            "accounts_to_assess": [],
            "skip_kind": "no_registry",
        }

    if not registry_entry.get("readinessEnabled"):
        return {
            "trigger": False,
            "reason": "readiness assessments are not enabled for this Agent Space",
            "accounts_to_assess": [],
            "skip_kind": "disabled",
        }

    classification = classification_result.get("classification", "")
    deadline_str = classification_result.get("deadline")

    if classification not in _ELIGIBLE_CLASSIFICATIONS or not deadline_str:
        return {
            "trigger": False,
            "reason": (
                f"classification={classification!r} with deadline={deadline_str!r} "
                "is not eligible for a readiness assessment"
            ),
            "accounts_to_assess": [],
            "skip_kind": "not_eligible",
        }

    deadline = _parse_deadline(deadline_str)
    if deadline is None:
        return {
            "trigger": False,
            "reason": f"deadline {deadline_str!r} could not be parsed as YYYY-MM-DD",
            "accounts_to_assess": [],
            "skip_kind": "not_eligible",
        }

    if deadline - today > timedelta(days=horizon_days) or deadline < today:
        return {
            "trigger": False,
            "reason": f"deadline {deadline_str!r} is outside the {horizon_days}-day readiness horizon",
            "accounts_to_assess": [],
            "skip_kind": "not_eligible",
        }

    all_accounts = set(impact_summary.get("by_account", {}).keys())
    assessed_accounts = set(prior_assessment.get("assessed_accounts", []))
    accounts_to_assess = sorted(all_accounts - assessed_accounts)

    if not accounts_to_assess:
        return {
            "trigger": False,
            "reason": "every affected account already has a readiness assessment for this event",
            "accounts_to_assess": [],
            "skip_kind": "already_assessed",
        }

    count = counters.get("readiness_count_this_month", 0)
    cap = counters.get("cap", 0)
    if count >= cap:
        return {
            "trigger": False,
            "reason": f"monthly readiness cap reached ({count}/{cap})",
            "accounts_to_assess": [],
            "skip_kind": "cap_exceeded",
        }

    return {
        "trigger": True,
        "reason": "eligible",
        "accounts_to_assess": accounts_to_assess,
        "skip_kind": None,
    }
