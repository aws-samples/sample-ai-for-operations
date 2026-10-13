# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Precision tool: build_impact_inventory.

Aggregates affected entities and service-specific inventory lookups into a
single ImpactInventory dict, broken down by account and Environment_Type, and
sets Impact_Status. Pure code — no AWS calls, no model call.

Impact_Status (R8.3, corrected 2026-09-28 per working spec
feat-devops-agent-enrichment req §1a / design §3.1, task 0b):

Before this change, impact_status derived ONLY from `lookups` and ignored
the event's own `entities` list entirely — so when a lookup failed (or,
after Phase A, when no enrichment investigation ran), an event AWS itself
confirmed by listing 11 affected entities was reported `unverifiable`,
throwing away the strongest evidence available. This was a real,
pre-existing defect (not a design choice), found while designing the
enrichment change but independent of it.

The corrected derivation reads the event's own entity list as PRIMARY
evidence, qualified by the event type's impact locus
(get_impact_locus(eventTypeCode) — "listed_resource" or "dependent", see
src/tools/get_event_type_guidance.py):

  locus = get_impact_locus(eventTypeCode)
  entities_present = entities is non-empty
  verified_by_enrichment = any lookup carries dependents_verified: true

  if verified_by_enrichment:                          confirmed | not_detected
                                                       (on the lookups' own
                                                       evidence — the ONLY
                                                       path that can MOVE a
                                                       `dependent` event's
                                                       status)
  elif entities_present and locus == "listed_resource": confirmed
  elif entities_present and locus == "dependent":       in_scope_unverified
                                                        (NEW value — never
                                                        confirmed from
                                                        entities alone)
  elif lookups ran and returned resource data:          confirmed
                                                        (unchanged from
                                                        before this fix, for
                                                        callers with no
                                                        entities but real
                                                        lookup data)
  elif lookups ran and returned nothing (no error):     not_detected
  else (no entities, lookups absent or errored):        unverifiable
                                                        (original meaning,
                                                        now only reached
                                                        when there is
                                                        genuinely no
                                                        evidence of any kind)

Why `dependent` needs its own status value and not just `unverifiable`:
`unverifiable` says "we don't know what's affected." For a Keyspaces CA
rotation, AWS told us exactly which tables are in scope — collapsing that
to `unverifiable` throws away the table list; calling it `confirmed` alarms
a team whose clients already trust the new CA. `in_scope_unverified` keeps
both facts: here are the in-scope resources, and here is what to check on
the CLIENT side.
"""

from __future__ import annotations

from src.tools.get_event_type_guidance import get_impact_locus

CONFIRMED = "confirmed"
NOT_DETECTED = "not_detected"
UNVERIFIABLE = "unverifiable"
IN_SCOPE_UNVERIFIED = "in_scope_unverified"

_LISTED_RESOURCE = "listed_resource"
_DEPENDENT = "dependent"

_DEFAULT_VERIFICATION_STEPS = [
    "Review the affected resources listed in the AWS Health Dashboard for this event.",
    "Manually verify resource versions and configuration against the notification details.",
    "Re-run the triage workflow once read access to the affected account is confirmed.",
]

_DEPENDENT_VERIFICATION_STEPS = [
    "This event lists resources that are IN SCOPE, but confirmed impact depends on your " +
    "application's client-side configuration, which AWS cannot see.",
    "Check each connecting workload's trust store, negotiated TLS version, and SDK/runtime " +
    "version against the requirements named in the event description.",
    "If every caller already meets the new requirement, this event has no impact despite the " +
    "listed resources; if any caller does not, that caller will lose connectivity at the deadline.",
]


def _account_environment(account_id: str, account_contexts: list[dict]) -> str:
    """Look up Environment_Type for an account from the account_contexts list."""
    for ctx in account_contexts:
        if ctx.get("account_id") == account_id:
            return ctx.get("environment_type", "unknown")
    return "unknown"


def build_impact_inventory(
    entities: list[dict],
    lookups: list[dict],
    account_contexts: list[dict] | None = None,
    event_type_code: str = "",
) -> dict:
    """Aggregate inventory lookups into an ImpactInventory result.

    Args:
        entities: The event's affectedEntities (from the consolidated event),
            each a dict with at least 'entityValue' and optionally 'accountId'.
        lookups: List of lookup result dicts. Each lookup dict may contain
            an 'error' key indicating the lookup failed, a
            'dependents_verified': True key (set only by
            parse_affected_resources() when the investigating agent's
            output includes '## Dependents verified: yes' — see
            src/devops_agent/affected_resources.py), or resource-specific
            keys otherwise. An 'accountId' key associates the lookup with
            an account when available.
        account_contexts: Optional list of enriched account context dicts
            (account_id, environment_type) for Environment_Type breakdown.
        event_type_code: The event's eventTypeCode, used to look up its
            impact locus (get_impact_locus()). Empty string (the default,
            e.g. for callers that predate this parameter, or synthetic
            aggregate calls with no single event type) resolves to
            "listed_resource" via get_impact_locus's own unknown-code
            default — the safe, common-case behaviour.

    Returns:
        Dict with keys:
          - impact_status: "confirmed" | "not_detected" | "unverifiable" |
            "in_scope_unverified"
          - by_account: dict of account_id -> {resources: [...], environment_type}
          - by_environment: {"production": [...], "non-production": [...], "unknown": [...]}
          - resources: flat list of all discovered resources
          - verification_steps: present (non-empty) whenever impact_status
            is "unverifiable" or "in_scope_unverified"
          - enrichment: {"ran": bool, "reason": str | None} — whether any
            enrichment lookup ran for this inventory, and if not, why
    """
    account_contexts = account_contexts or []
    locus = get_impact_locus(event_type_code)

    resources: list[dict] = []
    by_account: dict[str, dict] = {}
    by_environment: dict[str, list] = {"production": [], "non-production": [], "unknown": []}

    any_confirmed = False
    any_error = False
    any_dependents_verified = False

    for lookup in lookups:
        account_id = lookup.get("accountId", "")
        env = _account_environment(account_id, account_contexts) if account_id else "unknown"

        if lookup.get("dependents_verified") is True:
            any_dependents_verified = True

        if "error" in lookup:
            any_error = True
            continue

        # A successful lookup contributes resources. We treat any non-error
        # lookup with substantive data (beyond region/identifier/marker
        # bookkeeping) as a confirmed resource.
        resource_keys = {
            k: v for k, v in lookup.items()
            if k not in {"region", "accountId", "dependents_verified"}
        }
        if not resource_keys:
            continue

        any_confirmed = True
        resource_entry = {"account_id": account_id, **resource_keys}
        resources.append(resource_entry)

        if account_id:
            acct_bucket = by_account.setdefault(
                account_id, {"resources": [], "environment_type": env}
            )
            acct_bucket["resources"].append(resource_entry)

        by_environment.setdefault(env, [])
        by_environment[env].append(resource_entry)

    entities_present = len(entities) > 0
    # "An enrichment attempt was made" — approximated as "the caller
    # supplied at least one lookup dict," which is what the pre-fix
    # behaviour already implicitly used to distinguish not_detected (ran,
    # found nothing) from unverifiable (never ran / errored). Kept exactly
    # as before for the no-entities path; only used as an ADDITIONAL input
    # (not a replacement) on the new entity-driven paths below, where its
    # only effect is choosing the enrichment.reason wording — it never
    # changes impact_status there, since entity presence already decided
    # that per the module's decision table.
    lookups_attempted = len(lookups) > 0

    # Status derivation per the module docstring's decision table.
    enrichment_ran = lookups_attempted
    enrichment_reason: str | None = None

    if any_dependents_verified:
        # The ONLY path that can move a `dependent` event's status — the
        # agent verified the callers, so the lookups' own evidence decides,
        # exactly like the pre-existing non-locus-aware behaviour.
        status = CONFIRMED if any_confirmed else NOT_DETECTED
    elif entities_present and locus == _LISTED_RESOURCE:
        status = CONFIRMED
        if not lookups_attempted:
            enrichment_reason = "resource state not enriched"
    elif entities_present and locus == _DEPENDENT:
        status = IN_SCOPE_UNVERIFIED
        if not lookups_attempted:
            enrichment_reason = "resource state not enriched"
        else:
            enrichment_reason = "enrichment ran but did not verify dependent callers"
    elif any_confirmed:
        # No entities, but real lookup data exists (e.g. a caller supplying
        # lookups directly without an entity list) — unchanged from the
        # pre-fix behaviour for this specific case.
        status = CONFIRMED
    elif any_error:
        status = UNVERIFIABLE
        enrichment_reason = "enrichment lookup returned an error"
    elif lookups_attempted:
        # No entities, an enrichment attempt was made, it found nothing,
        # and nothing errored.
        status = NOT_DETECTED
    else:
        # No entities AND no enrichment attempt at all — "no way to
        # discover any" evidence (design §3.1's decision table; typically a
        # PUBLIC issue event with no affectedEntities and, in Phase A, no
        # covered account to enrich from). This IS a behaviour change from
        # before this fix, where entities=[], lookups=[] produced
        # not_detected — deliberately, per req §1a: not_detected implies
        # "we looked and found nothing," which overstates confidence when
        # nothing was ever looked at. unverifiable is the honest label.
        status = UNVERIFIABLE
        enrichment_reason = "no entities and no enrichment lookup ran"

    result: dict = {
        "impact_status": status,
        "by_account": by_account,
        "by_environment": by_environment,
        "resources": resources,
        "enrichment": {"ran": enrichment_ran, "reason": enrichment_reason},
    }

    if status == UNVERIFIABLE:
        result["verification_steps"] = list(_DEFAULT_VERIFICATION_STEPS)
    elif status == IN_SCOPE_UNVERIFIED:
        result["verification_steps"] = list(_DEPENDENT_VERIFICATION_STEPS)

    return result
