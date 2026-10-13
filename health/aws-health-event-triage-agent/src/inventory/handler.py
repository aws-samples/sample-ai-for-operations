# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Inventory baseline + ProjectCost + MergeEnrichment Lambda handler.

Step Functions invokes this Lambda for three step types via the 'step' field:

  step == "INVENTORY_BASELINE" (working spec feat-devops-agent-enrichment
  task 11, design §3.1 steps 1-3 / §3.8):
    Input: {"eventArn", "event": <consolidated event dict>}
    Computes the entity + impact-locus baseline with NO AWS API call —
    entities come straight from the event (already delivered by AWS
    Health), and get_impact_locus(eventTypeCode) is a pure config lookup.
    Feeds the enrichment path (ResolveAgentSpaces -> Map ->
    MergeEnrichment) so it has an impactSummary/impactLocus to read
    BEFORE any investigation is triggered — the investigation enriches
    this baseline, it does not produce it (design §3.1's step 4: "emit a
    request for the enrichment investigation and STOP here"). This is the
    single inventory step after Phase B (task 15/16) retired the old
    per-service plug-in INVENTORY step and its AssumeRole grant.

  step == "PROJECT_COST":
    Input: {"eventArn", "inventory": <ImpactInventory dict>, "deadline": "..."}
    Calls project_cost() over the inventory's resources. Unchanged by this
    working spec — confirmed by diff, per design §3.1's explicit note that
    project_cost is not modified.

  step == "MERGE_ENRICHMENT" (working spec feat-devops-agent-enrichment
  task 2, design §3.1's pseudocode):
    Input: {"eventArn", "event": <consolidated event dict>,
            "analysisMarkdown": <investigation callback's full analysis
            text, or None>, "deadline": "..."}
    1. parse_affected_resources(analysisMarkdown) — the trust-boundary
       parser (src/devops_agent/affected_resources.py).
    2. On a hard parse failure: build_impact_inventory() runs with an
       'error' lookup carrying the failure reason and raw section, so the
       aggregator falls back to the entity-list/locus baseline (req §1a) —
       AWS's own evidence is never erased by a bad or missing enrichment
       output, and never upgraded past what the locus supports either.
    3. On success: build_impact_inventory() runs with
       parse_result.as_lookups() — the same lookups: list[dict] shape the
       three retired per-service plug-ins produced, so project_cost's
       per-environment breakdown and pricing logic apply unchanged.
    4. project_cost() runs over the resulting inventory — unmodified.
    5. summarize_readiness_outcome() runs over the SAME analysisMarkdown —
       one investigation now answers both impact and readiness (E4),
       instead of two separate investigations.

All steps are pure orchestration around already-tested pure functions
(build_impact_inventory, project_cost, parse_affected_resources,
summarize_readiness_outcome). None makes an AWS AssumeRole call — the
Inventory Lambda's only remaining AWS dependency is pricing (via
project_cost's pricing:GetProducts). None calls the LLM — the investigating
DevOps Agent's own LLM reasoning happened externally, before this Lambda
ever sees its output; this handler only parses that output as data. None
ever raises past the handler — any failure degrades to 'unverifiable' /
'unknown' so the workflow always proceeds to Notify.
"""

from __future__ import annotations

import json
import logging
import os

from src import config
from src.devops_agent.affected_resources import parse_affected_resources
from src.devops_agent.readiness_outcome import summarize_readiness_outcome
from src.inventory.build_impact_inventory import build_impact_inventory
from src.cost.project_cost import project_cost
from src.tools.get_event_type_guidance import get_impact_locus

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))


def _do_inventory_baseline(payload: dict) -> dict:
    """INVENTORY_BASELINE step (task 11, design §3.1 steps 1-3 / §3.8).

    Makes NO AWS API call — see this module's docstring for why. Reads the
    event's own entity list and looks up its impact locus, then calls
    build_impact_inventory() with lookups=[] (no enrichment has happened
    yet at this point in the workflow), which per req §1a's decision table
    yields:
      - entities present + listed_resource locus -> confirmed
      - entities present + dependent locus        -> in_scope_unverified
      - no entities                                -> unverifiable
    """
    event_arn = payload.get("eventArn", "")
    consolidated = payload.get("event", {})
    if isinstance(consolidated, str):
        try:
            consolidated = json.loads(consolidated)
        except json.JSONDecodeError:
            consolidated = {}

    event_type_code = consolidated.get("eventTypeCode", "")
    raw_entities = consolidated.get("affectedEntities", {})
    entities = list(raw_entities.values()) if isinstance(raw_entities, dict) else (raw_entities or [])

    impact_locus = get_impact_locus(event_type_code)
    inventory = build_impact_inventory(entities=entities, lookups=[], event_type_code=event_type_code)

    logger.info(json.dumps({
        "message": "InventoryBaseline step complete",
        "event_arn": event_arn,
        "impact_status": inventory["impact_status"],
        "impact_locus": impact_locus,
        "entity_count": len(entities),
    }))

    return {"eventArn": event_arn, "impactSummary": inventory, "impactLocus": impact_locus}


def _do_project_cost(payload: dict) -> dict:
    event_arn = payload.get("eventArn", "")
    inventory = payload.get("inventory", {})
    deadline = payload.get("deadline")

    if isinstance(inventory, str):
        try:
            inventory = json.loads(inventory)
        except json.JSONDecodeError:
            inventory = {}

    horizon = {"deadline": deadline} if deadline else None
    cost_result = project_cost(inventory, horizon=horizon)

    logger.info(json.dumps({
        "message": "ProjectCost step complete",
        "event_arn": event_arn,
        "projectable": not cost_result.get("unknown", True),
    }))

    return {"eventArn": event_arn, "costProjection": cost_result}


def _do_merge_enrichment(payload: dict) -> dict:
    """MERGE_ENRICHMENT step (task 2, design §3.1's pseudocode)."""
    event_arn = payload.get("eventArn", "")
    consolidated = payload.get("event", {})
    if isinstance(consolidated, str):
        try:
            consolidated = json.loads(consolidated)
        except json.JSONDecodeError:
            consolidated = {}

    event_type_code = consolidated.get("eventTypeCode", "")
    raw_entities = consolidated.get("affectedEntities", {})
    entities = list(raw_entities.values()) if isinstance(raw_entities, dict) else (raw_entities or [])

    analysis_markdown = payload.get("analysisMarkdown")
    deadline = payload.get("deadline")

    parse_result = parse_affected_resources(analysis_markdown)

    if parse_result.error:
        # Hard parse failure: fall back to the entity-list/locus baseline
        # (req §1a). The 'error' lookup carries the failure reason and raw
        # section so build_impact_inventory's caller can see WHY enrichment
        # didn't run, without erasing or upgrading the entity-list evidence
        # build_impact_inventory already derives independently of lookups.
        lookups = [{"error": parse_result.error, "rawSection": parse_result.raw}]
    else:
        lookups = parse_result.as_lookups()

    inventory = build_impact_inventory(
        entities=entities, lookups=lookups, event_type_code=event_type_code
    )
    # A parse failure must never be silently absorbed by
    # build_impact_inventory's own generic error-lookup handling — surface
    # the parser's specific reason and raw text on the inventory too, so
    # MERGE_ENRICHMENT's caller (and ultimately the ticket) sees exactly
    # what went wrong with the CONTRACT, not just "an error occurred."
    if parse_result.error:
        inventory["enrichment"] = {"ran": True, "reason": f"enrichment output did not match contract: {parse_result.error}"}
        inventory["rawEnrichmentSection"] = parse_result.raw

    horizon = {"deadline": deadline} if deadline else None
    cost_result = project_cost(inventory, horizon=horizon)

    readiness_summary = summarize_readiness_outcome(analysis_markdown)

    logger.info(json.dumps({
        "message": "MergeEnrichment step complete",
        "event_arn": event_arn,
        "impact_status": inventory["impact_status"],
        "parse_error": parse_result.error,
        "rows_parsed": len(parse_result.rows),
        "rows_dropped": len(parse_result.dropped_rows),
        "dependents_verified": parse_result.dependents_verified,
        "projectable": not cost_result.get("unknown", True),
    }))

    return {
        "eventArn": event_arn,
        "impactSummary": inventory,
        "costProjection": cost_result,
        "readinessFeasibility": readiness_summary["feasibility"],
        "readinessBlockers": readiness_summary["blockers"],
        "readinessRisk": readiness_summary["risk"],
        "readinessRollbackAvailable": readiness_summary["rollback_available"],
    }


def handler(event: dict, context) -> dict:
    """Lambda handler for the INVENTORY_BASELINE, PROJECT_COST, and
    MERGE_ENRICHMENT workflow steps."""
    step = event.get("step", "")

    if step == "INVENTORY_BASELINE":
        return _do_inventory_baseline(event)
    if step == "PROJECT_COST":
        return _do_project_cost(event)
    if step == "MERGE_ENRICHMENT":
        return _do_merge_enrichment(event)

    logger.warning("Unknown step '%s' in inventory handler", step)
    return {"eventArn": event.get("eventArn", ""), "error": f"Unknown step: {step}"}
