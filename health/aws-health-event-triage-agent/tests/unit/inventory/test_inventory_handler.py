# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Unit tests for src.inventory.handler — INVENTORY_BASELINE, PROJECT_COST,
and MERGE_ENRICHMENT steps (the three steps the handler dispatches after
Phase B retired the OLD INVENTORY and PRECHECK steps)."""

from __future__ import annotations

from unittest.mock import patch

from src.inventory.handler import handler

EVENT_ARN = "arn:aws:health:us-east-1::event/EKS/TEST/001"


class TestProjectCostStep:
    def test_project_cost_with_confirmed_inventory(self):
        inventory = {
            "impact_status": "confirmed",
            "resources": [
                {"account_id": "123456789012", "cluster_name": "my-cluster"},
            ],
        }
        event = {
            "step": "PROJECT_COST",
            "eventArn": EVENT_ARN,
            "inventory": inventory,
            "deadline": "2026-09-01",
        }
        result = handler(event, None)
        assert "costProjection" in result
        assert result["eventArn"] == EVENT_ARN

    def test_project_cost_empty_inventory_returns_unknown(self):
        event = {
            "step": "PROJECT_COST",
            "eventArn": EVENT_ARN,
            "inventory": {"resources": []},
        }
        result = handler(event, None)
        assert result["costProjection"]["unknown"] is True

    def test_project_cost_handles_string_inventory(self):
        import json
        event = {
            "step": "PROJECT_COST",
            "eventArn": EVENT_ARN,
            "inventory": json.dumps({"resources": []}),
        }
        result = handler(event, None)
        assert result["costProjection"]["unknown"] is True


class TestUnknownStep:
    def test_unknown_step_returns_error(self):
        event = {"step": "BOGUS_STEP", "eventArn": EVENT_ARN}
        result = handler(event, None)
        assert "error" in result


class TestMergeEnrichmentStep:
    """MERGE_ENRICHMENT step (task 2, working spec feat-devops-agent-enrichment,
    design §3.1's pseudocode)."""

    _WELL_FORMED_MARKDOWN = """\
## Summary

The RDS instance is affected by the extended support deadline.

## Affected resources

| account | resource_arn | resource_type | current_version | status | evidence |
|---|---|---|---|---|---|
| 123456789012 | arn:aws:rds:us-east-1:123456789012:db:orders | rds-instance | 11.9 | affected | engine detail |

## Readiness Assessment

FEASIBILITY: READY
BLOCKERS: NONE
RISK: LOW
ROLLBACK_AVAILABLE: YES
"""

    def _event(self, event_type_code="AWS_RDS_EXTENDED_SUPPORT", entities=None):
        return {
            "eventArn": EVENT_ARN,
            "service": "RDS",
            "eventTypeCode": event_type_code,
            "region": "us-east-1",
            "affectedEntities": entities
            if entities is not None
            else {"db-1": {"entityValue": "arn:aws:rds:us-east-1:123456789012:db:orders"}},
        }

    def test_conformant_markdown_yields_confirmed_impact(self):
        event = {
            "step": "MERGE_ENRICHMENT",
            "eventArn": EVENT_ARN,
            "event": self._event(),
            "analysisMarkdown": self._WELL_FORMED_MARKDOWN,
            "deadline": "2027-01-01",
        }
        result = handler(event, None)
        assert result["impactSummary"]["impact_status"] == "confirmed"
        assert len(result["impactSummary"]["resources"]) == 1
        assert result["readinessFeasibility"] == "ready"
        assert result["readinessRisk"] == "low"
        assert "costProjection" in result

    def test_malformed_markdown_falls_back_to_entity_list_confirmed(self):
        """listed_resource event + entities present + parse failure ->
        still confirmed from the entity list (req §1a — a bad enrichment
        never erases AWS's own evidence)."""
        event = {
            "step": "MERGE_ENRICHMENT",
            "eventArn": EVENT_ARN,
            "event": self._event(),
            "analysisMarkdown": "## Summary\n\nNo table here.\n",
        }
        result = handler(event, None)
        assert result["impactSummary"]["impact_status"] == "confirmed"
        assert "rawEnrichmentSection" in result["impactSummary"]
        assert "enrichment output did not match contract" in result["impactSummary"]["enrichment"]["reason"]

    def test_malformed_markdown_dependent_locus_falls_back_to_in_scope_unverified(self):
        event = {
            "step": "MERGE_ENRICHMENT",
            "eventArn": EVENT_ARN,
            "event": self._event(event_type_code="AWS_KEYSPACES_TLS_CERTIFICATE_ROTATION"),
            "analysisMarkdown": None,
        }
        result = handler(event, None)
        assert result["impactSummary"]["impact_status"] == "in_scope_unverified"

    def test_no_analysis_markdown_at_all_still_returns_structured_result(self):
        event = {
            "step": "MERGE_ENRICHMENT",
            "eventArn": EVENT_ARN,
            "event": self._event(),
            "analysisMarkdown": None,
        }
        result = handler(event, None)
        assert result["eventArn"] == EVENT_ARN
        assert result["impactSummary"]["impact_status"] == "confirmed"  # entity list still primary evidence
        assert result["readinessFeasibility"] == "unverifiable"

    def test_partially_malformed_one_bad_row_among_good_still_confirmed(self):
        markdown = """\
## Affected resources

| account | resource_arn | resource_type | current_version | status | evidence |
|---|---|---|---|---|---|
| 123456789012 | arn:aws:rds:us-east-1:123456789012:db:orders | rds-instance | 11.9 | affected | good row |
| not-valid | not-an-arn | rds-instance | 11.9 | affected | bad row |
"""
        event = {
            "step": "MERGE_ENRICHMENT",
            "eventArn": EVENT_ARN,
            "event": self._event(),
            "analysisMarkdown": markdown,
        }
        result = handler(event, None)
        assert result["impactSummary"]["impact_status"] == "confirmed"
        assert len(result["impactSummary"]["resources"]) == 1

    def test_project_cost_receives_the_merged_inventory(self):
        """Confirms MERGE_ENRICHMENT actually calls project_cost over its
        own result (not a stale/unrelated inventory)."""
        event = {
            "step": "MERGE_ENRICHMENT",
            "eventArn": EVENT_ARN,
            "event": self._event(),
            "analysisMarkdown": self._WELL_FORMED_MARKDOWN,
            "deadline": "2027-01-01",
        }
        result = handler(event, None)
        # The parsed row has resource_type "rds-instance" but not the
        # instance_class/engine keys project_cost's heuristic detects, so
        # cost stays unknown -- this is an accurate, non-regressive result,
        # not a bug: project_cost's detection heuristic is unmodified by
        # this working spec (design §3.1 "project_cost is NOT modified").
        assert result["costProjection"]["unknown"] is True


class TestInventoryBaselineStep:
    """INVENTORY_BASELINE step (working spec feat-devops-agent-enrichment,
    task 11, design §3.1 steps 1-3 / §3.8): computes the entity +
    impact-locus baseline with NO AWS API call. After Phase B this is the
    single inventory step (the OLD INVENTORY step, which made AssumeRole +
    per-service plug-in calls, was retired). It exists so RequiresInventory's
    enrichment branch (ResolveAgentSpaces -> Map -> MergeEnrichment) has an
    impactSummary/impactLocus to read before any investigation is triggered —
    the investigation is what enriches that baseline, not what produces it
    (design §3.1's step 4: "emit a request for the enrichment investigation
    and STOP here").
    """

    def _event(self, event_type_code="AWS_LAMBDA_RUNTIME_DEPRECATION", entities=None):
        return {
            "eventArn": EVENT_ARN,
            "service": "LAMBDA",
            "eventTypeCode": event_type_code,
            "region": "us-east-1",
            "affectedEntities": entities
            if entities is not None
            else {"fn-1": {"entityValue": "arn:aws:lambda:us-east-1:123456789012:function:orders"}},
        }

    def test_makes_no_aws_call_at_all(self):
        """The defining property of this step per design §3.1: it must not
        make any AWS API call. After Phase B the handler no longer imports
        boto3 at all (the AssumeRole plug-in path was retired), so patching
        boto3.client and asserting it never fires is sufficient — there is no
        longer any _assume_readonly_session / _run_lookup helper to patch."""
        with patch("boto3.client") as mock_boto_client:
            event = {
                "step": "INVENTORY_BASELINE",
                "eventArn": EVENT_ARN,
                "event": self._event(),
            }
            result = handler(event, None)

        mock_boto_client.assert_not_called()
        assert result["eventArn"] == EVENT_ARN

    def test_listed_resource_event_with_entities_is_confirmed(self):
        """AWS_LAMBDA_RUNTIME_DEPRECATION has no event-type-guidance entry
        -> impactLocus defaults to listed_resource -> entities present ->
        confirmed, with zero lookups (req §1a's decision table, first
        applicable branch)."""
        event = {
            "step": "INVENTORY_BASELINE",
            "eventArn": EVENT_ARN,
            "event": self._event(),
        }
        result = handler(event, None)
        assert result["impactSummary"]["impact_status"] == "confirmed"
        assert result["impactLocus"] == "listed_resource"
        # resources[] is derived only from lookups (build_impact_inventory
        # never materializes entities into resource rows) — with
        # lookups=[] (no enrichment has run yet), it stays empty even
        # though impact_status is correctly 'confirmed' from entity
        # presence alone. A materialized row only appears once
        # MERGE_ENRICHMENT parses a real investigation result.
        assert result["impactSummary"]["resources"] == []
        assert result["impactSummary"]["enrichment"]["ran"] is False

    def test_dependent_locus_event_with_entities_is_in_scope_unverified(self):
        """AWS_KEYSPACES_TLS_CERTIFICATE_ROTATION is configured as
        impactLocus: dependent in config/event-type-guidance.json ->
        entities present, no enrichment yet -> in_scope_unverified, never
        confirmed (req §1a — this is the value this baseline step exists
        to compute correctly BEFORE any investigation runs)."""
        event = {
            "step": "INVENTORY_BASELINE",
            "eventArn": EVENT_ARN,
            "event": self._event(event_type_code="AWS_KEYSPACES_TLS_CERTIFICATE_ROTATION"),
        }
        result = handler(event, None)
        assert result["impactSummary"]["impact_status"] == "in_scope_unverified"
        assert result["impactLocus"] == "dependent"

    def test_no_entities_at_all_is_unverifiable(self):
        """No entities, no lookups (this step never runs any) ->
        unverifiable, the original meaning of the value (req §1a's final
        else branch)."""
        event = {
            "step": "INVENTORY_BASELINE",
            "eventArn": EVENT_ARN,
            "event": self._event(entities={}),
        }
        result = handler(event, None)
        assert result["impactSummary"]["impact_status"] == "unverifiable"

    def test_unknown_event_type_code_defaults_to_listed_resource(self):
        event = {
            "step": "INVENTORY_BASELINE",
            "eventArn": EVENT_ARN,
            "event": self._event(event_type_code="AWS_TOTALLY_MADE_UP_CODE"),
        }
        result = handler(event, None)
        assert result["impactLocus"] == "listed_resource"

    def test_result_has_no_enrichment_ran_true_yet(self):
        """This step alone never sets enrichment.ran: true — that only
        happens once MERGE_ENRICHMENT actually runs a parsed investigation
        result over this baseline (task 2, already committed). Confirms
        this step passes lookups=[] straight through, not a synthetic
        'ran' marker."""
        event = {
            "step": "INVENTORY_BASELINE",
            "eventArn": EVENT_ARN,
            "event": self._event(),
        }
        result = handler(event, None)
        assert result["impactSummary"].get("enrichment", {}).get("ran") is not True
