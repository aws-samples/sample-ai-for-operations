# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Unit tests for src.inventory.build_impact_inventory."""

from __future__ import annotations

import pytest

from src.inventory.build_impact_inventory import (
    CONFIRMED,
    IN_SCOPE_UNVERIFIED,
    NOT_DETECTED,
    UNVERIFIABLE,
    build_impact_inventory,
)


class TestConfirmed:
    def test_single_resource_confirmed(self):
        lookups = [
            {"accountId": "123456789012", "cluster_name": "my-cluster", "version": "1.29", "region": "us-east-1"}
        ]
        result = build_impact_inventory(entities=[], lookups=lookups)
        assert result["impact_status"] == CONFIRMED
        assert len(result["resources"]) == 1

    def test_by_account_grouping(self):
        lookups = [
            {"accountId": "111111111111", "cluster_name": "c1", "region": "us-east-1"},
            {"accountId": "222222222222", "cluster_name": "c2", "region": "us-east-1"},
        ]
        result = build_impact_inventory(entities=[], lookups=lookups)
        assert "111111111111" in result["by_account"]
        assert "222222222222" in result["by_account"]
        assert len(result["by_account"]["111111111111"]["resources"]) == 1

    def test_environment_breakdown(self):
        contexts = [
            {"account_id": "111111111111", "environment_type": "production"},
            {"account_id": "222222222222", "environment_type": "non-production"},
        ]
        lookups = [
            {"accountId": "111111111111", "cluster_name": "c1", "region": "us-east-1"},
            {"accountId": "222222222222", "cluster_name": "c2", "region": "us-east-1"},
        ]
        result = build_impact_inventory(entities=[], lookups=lookups, account_contexts=contexts)
        assert len(result["by_environment"]["production"]) == 1
        assert len(result["by_environment"]["non-production"]) == 1

    def test_multiple_confirmed_resources_same_account(self):
        lookups = [
            {"accountId": "123456789012", "cluster_name": "c1", "region": "us-east-1"},
            {"accountId": "123456789012", "identifier": "db-1", "region": "us-east-1"},
        ]
        result = build_impact_inventory(entities=[], lookups=lookups)
        assert result["impact_status"] == CONFIRMED
        assert len(result["by_account"]["123456789012"]["resources"]) == 2


class TestNotDetected:
    def test_no_entities_and_no_lookup_attempt_is_unverifiable(self):
        """Was asserted as not_detected before the req §1a / task 0b fix.
        entities=[], lookups=[] means NO evidence of any kind was gathered
        (no entities to report, no enrichment attempt at all) — labelling
        that not_detected overstates confidence ("we looked and found
        nothing") when nothing was ever looked at. unverifiable is the
        honest label (design §3.1's decision table, eval case E-0)."""
        result = build_impact_inventory(entities=[], lookups=[])
        assert result["impact_status"] == UNVERIFIABLE
        assert result["resources"] == []
        assert result["enrichment"] == {"ran": False, "reason": "no entities and no enrichment lookup ran"}

    def test_lookups_with_only_bookkeeping_fields_not_detected(self):
        """A lookup with only region/accountId (no actual resource data) doesn't count."""
        lookups = [{"accountId": "123456789012", "region": "us-east-1"}]
        result = build_impact_inventory(entities=[], lookups=lookups)
        assert result["impact_status"] == NOT_DETECTED


class TestUnverifiable:
    def test_single_error_lookup_is_unverifiable(self):
        lookups = [{"accountId": "123456789012", "error": "AssumeRole denied", "region": "us-east-1"}]
        result = build_impact_inventory(entities=[], lookups=lookups)
        assert result["impact_status"] == UNVERIFIABLE

    def test_unverifiable_includes_verification_steps(self):
        lookups = [{"accountId": "123456789012", "error": "throttled"}]
        result = build_impact_inventory(entities=[], lookups=lookups)
        assert "verification_steps" in result
        assert len(result["verification_steps"]) > 0

    def test_confirmed_takes_precedence_over_error(self):
        """If at least one lookup confirms a resource, status is confirmed even if
        another lookup for a different account failed."""
        lookups = [
            {"accountId": "111111111111", "cluster_name": "c1", "region": "us-east-1"},
            {"accountId": "222222222222", "error": "denied", "region": "us-east-1"},
        ]
        result = build_impact_inventory(entities=[], lookups=lookups)
        assert result["impact_status"] == CONFIRMED

    def test_no_verification_steps_when_confirmed(self):
        lookups = [{"accountId": "111111111111", "cluster_name": "c1"}]
        result = build_impact_inventory(entities=[], lookups=lookups)
        assert "verification_steps" not in result

    def test_no_verification_steps_when_not_detected(self):
        """entities=[], lookups=[{...}] (a real attempt that found nothing,
        no error) is the genuine not_detected case, distinct from
        entities=[], lookups=[] (no attempt at all -> unverifiable, see
        TestNoEvidence below, req §1a / task 0b)."""
        lookups = [{"accountId": "123456789012", "region": "us-east-1"}]
        result = build_impact_inventory(entities=[], lookups=lookups)
        assert result["impact_status"] == NOT_DETECTED
        assert "verification_steps" not in result


class TestEnvironmentUnknownFallback:
    def test_missing_account_context_defaults_unknown(self):
        lookups = [{"accountId": "999999999999", "cluster_name": "c1"}]
        result = build_impact_inventory(entities=[], lookups=lookups, account_contexts=[])
        assert len(result["by_environment"]["unknown"]) == 1

    def test_no_account_id_in_lookup_uses_unknown_env(self):
        lookups = [{"cluster_name": "c1"}]
        result = build_impact_inventory(entities=[], lookups=lookups)
        assert len(result["by_environment"]["unknown"]) == 1


class TestImpactLocusDecisionTable:
    """Full branch coverage of the corrected status derivation (req §1a,
    design §3.1, task 0b). Uses real config/event-type-guidance.json codes
    so this also exercises the real get_impact_locus() wiring, not just a
    mocked locus."""

    LISTED_RESOURCE_CODE = "AWS_LAMBDA_RUNTIME_DEPRECATION"  # real config: listed_resource
    DEPENDENT_CODE = "AWS_KEYSPACES_TLS_CERTIFICATE_ROTATION"  # real config: dependent
    UNKNOWN_CODE = "AWS_TOTALLY_UNKNOWN_CODE_NOT_IN_CONFIG"  # defaults to listed_resource

    def test_listed_resource_with_entities_no_enrichment_is_confirmed(self):
        """listed_resource + entities present + no lookups -> confirmed.
        This is the R8.3 correction in its simplest form: AWS's own entity
        list is primary evidence for a listed_resource event."""
        entities = [{"entityValue": "arn:aws:lambda:us-east-1:123456789012:function:f1"}]
        result = build_impact_inventory(
            entities=entities, lookups=[], event_type_code=self.LISTED_RESOURCE_CODE
        )
        assert result["impact_status"] == CONFIRMED
        assert result["enrichment"] == {"ran": False, "reason": "resource state not enriched"}

    def test_dependent_with_entities_no_enrichment_is_in_scope_unverified_never_confirmed(self):
        """dependent + entities present + no lookups -> in_scope_unverified,
        NEVER confirmed. This is the core new behaviour: the entity list
        alone is not evidence of impact for a dependent-locus event."""
        entities = [
            {"entityValue": "arn:aws:cassandra:us-east-1:123456789012:/keyspace/ks/table/t1"},
            {"entityValue": "arn:aws:cassandra:us-east-1:123456789012:/keyspace/ks/table/t2"},
            {"entityValue": "arn:aws:cassandra:us-east-1:123456789012:/keyspace/ks/table/t3"},
        ]
        result = build_impact_inventory(
            entities=entities, lookups=[], event_type_code=self.DEPENDENT_CODE
        )
        assert result["impact_status"] == IN_SCOPE_UNVERIFIED
        assert result["impact_status"] != CONFIRMED
        assert "verification_steps" in result
        # Verification steps must name CLIENT-side checks, not the resource.
        joined = " ".join(result["verification_steps"]).lower()
        assert "trust store" in joined or "client" in joined

    def test_dependent_with_enrichment_that_merely_relists_entities_stays_unverified(self):
        """dependent + lookups that ran but never set dependents_verified
        (the agent merely re-listed the same tables AWS listed, without
        checking callers) -> STILL in_scope_unverified, never confirmed.
        This is the exact LLM failure mode the design calls out — the
        parser/aggregator must not mistake re-listing for verification."""
        entities = [{"entityValue": "arn:aws:cassandra:us-east-1:123456789012:/keyspace/ks/table/t1"}]
        lookups = [
            {"accountId": "123456789012", "resource_arn": "arn:...table/t1", "status": "affected"},
        ]
        result = build_impact_inventory(
            entities=entities, lookups=lookups, event_type_code=self.DEPENDENT_CODE
        )
        assert result["impact_status"] == IN_SCOPE_UNVERIFIED
        assert result["enrichment"]["ran"] is True
        assert "did not verify" in result["enrichment"]["reason"]

    def test_dependent_with_dependents_verified_true_and_confirmed_lookup_becomes_confirmed(self):
        """dependent + lookups with dependents_verified=True and real
        resource data -> confirmed, ON THE AGENT'S EVIDENCE. This is the
        one path that can MOVE a dependent event off in_scope_unverified."""
        entities = [{"entityValue": "arn:aws:cassandra:us-east-1:123456789012:/keyspace/ks/table/t1"}]
        lookups = [
            {
                "accountId": "123456789012",
                "resource_arn": "arn:aws:lambda:us-east-1:123456789012:function:consumer",
                "status": "affected",
                "dependents_verified": True,
            },
        ]
        result = build_impact_inventory(
            entities=entities, lookups=lookups, event_type_code=self.DEPENDENT_CODE
        )
        assert result["impact_status"] == CONFIRMED

    def test_dependent_with_dependents_verified_true_but_no_resource_data_becomes_not_detected(self):
        """dependent + dependents_verified=True but the lookups found no
        actual affected callers -> not_detected (the agent verified and
        found nothing), not in_scope_unverified and not confirmed."""
        entities = [{"entityValue": "arn:aws:cassandra:us-east-1:123456789012:/keyspace/ks/table/t1"}]
        lookups = [
            {"accountId": "123456789012", "dependents_verified": True},
        ]
        result = build_impact_inventory(
            entities=entities, lookups=lookups, event_type_code=self.DEPENDENT_CODE
        )
        assert result["impact_status"] == NOT_DETECTED

    def test_unknown_event_type_code_defaults_to_listed_resource(self):
        """Unknown eventTypeCode (no guidance entry) -> defaults to
        listed_resource -> entities present -> confirmed."""
        entities = [{"entityValue": "arn:aws:ec2:us-east-1:123456789012:instance/i-1"}]
        result = build_impact_inventory(
            entities=entities, lookups=[], event_type_code=self.UNKNOWN_CODE
        )
        assert result["impact_status"] == CONFIRMED

    def test_no_entities_no_enrichment_is_unverifiable_regardless_of_locus(self):
        """No entities and no lookups -> unverifiable, for BOTH loci — the
        locus only matters when there are entities to qualify."""
        for code in (self.LISTED_RESOURCE_CODE, self.DEPENDENT_CODE):
            result = build_impact_inventory(entities=[], lookups=[], event_type_code=code)
            assert result["impact_status"] == UNVERIFIABLE

    def test_default_event_type_code_behaves_as_listed_resource(self):
        """Callers that don't pass event_type_code at all (backward
        compatibility with pre-task-0b call sites) get listed_resource's
        behaviour, matching get_impact_locus's own default."""
        entities = [{"entityValue": "arn:aws:ec2:us-east-1:123456789012:instance/i-1"}]
        result = build_impact_inventory(entities=entities, lookups=[])
        assert result["impact_status"] == CONFIRMED
