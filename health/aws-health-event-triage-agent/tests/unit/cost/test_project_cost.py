# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Unit + property tests for src.cost.project_cost.project_cost (Phase 3)."""

from __future__ import annotations

from datetime import date

import pytest
from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

from src.cost.project_cost import project_cost

REF_DATE = date(2026, 1, 1)


def _pricing_lookup_factory(eks_standard=0.10, eks_extended=0.60, rds_year1_2=0.10):
    """Return a pricing_lookup callable with fixed rates for tests."""
    def lookup(service, dimension):
        if service == "AmazonEKS" and dimension == "ClusterUsage":
            return {"unitPrice": eks_standard, "source": "pricelist"}
        if service == "AmazonEKS" and dimension == "ExtendedSupportUsage":
            return {"unitPrice": eks_extended, "source": "pricelist"}
        if service == "AmazonRDS" and dimension == "ExtendedSupportYear1-2":
            return {"unitPrice": rds_year1_2, "source": "pricelist"}
        return {"unitPrice": None, "source": "unavailable"}
    return lookup


class TestNoResources:
    def test_empty_inventory_returns_unknown(self):
        result = project_cost({"resources": []}, pricing_lookup=_pricing_lookup_factory())
        assert result["unknown"] is True
        assert "reason" in result

    def test_missing_resources_key_returns_unknown(self):
        result = project_cost({}, pricing_lookup=_pricing_lookup_factory())
        assert result["unknown"] is True


class TestEksProjection:
    def test_single_cluster_monthly_increment(self):
        inventory = {
            "resources": [
                {"account_id": "123456789012", "cluster_name": "my-cluster", "version": "1.29"}
            ]
        }
        result = project_cost(inventory, pricing_lookup=_pricing_lookup_factory())
        assert result["unknown"] is False
        # increment = 0.60 - 0.10 = 0.50/hr; monthly = 0.50 * 730 = 365.0
        assert result["monthly_increment"] == 365.0

    def test_twelve_month_projection(self):
        inventory = {
            "resources": [{"account_id": "123456789012", "cluster_name": "c1"}]
        }
        result = project_cost(inventory, pricing_lookup=_pricing_lookup_factory())
        assert result["twelve_month"] == 365.0 * 12

    def test_to_deadline_projection(self):
        inventory = {
            "resources": [{"account_id": "123456789012", "cluster_name": "c1"}]
        }
        horizon = {"deadline": "2026-01-31", "now": REF_DATE}  # 30 days = 720 hours
        result = project_cost(inventory, pricing_lookup=_pricing_lookup_factory(), horizon=horizon)
        assert result["to_deadline"] == round(0.50 * 720, 2)

    def test_confidence_list_price_when_all_pricelist(self):
        inventory = {"resources": [{"account_id": "123456789012", "cluster_name": "c1"}]}
        result = project_cost(inventory, pricing_lookup=_pricing_lookup_factory())
        assert result["confidence"] == "list_price"


class TestRdsProjection:
    def test_single_instance_monthly_increment(self):
        inventory = {
            "resources": [{
                "account_id": "123456789012",
                "identifier": "my-db",
                "engine": "mysql",
                "instance_class": "db.r5.large",  # 2 vCPU
                "multi_az": False,
            }]
        }
        result = project_cost(inventory, pricing_lookup=_pricing_lookup_factory())
        # 0.10/vCPU-hr * 2 vCPU * 730 hr = 146.0
        assert result["monthly_increment"] == 146.0

    def test_multi_az_doubles_vcpu(self):
        inventory = {
            "resources": [{
                "account_id": "123456789012",
                "identifier": "my-db",
                "engine": "mysql",
                "instance_class": "db.r5.large",
                "multi_az": True,
            }]
        }
        result = project_cost(inventory, pricing_lookup=_pricing_lookup_factory())
        # 2x vCPU due to standby: 0.10 * 4 * 730 = 292.0
        assert result["monthly_increment"] == 292.0

    def test_unknown_instance_class_excluded(self):
        inventory = {
            "resources": [{
                "account_id": "123456789012",
                "identifier": "my-db",
                "engine": "mysql",
                "instance_class": "db.exotic.99xlarge",
            }]
        }
        result = project_cost(inventory, pricing_lookup=_pricing_lookup_factory())
        assert result["unknown"] is True


class TestMixedResources:
    def test_per_account_aggregation(self):
        inventory = {
            "resources": [
                {"account_id": "111111111111", "cluster_name": "c1"},
                {"account_id": "111111111111", "identifier": "db1", "engine": "mysql", "instance_class": "db.r5.large"},
                {"account_id": "222222222222", "cluster_name": "c2"},
            ]
        }
        result = project_cost(inventory, pricing_lookup=_pricing_lookup_factory())
        assert "111111111111" in result["per_account"]
        assert "222222222222" in result["per_account"]
        # account 1 has both EKS + RDS increments summed
        assert result["per_account"]["111111111111"]["monthly_increment"] == 365.0 + 146.0

    def test_org_total_equals_sum_of_per_account(self):
        inventory = {
            "resources": [
                {"account_id": "111111111111", "cluster_name": "c1"},
                {"account_id": "222222222222", "cluster_name": "c2"},
                {"account_id": "333333333333", "cluster_name": "c3"},
            ]
        }
        result = project_cost(inventory, pricing_lookup=_pricing_lookup_factory())
        expected = round(sum(a["monthly_increment"] for a in result["per_account"].values()), 2)
        assert result["monthly_increment"] == expected

    def test_partial_unprojectable_noted_in_assumptions(self):
        inventory = {
            "resources": [
                {"account_id": "111111111111", "cluster_name": "c1"},
                {"account_id": "222222222222", "identifier": "db1", "engine": "mysql", "instance_class": "db.unknown.xl"},
            ]
        }
        result = project_cost(inventory, pricing_lookup=_pricing_lookup_factory())
        assert result["unknown"] is False  # EKS resource still projectable
        assert any("excluded" in a for a in result["assumptions"])


class TestAssumptionsPresent:
    def test_assumptions_list_non_empty(self):
        inventory = {"resources": [{"account_id": "123456789012", "cluster_name": "c1"}]}
        result = project_cost(inventory, pricing_lookup=_pricing_lookup_factory())
        assert len(result["assumptions"]) > 0
        assert any("730" in a for a in result["assumptions"])


class TestPricingUnavailable:
    def test_no_pricing_data_returns_unknown(self):
        def no_pricing(service, dimension):
            return {"unitPrice": None, "source": "unavailable"}
        inventory = {"resources": [{"account_id": "123456789012", "cluster_name": "c1"}]}
        result = project_cost(inventory, pricing_lookup=no_pricing)
        assert result["unknown"] is True


# ---------------------------------------------------------------------------
# Property test: org total always equals the sum of per-account totals
# ---------------------------------------------------------------------------

account_id_strategy = st.from_regex(r"[0-9]{12}", fullmatch=True)

eks_resource_strategy = st.fixed_dictionaries({
    "account_id": account_id_strategy,
    "cluster_name": st.text(min_size=1, max_size=10, alphabet="abcdefg"),
})


@given(resources=st.lists(eks_resource_strategy, min_size=1, max_size=10))
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_org_total_always_equals_sum_of_accounts(resources):
    """Property: monthly_increment (org) == sum of per_account monthly_increment."""
    inventory = {"resources": resources}
    result = project_cost(inventory, pricing_lookup=_pricing_lookup_factory())
    if result.get("unknown"):
        return  # nothing to check
    expected = round(sum(a["monthly_increment"] for a in result["per_account"].values()), 2)
    assert result["monthly_increment"] == expected
