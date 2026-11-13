# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT License
# See LICENSE file in the project root for full license information.
from tools.compute_deployability import (
    VERDICT_BLOCKED,
    VERDICT_DEGRADED,
    VERDICT_READY,
    compute_deployability_impl,
)

READY_FACTS = {
    "region_exists": True,
    "ec2_available": True,
    "eks_required": True,
    "eks_available": True,
    "ami_available": True,
    "eks_ecr_registry_present": True,
    "az_count": 3,
    "instance_type_required": True,
    "instance_type_offered": True,
    "source_confidences": ["high", "high"],
}


def _codes(result):
    return {b["code"] for b in result["blockers"]}


def test_ready():
    r = compute_deployability_impl(READY_FACTS)
    assert r["verdict"] == VERDICT_READY
    assert r["blockers"] == []
    assert r["confidence"] == "high"


def test_blocked_region_missing():
    r = compute_deployability_impl({"region_exists": False})
    assert r["verdict"] == VERDICT_BLOCKED
    assert "region-does-not-exist" in _codes(r)


def test_blocked_ec2_unavailable():
    r = compute_deployability_impl({**READY_FACTS, "ec2_available": False})
    assert r["verdict"] == VERDICT_BLOCKED
    assert "ec2-not-available-in-region" in _codes(r)


def test_blocked_eks_unavailable_when_required():
    r = compute_deployability_impl({**READY_FACTS, "eks_available": False})
    assert r["verdict"] == VERDICT_BLOCKED
    assert "eks-not-available-in-region" in _codes(r)


def test_eks_unavailable_ignored_when_not_required():
    r = compute_deployability_impl(
        {**READY_FACTS, "eks_required": False, "eks_available": False}
    )
    assert r["verdict"] == VERDICT_READY


def test_blocked_no_ami():
    r = compute_deployability_impl({**READY_FACTS, "ami_available": False})
    assert r["verdict"] == VERDICT_BLOCKED
    assert "no-ami-published" in _codes(r)


def test_blocked_instance_type_not_offered():
    r = compute_deployability_impl({**READY_FACTS, "instance_type_offered": False})
    assert r["verdict"] == VERDICT_BLOCKED
    assert "instance-type-not-offered" in _codes(r)


def test_pricing_only_not_offered_caps_confidence_and_adds_caveat():
    r = compute_deployability_impl(
        {
            **READY_FACTS,
            "instance_type_offered": False,
            "instance_type_offered_source": "pricing-api",
            "source_confidences": ["high", "high"],
        }
    )
    assert r["verdict"] == VERDICT_BLOCKED
    # Overall confidence capped at medium despite all-high source confidences.
    assert r["confidence"] == "medium"
    blocker = next(b for b in r["blockers"] if b["code"] == "instance-type-not-offered")
    assert "Price List API only" in blocker["reason"]
    assert "could not be confirmed" in blocker["reason"]


def test_live_not_offered_stays_high_confidence_no_caveat():
    r = compute_deployability_impl(
        {
            **READY_FACTS,
            "instance_type_offered": False,
            "instance_type_offered_source": "ec2-live",
            "source_confidences": ["high", "high"],
        }
    )
    assert r["verdict"] == VERDICT_BLOCKED
    assert r["confidence"] == "high"
    blocker = next(b for b in r["blockers"] if b["code"] == "instance-type-not-offered")
    assert "Price List API only" not in blocker["reason"]


def test_pricing_cap_does_not_raise_confidence():
    # If source confidences are already low, the medium cap must not raise it.
    r = compute_deployability_impl(
        {
            **READY_FACTS,
            "instance_type_offered": False,
            "instance_type_offered_source": "pricing-api",
            "source_confidences": ["low"],
        }
    )
    assert r["confidence"] == "low"


def test_degraded_no_ecr_registry():
    r = compute_deployability_impl(
        {**READY_FACTS, "eks_ecr_registry_present": False}
    )
    assert r["verdict"] == VERDICT_DEGRADED
    assert _codes(r) == {"no-eks-ecr-registry-mapped"}


def test_degraded_insufficient_azs():
    r = compute_deployability_impl({**READY_FACTS, "az_count": 1})
    assert r["verdict"] == VERDICT_DEGRADED
    assert "insufficient-azs" in _codes(r)


def test_blocking_wins_over_degraded():
    r = compute_deployability_impl(
        {**READY_FACTS, "ami_available": False, "az_count": 1}
    )
    assert r["verdict"] == VERDICT_BLOCKED


def test_confidence_is_lowest():
    r = compute_deployability_impl(
        {**READY_FACTS, "source_confidences": ["high", "low", "medium"]}
    )
    assert r["confidence"] == "low"


def test_confidence_defaults_high_when_none():
    r = compute_deployability_impl({**READY_FACTS, "source_confidences": []})
    assert r["confidence"] == "high"


def test_invalid_input():
    assert compute_deployability_impl("nope")["error_type"] == "invalid_input"
